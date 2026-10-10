--[[ [OFFLINE-SERVER] 内置离线服务端（阶段 1：TCP + 传输帧 + CRC32 校验）

协议规格全部来自 rrcp_server.py 的 docstring（由真实抓包反汇编得出），不是猜的：

transport 帧  MessageProtocol::packupMessage @0x827e78
    [0]=(len>>8)&0xff  [1]=len&0xff  [2]=(len>>16)&0xff  [3]=type  [4:]=payload
    即 len = (b0<<8) | b1 | (b2<<16)   —— 注意 b1 是低位、b0 是 8..15 位、b2 是 16..23 位

握手
    C->S type 1 : payload = [u16 BE spki_len][SPKI DER][2B]
    S->C type 3 : RSA-PKCS1v15(client_pub, [u16 keylen][key][u8 algo])
                  algo=0 -> 会话走明文，state=4

数据帧 type 0
    payload = [u32 BE crc32][u32 BE plainlen][data]
    crc32 为标准 zlib crc32，作用在 data 上，且 plainlen == len(data)

RPC 请求 (data)
    [0] kind=1  [1] comp  [2:6] req_id  [6:10] opcode  [10:14] body_len  [14:18] ?  [18:] body

RPC 响应  RPCTransport::writeResponse @0x8205d8
    kind=2 | comp | i32 req_id | i64 timestamp | i32 b | i16 c | u32 len | body

RPC 负载  Service:newRequest
    [u8 ver][u8 ridlen][rid][cjson(params)]

本阶段目标：验证 socket / 非阻塞 select / 帧解析 / CRC32 四件事在设备上真的可用。
RSA 与业务响应留到后续阶段。 ]]

local OS = {}
OfflineServer = OfflineServer or {}
OfflineServer.__index = OfflineServer

local SVR_PORT = 8888
local T_DATA = 0
local T_HS_OUT = 1        -- C->S 客户端公钥
local T_HS_IN = 3         -- S->C 给客户端会话密钥
local T_TICK = 0xBB
local T_ERR = 0xFF

local R_KIND_REQUEST = 1
local R_KIND_RESPONSE = 2

local SESSION_KEY_LEN = 16   -- 与 Python mock --keylen 默认值一致
local SESSION_ALGO = 0      -- 0 = 明文会话，客户端跳过 newCrypto
-- 前置声明：应答层的函数定义在 on_frame 之后，
-- 但 on_frame 要调它必须先声明，否则在模块加载时拿到 nil。
local build_response, send_data_frame

local SOCK = nil          -- socket 模块缓存；全局 socket 是 nil
-- interval 不能用 0：重排后会被同一 scheduler pass 里反复触发，实测 ~78k 次/秒
local TICK_INTERVAL = 0.05
local _state = {
    listen = nil,
    client = nil,
    buf = '',
    phase = 'new',        -- new -> hs -> data
    log = {},
    spki = nil,
    nframe = 0,
    -- 主屏助理（opcode 10038 changeHero）。离线侧和 Python 侧共用同一个
    -- main_screen_state.json，这样两种服务端之间切换不会丢选择。
    main_hero = nil,
    main_type = nil,
    main_hero_ph = nil,
    main_type_ph = nil,
    main_default = nil,
    debug_toggles = nil,
    -- 关卡进度。离线端本来是纯回放器（campaignProgress 是构建期穷举的静态
    -- 快照），进度只活在这几个变量里，冷启动就回到构建时的初值。
    --
    -- last_stage 和 saved_stage **必须分开**，早先合并成一个导致两个 bug：
    --   1) 14002 先把 last_stage 设成本次打的关，14003 再比
    --      campaign_farther(cid, last_stage) 就成了自己跟自己比 -> 永远不落盘；
    --   2) 冷启动还没打过任何关时 last_stage 是 nil，10001 会把构建期的
    --      哨兵 "__YQLR_CD__" 原样发给客户端 —— 那是个**字符串**，
    --      而 CampaignData 必须是对象，客户端拿到就炸。
    -- last_stage = 本次 14002 打的关（内存态，14003 兜底要用）
    -- saved_stage = 已通关的最远那关（落盘态，10001 要用）
    -- campaign_cd = 每关的 CampaignData 片段，供 10001 替换哨兵
    last_stage = nil,
    saved_stage = nil,
    campaign_cd = nil,
    campaign_cd_ph = nil,
    campaign_cd_default = nil,
    campaign_order = nil,
}

local function slog(fmt, ...)
    local ok, msg = pcall(string.format, fmt, ...)
    if not ok then
        msg = tostring(fmt)
    end
    local line = '[osrv] ' .. msg
    _state.log[#_state.log + 1] = line
    -- 顺手沿用工程既有的文件探针通道，方便在 logcat 失效时观察
    local wrote = pcall(function ()
        local fh = io.open('/sdcard/osrv.txt', 'a')
        if not fh then
            error('no file')
        end
        fh:write(os.date('%H:%M:%S') .. ' ' .. line .. '\n')
        fh:close()
    end)
    -- 落盘失败（本机 luajit 调试、/sdcard 不可写时）退回 stdout，
    -- 否则 load_opcode_table 之类的失败原因会被 pcall 静默吞掉。
    if not wrote then
        io.write(os.date('%H:%M:%S') .. ' ' .. line .. '\n')
    end
    return line
end

OfflineServer.log = function (self, fmt, ...)
    return slog(fmt, ...)
end

-- ---------------------------------------------------------------- 二进制工具
-- LuaJIT 无 string.pack，用 string.byte/char 手工取整数。
local function u8(s, i)
    return string.byte(s, i)
end

local function u16be(s, i)
    return u8(s, i) * 256 + u8(s, i + 1)
end

local function u32be(s, i)
    return u8(s, i) * 16777216 + u8(s, i + 1) * 65536 + u8(s, i + 2) * 256 + u8(s, i + 3)
end

-- transport 的 3 字节长度：b0 是 8..15 位、b1 是 0..7 位、b2 是 16..23 位
local function transport_len(b0, b1, b2)
    return (b0 * 256) + b1 + (b2 * 65536)
end

OfflineServer.u32be = u32be
OfflineServer.u16be = u16be
OfflineServer.u8 = u8

-- ---------------------------------------------------------------- CRC32
-- 优先用游戏自带的纯 Lua 实现。它在 foundation/crypto/init.lua:10-14 被挂成
-- **全局 _G.crypto.crc32**（不是模块导出），算法与 zlib crc32 一致。
-- 取不到再退回内置表驱动实现。
local _crc32
local function load_crc32()
    local g = rawget(_G, 'crypto')
    if type(g) == 'table' and type(g.crc32) == 'function' then
        return g.crc32
    end
    local ok, mod = pcall(require, 'foundation.crypto.crc32')
    if ok and type(mod) == 'table' and type(mod.crc32) == 'function' then
        return mod.crc32
    end
    if ok and type(mod) == 'function' then
        return mod
    end
    -- 兜底：表驱动
    local tbl = {}
    for i = 0, 255 do
        local c = i
        for _ = 1, 8 do
            c = bit.band(bit.bxor(c, 1), 0xFFFFFFFF)
            c = bit.bor(bit.lshift(c, 1), bit.rshift(c, 31))
        end
        tbl[i] = c
    end
    return function (s, crc)
        crc = bit.bxor(crc or 0, 0xFFFFFFFF)
        for i = 1, #s do
            crc = bit.bxor(tbl[bit.band(bit.bxor(crc, u8(s, i)), 0xFF)], bit.rshift(crc, 8))
        end
        return bit.bxor(crc, 0xFFFFFFFF)
    end
end

_crc32 = load_crc32()

-- 只为自检用：对已知串算出 crc32，与 zlib 对齐
-- "123456789" 的 zlib crc32 = 0xCBF43926
function OfflineServer.selfTestCrc32()
    local v = _crc32('123456789', 0)
    slog('crc32("123456789") = 0x%08X  期望 0xCBF43926  %s',
         v, bit.band(v, 0xFFFFFFFF) == 0xCBF43926 and 'OK' or 'FAIL')
    return v
end

local function hexdump(b, n)
    n = n or 64
    local out = {}
    for i = 1, math.min(n, #b) do
        out[#out + 1] = string.format('%02X', u8(b, i))
        if i % 16 == 0 then
            out[#out + 1] = '  '
        end
    end
    return table.concat(out, ' ')
end

-- ---------------------------------------------------------------- DER / RSA
-- 纯 Lua 的最小 DER 解析：只需要走往往就能从 SPKI 里取出 n 和 e。
-- SPKI 结构（已从实际抓包确认）：
--   SEQUENCE {
--     SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }      -- rsaEncryption
--     BIT STRING (0 unused bits) {
--       SEQUENCE {
--         INTEGER  modulus   (129 B, 前导 00)
--         INTEGER  exponent (3  B,  01 00 01 = 65537)
--       }
--     }
--   }
local function der_tlv(b, p)
    if p + 1 > #b then
        return nil
    end
    local tag = u8(b, p)
    local len = u8(b, p + 1)
    local hdr = 2
    if len > 0x80 then
        local nb = len - 0x80
        len = 0
        for i = 1, nb do
            len = len * 256 + u8(b, p + 1 + i)
        end
        hdr = 2 + nb
    end
    local content = string.sub(b, p + hdr, p + hdr + len - 1)
    return {
        tag = tag,
        len = len,
        content = content,
        next = p + hdr + len,
    }
end

local function der_find_seq(b, p, depth, want_tag)
    -- 在 b 里纵细找第 depth 层的 want_tag
    local cur = p
    local idx = 0
    while cur and cur <= #b do
        local t = der_tlv(b, cur)
        if not t then
            return nil
        end
        idx = idx + 1
        if t.tag == want_tag then
            return t, idx
        end
        cur = t.next
    end
    return nil
end

local function der_parse_spki(spki)
    local out = { ok = false }
    local outer = der_tlv(spki, 1)
    if not outer or outer.tag ~= 0x30 then
        out.err = 'outer is not SEQUENCE'
        return out
    end

    -- outer: SEQ { SEQ alg, BITSTRING key }
    local alg = der_tlv(outer.content, 1)
    local bits = der_tlv(outer.content, alg.next)
    if not alg or not bits then
        out.err = 'cannot split algId / BIT STRING'
        return out
    end
    if alg.tag ~= 0x30 then
        out.err = 'algId tag = 0x%02X' % alg.tag
        return out
    end
    if bits.tag ~= 0x03 then
        out.err = 'keyBits tag = 0x%02X' % bits.tag
        return out
    end

    -- BIT STRING 的第一个字节是 unused-bits
    local inner = der_tlv(string.sub(bits.content, 2), 1)
    if not inner or inner.tag ~= 0x30 then
        out.err = 'inner is not SEQUENCE'
        return out
    end

    local nIv = der_tlv(inner.content, 1)
    local eIv = der_tlv(inner.content, nIv and nIv.next or 2)
    if not nIv or nIv.tag ~= 0x02 or not eIv or eIv.tag ~= 0x02 then
        out.err = 'modulus/exponent not INTEGER'
        return out
    end

    -- INTEGER 可能带前导 00（保持正数）
    local function strip_leading_zero(x)
        if #x > 1 and string.byte(x, 1) == 0 then
            return string.sub(x, 2)
        end
        return x
    end

    out.modulus = strip_leading_zero(nIv.content)
    out.exponent = strip_leading_zero(eIv.content)
    out.modulus_len = #out.modulus
    out.exponent_len = #out.exponent
    out.bits = #out.modulus * 8
    out.ok = true
    return out
end

OfflineServer.der_parse_spki = der_parse_spki

-- ---------------------------------------------------------------- RSA（纯 Lua）
-- 用 16-bit limb（小端）表示大整数，R = 2^(16*nlimbs)，模乘用 Montgomery CIOS。
-- 为什么不用 32-bit limb：乘法的中间值会超过 2^53，LuaJIT 的 double 会丢精度。
-- 16-bit limb 下中间值 <= 65535*65535 + 2^17 < 2^33，完全安全。

local function bytes_to_limbs(b)
    local l = {}
    local n = math.floor(#b / 2)
    -- 必须小端存放：limb[1] = 最低 16 位。
    -- （先前写成从 bytes[1] 开始取，等于大端，而 mont_mul/ge/sub 都按
    --   "索引 1 = 最低位" 处理，两边不一致，算出来全错。）
    for k = 1, n do
        local lo = string.byte(b, #b - 2 * k + 2) or 0
        local hi = string.byte(b, #b - 2 * k + 1) or 0
        l[k] = lo + hi * 256
    end
    return l
end

local function limbs_to_bytes(l, nlimbs)
    local n = nlimbs * 2
    local out = {}
    for k = 1, nlimbs do
        local v = l[k] or 0
        -- limb[k] 是第 k 低的 16 位：它的低字节要落在字符串更靠后的位置
        out[n - 2 * k + 2] = string.char(v % 256)
        out[n - 2 * k + 1] = string.char((v - (v % 256)) / 256)
    end
    return table.concat(out)
end

-- a >= b ?
local function ge(a, b, nlen)
    for i = nlen, 1, -1 do
        local x = a[i] or 0
        local y = b[i] or 0
        if x ~= y then
            return x > y
        end
    end
    return true
end

-- a -= b（要求 a >= b）
local function sub(a, b, nlen)
    local borrow = 0
    for i = 1, nlen do
        local d = (a[i] or 0) - (b[i] or 0) - borrow
        if d < 0 then
            d = d + 65536
            borrow = 1
        else
            borrow = 0
        end
        a[i] = d
    end
end

-- 求 -x^-1 mod 2^16（x 必须为奇数）
local function n0inv_of(x)
    local a, b = x % 65536, 65536
    local x0, x1 = 1, 0
    while b ~= 0 do
        local q = math.floor(a / b)
        a, b = b, a - q * b
        x0, x1 = x1, x0 - q * x1
    end
    return (65536 - (x0 % 65536)) % 65536
end

-- Montgomery 乘法：返回 a*b*R^-1 mod n
-- a / b 都是 1-based 且"索引 1 = 最低位"；t 是 0-based（t[0] 最低）。
local function mont_mul(a, b, n, nlen, n0inv)
    local t = {}
    for i = 0, nlen + 1 do
        t[i] = 0
    end
    for i = 0, nlen - 1 do
        local bi = b[i + 1] or 0
        local carry = 0
        for j = 0, nlen - 1 do
            local s = t[j] + (a[j + 1] or 0) * bi + carry
            t[j] = s % 65536
            carry = math.floor((s - t[j]) / 65536)
        end
        local s = t[nlen] + carry
        t[nlen] = s % 65536
        t[nlen + 1] = (t[nlen + 1] or 0) + math.floor((s - t[nlen]) / 65536)

        local m = (t[0] * n0inv) % 65536
        local carry2 = 0
        for j = 0, nlen - 1 do
            local s2 = t[j] + m * (n[j + 1] or 0) + carry2
            t[j] = s2 % 65536
            carry2 = math.floor((s2 - t[j]) / 65536)
        end
        local s3 = t[nlen] + carry2
        t[nlen] = s3 % 65536
        t[nlen + 1] = (t[nlen + 1] or 0) + math.floor((s3 - t[nlen]) / 65536)

        for j = 0, nlen do
            t[j] = t[j + 1]
        end
        t[nlen + 1] = 0
    end

    -- 注意：t 是 0-based（t[0] 是最低 limb），n 是 1-based，
    -- 必须先转成 1-based 再做比较，否则 ge() 读到的位全错位。
    local out = {}
    for i = 1, nlen do
        out[i] = t[i - 1]
    end
    if t[nlen] > 0 or ge(out, n, nlen) then
        sub(out, n, nlen)
    end
    return out
end

-- (x*2) mod n，要求 x < n
-- 先算 t = 2x（nlen+1 个 limb），再试减 n：
--   减完没有借位 -> t >= n，结果就是 t-n（必然 < n）
--   减完有借位   -> t <  n，把 n 加回去
-- 不要像先前那样"若 carry>0 或 y>=n 就减"：x 很小时 2x<n，无条件减会算出垃圾。
local function dbl_mod(x, n, nlen)
    local y = {}
    for i = 1, nlen + 1 do
        y[i] = 0
    end

    local carry = 0
    for i = 1, nlen do
        local v = (x[i] or 0) * 2 + carry
        y[i] = v % 65536
        carry = math.floor((v - y[i]) / 65536)
    end
    y[nlen + 1] = carry

    local borrow = 0
    for i = 1, nlen + 1 do
        local d = y[i] - (n[i] or 0) - borrow
        if d < 0 then
            d = d + 65536
            borrow = 1
        else
            borrow = 0
        end
        y[i] = d
    end

    if borrow == 1 then
        local c = 0
        for i = 1, nlen + 1 do
            local v = y[i] + (n[i] or 0) + c
            y[i] = v % 65536
            c = math.floor((v - y[i]) / 65536)
        end
    end

    y[nlen + 1] = 0
    return y
end

-- R mod n（从 1 开始倍增 16*nlen 次）
local function r_mod_n(n, nlen)
    local x = {}
    for i = 1, nlen do
        x[i] = 0
    end
    x[1] = 1
    for _ = 1, 16 * nlen do
        x = dbl_mod(x, n, nlen)
    end
    return x
end

-- R^2 mod n
local function r2_mod_n(n, nlen)
    local x = r_mod_n(n, nlen)
    for _ = 1, 16 * nlen do
        x = dbl_mod(x, n, nlen)
    end
    return x
end

-- a^e mod n（e 为字节序列，按大端逐位做平方-乘）
local function modexp(a, e, n, nlen, n0inv, r2)
    local base = mont_mul(a, r2, n, nlen, n0inv)

    local one = {}
    for i = 1, nlen do
        one[i] = 0
    end
    one[1] = 1

    local acc = r_mod_n(n, nlen)

    -- 注意 1：Lua 里的 ^ 是**按位异或**，不是乘方。
    --   曾经写成 math.floor(byte / (2 ^ k)) % 2，取的位完全是错的。
    -- 注意 2：Lua 5.1 的数值 for **只向上计数**，不会自动反向。
    --   写成 for k = 7, 0 do 会一次都不执行（7 永远到不了 0），
    --   结果 modexp 无论 e 是多少都返回 1。必须用倒序索引。
    local POW2 = { 1, 2, 4, 8, 16, 32, 64, 128 }

    for i = 1, #e do
        local byte = string.byte(e, i)
        for idx = 0, 7 do
            local k = 7 - idx
            acc = mont_mul(acc, acc, n, nlen, n0inv)
            local bit = math.floor(byte / POW2[k + 1]) % 2
            if bit == 1 then
                acc = mont_mul(acc, base, n, nlen, n0inv)
            end
        end
    end

    return mont_mul(acc, one, n, nlen, n0inv)
end

OfflineServer.bytes_to_limbs = bytes_to_limbs
OfflineServer.limbs_to_bytes = limbs_to_bytes
OfflineServer.modexp = modexp

-- 内部函数导出，仅用于和 Python 逐个对拍排查（release 也不会被调用）
OfflineServer._internals = {
    mont_mul = mont_mul,
    dbl_mod = dbl_mod,
    r_mod_n = r_mod_n,
    r2_mod_n = r2_mod_n,
    ge = ge,
    sub = sub,
    n0inv_of = n0inv_of,
}

local function hex2bin(h)
    return (h:gsub('%x%x', function (x)
        return string.char(tonumber(x, 16))
    end))
end

-- 自检：固定测试向量验证 bignum / Montgomery / modexp 三者是否正确。
-- 向量由 Python cryptography 生成，并把 PS 填充定死，因此可永久重现。
local SELFTEST_NHEX = 'dc2117e166c1cdcc80be0c4de2dbe097bc54aedef787b2ebc496bde68121d120e9c65' ..
                       '197da7c71e842521b7e9250bacf831d2b62ec1ea7cc7910a3ba751a2ea5dae7ae' ..
                       '02932212b728d2fa7058bedd41f6300313f8fea40ef80e8a3da680e3d8c11b1c' ..
                       '06bc87438f2b0ef224e5d9849b4768f2c31294745ed017a3d953a5cde5'
local SELFTEST_EMHEX = '00020c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d' ..
                       '7dee5ecf3fa020910171e252c333a41484f565d646b727980878e959ca3aab' ..
                       '1b8bfc6cdd4dbe2e9f0f7fe060d141b222930373e454c535a61686f767d84' ..
                       '8b9299a0a7aeb5bcc3cad1d8dfe6edf4fb00000102030405060708090a0b0c' ..
                       '0d0e0f00'
local SELFTEST_CTHEX = 'beca7ed8b18933a077cd2086e3b1282a231a60a86a6172d07fbb2c212f036f' ..
                       '021e524061e020eee6ff59c99b699ff2afff2f8e44bb6e663025fa929191b9f' ..
                       '8ba5b2ac578619ac3cde6ed8601130a8270820ff52d23f80b84a771146d0' ..
                       'af35b8bcc3fce9101b2ed021da83742ba6d609d201edbb45114a058d33eb82' ..
                       'b263cd268'

function OfflineServer.selfTestRsa()
    local nb = hex2bin(SELFTEST_NHEX)
    local em = hex2bin(SELFTEST_EMHEX)
    local want = hex2bin(SELFTEST_CTHEX)

    local n = bytes_to_limbs(nb)
    local nlen = #n
    local n0inv = n0inv_of(n[1])
    local r2 = r2_mod_n(n, nlen)

    local got = limbs_to_bytes(
        modexp(bytes_to_limbs(em), string.char(0x01, 0x00, 0x01), n, nlen, n0inv, r2),
        nlen)
    local ok = (got == want)

    slog('RSA 自检 n=%d B e=65537 实算=%s 期望=%s', #nb,
         hexdump(got, 16), hexdump(want, 16))
    slog('RSA 自检 %s', ok and 'PASS' or 'FAIL')
    return ok, got
end

-- PKCS#1 v1.5 公钥加密
local function rsa_encrypt(rsa, msg)
    local k = #rsa.modulus
    if #msg + 11 > k then
        return nil, 'message too long'
    end

    local ps = {}
    for i = 1, k - #msg - 3 do
        local v
        repeat
            v = math.random(1, 255)
        until v ~= 0
        ps[i] = string.char(v)
    end

    local em = string.char(0x00, 0x02) .. table.concat(ps) .. string.char(0x00) .. msg

    local n = bytes_to_limbs(rsa.modulus)
    local nlen = #n
    local n0inv = n0inv_of(n[1])
    local r2 = r2_mod_n(n, nlen)

    local ct = modexp(bytes_to_limbs(em), rsa.exponent, n, nlen, n0inv, r2)
    return limbs_to_bytes(ct, nlen)
end

OfflineServer.rsa_encrypt = rsa_encrypt

-- 发帧：[len>>8][len&0xFF][len>>16][type][payload]
-- 注意：连接 socket 是 settimeout(0)（非阻塞），LuaSocket 在这种模式下
-- send 常常直接返回 nil,"timeout"（数据其实已经进了内核缓冲）。
-- 发送前临时给一个短超时，几十字字节不可能真的阻塞。
local function send_frame(sock, mtype, payload)
    local len = #payload
    local head = string.char(math.floor(len / 256) % 256, len % 256,
                             math.floor(len / 65536) % 256, mtype)
    local data = head .. payload

    local ok, err = pcall(function ()
        sock:settimeout(2)
    end)

    local sent, e = pcall(function ()
        return sock:send(data)
    end)

    pcall(function ()
        sock:settimeout(0)
    end)

    if not sent then
        slog('send 抛错: %s', tostring(e))
        return false
    end

    if e == nil then
        -- 非阻塞下的 timeout：数据已交给内核，按成功记账但留个记录
        slog('send 返回 nil（socket 为非阻塞），按已发出处理：%d B', #data)
        return true
    end

    if e ~= #data then
        slog('send 不完整: 期望 %d B 实际 %s B', #data, tostring(e))
        return false
    end

    return true
end

OfflineServer.send_frame = send_frame

-- ---------------------------------------------------------------- 帧解析
-- 从累积缓冲里切出完整帧。返回 nil 表示数据还不够。
local function try_parse_frame(buf)
    if #buf < 4 then
        return nil
    end
    local len = transport_len(u8(buf, 1), u8(buf, 2), u8(buf, 3))
    local mtype = u8(buf, 4)
    if #buf < 4 + len then
        return nil
    end
    return {
        mtype = mtype,
        payload = string.sub(buf, 5, 4 + len),
        rest = string.sub(buf, 5 + len),
    }
end

OfflineServer.try_parse_frame = try_parse_frame

-- 数据帧 -> RPC 请求
-- 布局以 Python mock（rrcp_server.py:1259 parse_request，已实测能跑通登录）为准：
--     [0]     kind = 1
--     [1]     compression
--     [2:6]   i32 req_id
--     [6:10]  i32 unknown（实测 0）
--     [10:14] i32 opcode        <-- 不是 [6:10]
--     [14:18] u32 body_len      <-- 错读成 opcode 会让服务端误判 opcode=0
--     [18:]   body
local function parse_rpc_request(data)
    if #data < 18 then
        return nil, 'too short: ' .. #data
    end
    local kind = u8(data, 1)
    if kind ~= R_KIND_REQUEST then
        return nil, 'kind=' .. kind
    end
    local req = {
        kind = kind,
        comp = u8(data, 2),
        req_id = u32be(data, 3),
        unk = u32be(data, 7),
        opcode = u32be(data, 11),
        body_len = u32be(data, 15),
    }
    if #data >= 18 + req.body_len then
        req.body = string.sub(data, 19, 18 + req.body_len)
    end
    req.tail = string.sub(data, 19 + req.body_len)
    return req
end

OfflineServer.parse_rpc_request = parse_rpc_request

-- RPC 负载 -> [i32 native 前缀][u8 ver][u8 ridlen][rid][cjson][TLV...]
-- 那 4 字节前缀来自 native RPC 层；Service:newRequest 只构造
-- string.char(version, #rid) .. rid .. cjson 这一段。
-- （照抄 Python mock rrcp_server.py:89 parse_app_body）
local function parse_rpc_body(body)
    if not body or #body < 6 then
        return nil
    end
    local ver = u8(body, 5)
    local ridlen = u8(body, 6)
    local rid = string.sub(body, 7, 6 + ridlen)
    local js = string.sub(body, 7 + ridlen)
    local ok, cjson = pcall(require, 'cjson.safe')
    local params = nil
    if ok and type(js) == 'string' and #js > 0 then
        local ok2, p = pcall(cjson.decode, js)
        if ok2 then
            params = p
        end
    end
    return { ver = ver, rid = rid, json = js, params = params }
end

OfflineServer.parse_rpc_body = parse_rpc_body

-- ---------------------------------------------------------------- 事件处理
local function on_frame(fr)
    _state.nframe = _state.nframe + 1
    slog('帧#%d type=0x%02X payload=%d B  phase=%s',
         _state.nframe, fr.mtype, #fr.payload, _state.phase)

    if fr.mtype == T_HS_OUT then
        local spki_len = u16be(fr.payload, 1)
        local spki = string.sub(fr.payload, 3, 2 + spki_len)
        local tail = string.sub(fr.payload, 3 + spki_len)
        _state.spki = spki
        _state.phase = 'hs'
        slog('握手 type=1：spki_len=%d 实收=%d 尾部=%d B', spki_len, #spki, #tail)
        slog('尾部 hex = %s', hexdump(tail, 16))

        local rsa = der_parse_spki(spki)
        if rsa.ok then
            slog('SPKI DER 解析成功: 模数 %d B (%d bit)  指数 %d B = %s',
                 rsa.modulus_len, rsa.bits, rsa.exponent_len, hexdump(rsa.exponent, 8))
            slog('模数前 24 B = %s', hexdump(rsa.modulus, 24))
            _state.rsa = rsa
        else
            slog('SPKI DER 解析失败: %s', tostring(rsa.err))
        end
        -- 阶段 2：RSA-PKCS1v15 加密 [u16 keylen][key][u8 algo] 并回 type 3。
        -- 明文长度 = 2 + keylen + 1 = 19 B，远小于 1024-bit 上限 (128-11)。
        -- 注意 u16be(s, i) 是"从字节串 s 的第 i 位读"，不是"把数字编成 u16"。
        local plain = string.char(math.floor(SESSION_KEY_LEN / 256),
                                  SESSION_KEY_LEN % 256)
                       .. _state.session_key .. string.char(SESSION_ALGO)
        slog('应答明文 %d B = u16(%d) + key(%d) + algo(%d)  会话密钥=%s',
             #plain, SESSION_KEY_LEN, SESSION_KEY_LEN, SESSION_ALGO,
             hexdump(_state.session_key, 16))

        local ct, err = rsa_encrypt(rsa, plain)
        if not ct then
            slog('RSA 加密失败: %s', tostring(err))
            return
        end

        if _state.client then
            if send_frame(_state.client, T_HS_IN, ct) then
                slog('已回 type=3，密文 %d B，前 16 B=%s', #ct, hexdump(ct, 16))
                _state.phase = 'encrypted'
            end
        else
            slog('RSA 加密成功但没有客户端连接，无法发送')
        end

    elseif fr.mtype == T_DATA then
        local payload = fr.payload
        if #payload < 8 then
            slog('数据帧过短 %d B', #payload)
            return
        end
        local crc = u32be(payload, 1)
        local plainlen = u32be(payload, 5)
        local data = string.sub(payload, 9)
        local calc = bit.band(_crc32(data, 0), 0xFFFFFFFF)
        slog('数据帧：声明 crc=0x%08X 实算=0x%08X %s | plainlen=%d 实长=%d %s',
             crc, calc, crc == calc and 'MATCH' or 'MISMATCH',
             plainlen, #data, plainlen == #data and 'MATCH' or 'MISMATCH')
        local req, err = parse_rpc_request(data)
        if not req then
            slog('RPC 解析失败: %s', tostring(err))
            return
        end
        local b = parse_rpc_body(req.body)
        slog('RPC kind=%d comp=%d req_id=%d opcode=%d body_len=%d',
             req.kind, req.comp, req.req_id, req.opcode, req.body_len)
        if b then
            slog('  ver=%d rid=%s params=%s', b.ver, b.rid,
                 b.json and string.sub(b.json, 1, 120) or 'nil')
        end
        _state.phase = 'data'

        if _state.client then
            local body = build_response(req)
            if body then
                send_data_frame(_state.client, body)
                _state.nresp = (_state.nresp or 0) + 1
                slog('-> RESP #%d opcode=%d body=%d B', _state.nresp,
                     req.opcode, #body)
            end
        else
            slog('没有客户端连接，丢弃 opcode=%d 的应答', req.opcode)
        end
    end
end

-- ---------------------------------------------------------------- 应答层
-- 响应体在**构建期**就已经由 Python mock 物化并 json.dumps 成字符串
-- （见 build_lua_table.py，产物是 lua/opcode_table.lua）。这里只取字符串，
-- 绝不 decode -> encode 往返：表里有 5 处空数组 `[]`，cjson 会把它们变成 `{}`
-- （reward / clubList 等会踩雷）。
--
-- OPCODE_TABLE 由构建期内联到这里；单元测试时可先 require 进来。
if not OPCODE_TABLE then
    local ok, t = pcall(require, 'opcode_table')
    if ok and type(t) == 'table' then
        OPCODE_TABLE = t
    end
end

-- 主屏助理落盘。与 Python 侧共用同一个 main_screen_state.json。
local MAIN_SCREEN_PATH = '/sdcard/main_screen_state.json'

local function load_main_screen()
    local f = io.open(MAIN_SCREEN_PATH, 'r')

    if not f then
        local d = _state.main_default or {}
        _state.main_hero = d.heroId
        _state.main_type = d.type
        return
    end

    local raw = f:read('*a')
    f:close()

    -- 不引 JSON 库（宿主 luajit 没有，设备上的 cjson 也不能在离线自测里用），
    -- 只按字节抽这两个标量字段，理由和 Python 侧的 change_hero_params 一样。
    --
    -- 必须用 string.match 而不是 string.find：find 返回的是**整个匹配**的
    -- 起止位置，用 string.sub(a+1, b) 会把 `"heroId":` 也截进去
    -- （曾经抽出过 'heroId":"BaiJ' 这种脏值）。match 才返回捕获组本身。
    local function grab(key)
        return string.match(raw, '"' .. key .. '"%s*:%s*"([^"]*)"')
    end

    _state.main_hero = grab('heroId') or (_state.main_default or {}).heroId
    _state.main_type = grab('type') or (_state.main_default or {}).type
    slog('main screen hero loaded: %s / %s', tostring(_state.main_hero),
         tostring(_state.main_type))
end

local function save_main_screen()
    local f = io.open(MAIN_SCREEN_PATH, 'w')

    if not f then
        slog('!! cannot write %s', MAIN_SCREEN_PATH)
        return false
    end

    f:write('{"heroId":"', tostring(_state.main_hero or ''), '","type":"',
            tostring(_state.main_type or ''), '"}')
    f:close()
    return true
end

-- ---------------------------------------------------------------- 编队
-- 与 Python 侧共用 team_state.json，两种服务端之间切换不会丢编队。
-- 格式就是一串 heroId，用逗号分隔 —— 不引 JSON 库，理由同 load_main_screen。
local TEAM_PATH = '/sdcard/team_state.json'

local function load_team()
    local f = io.open(TEAM_PATH, 'r')
    _state.team = nil

    if not f then
        return
    end

    local raw = f:read('*a')
    f:close()
    -- 抠出最后一个 "team": [...] 或顶层 [...] 里的英雄名。
    -- 简单起见按已知英雄 id 逐个匹配出现顺序。
    local ids = {}
    if raw then
        for h in string.gmatch(raw, '[A-Za-z][A-Za-z0-9_]*') do
            ids[#ids + 1] = h
        end
    end
    if #ids > 0 then
        _state.team = ids
        slog('team loaded: %s', table.concat(ids, ','))
    end
end

local function save_team(ids)
    if not ids or #ids == 0 then
        return false
    end
    local f = io.open(TEAM_PATH, 'w')
    if not f then
        slog('!! cannot write %s', TEAM_PATH)
        return false
    end
    f:write('{"team":[')
    for i, h in ipairs(ids) do
        if i > 1 then
            f:write(',')
        end
        f:write('"', h, '"')
    end
    f:write(']}')
    f:close()
    _state.team = ids
    slog('team saved: %s', table.concat(ids, ','))
    return true
end

-- ---------------------------------------------------------------- 关卡进度落盘
--
-- 为什么必须落盘：campaignProgress 是构建期按"一路打上来"穷举的静态快照，
-- 运行时没有任何状态机。不落盘的话，打过的关卡退出重进就回到构建时的初值。
--
-- 为什么只存一个关卡号而不是 Python 侧那样的 campaign_passed 全集：
-- campaignProgress[stage] 本身就是"通关 stage 之后"的**累计**快照，已经把
-- 之前所有关卡的效果算进去了，所以记住最远的那一关就够了，全集是冗余的。
--
-- 格式只有 {"stage":"C02S03"} —— 不引 JSON 库，理由同 load_main_screen。
local CAMPAIGN_PATH = '/sdcard/campaign_state.json'

-- 测试钩子：离线自测跑在宿主机上，没有 /sdcard，io.open 会直接失败。
-- 设备上用默认值，不影响运行时。理由同本文件其它 OfflineServer.* 导出。
function OfflineServer.campaign_path(p)
    if p then
        CAMPAIGN_PATH = p
    end
    return CAMPAIGN_PATH
end

-- 落盘的关卡可能已经不在表里了（表重建过 / 版本回退 / 手改成乱码）。
-- 这时必须丢掉回落默认值，不能带着一个查不到的 id 启动。
local function campaign_known(stage)
    return stage and _state.campaign_cd and _state.campaign_cd[stage] ~= nil
end

-- 这次通关是不是比落盘的更远？
--
-- campaign_order 是 Campaign.tsv 的**行序**（1..N），不是 campaign_order_rank()。
-- 实测 205 关只有 178 个不同的 rank —— C00S01 和 C00M01 这类剧情关共用同一个
-- rank，用 rank 比会打平，于是"打完 C00M01 再打 C00S01"这种正常推进不会更新
-- 落盘值，冷启动反而拿 C00M01 的快照。
-- 行序也正是 campaignProgress 快照的累加顺序，所以"行序更大" == "快照包含更多关卡"。
local function campaign_farther(new_stage, old_stage)
    local order = _state.campaign_order or {}
    local n = order[new_stage]
    local o = old_stage and order[old_stage] or nil

    -- 行序恒 >= 0，这里的 < 0 只是防御（万一以后换排序键）。
    if not n or n < 0 then
        return false
    end
    if not o or o < 0 then
        return true
    end
    return n > o
end

local function load_campaign_state()
    _state.saved_stage = nil
    local f = io.open(CAMPAIGN_PATH, 'r')

    if not f then
        slog('campaign state: 无落盘，10001 用初值快照')
        return
    end

    local raw = f:read('*a')
    f:close()
    -- string.match 返回捕获组本身；用 find 会把 "stage": 也截进去
    -- （load_main_screen 里踩过这个坑）。
    local stage = raw and string.match(raw, '"stage"%s*:%s*"([^"]*)"') or nil

    if stage and campaign_known(stage) then
        _state.saved_stage = stage
        slog('campaign state loaded: %s', stage)
    elseif stage then
        slog('campaign state 里 %s 已不在表里，丢弃回落初值', stage)
    end
end

local function save_campaign_state()
    if not campaign_known(_state.saved_stage) then
        return false
    end

    local f = io.open(CAMPAIGN_PATH, 'w')

    if not f then
        slog('!! cannot write %s', CAMPAIGN_PATH)
        return false
    end

    f:write('{"stage":"', _state.saved_stage, '"}')
    f:close()
    slog('campaign state saved: %s', _state.saved_stage)
    return true
end

-- 从请求体里抠编队。规则逐条照抄 rrcp_server.Server.parse_battle_teams：
--   1) 先扫带引号的 token，再扫裸 token（打包段里英雄名没有引号前缀）
--   2) 非 owned 的一律丢掉；裸 token 逐个前缀去 owned 里匹配（MoG2 -> MoG）
--   3) 按出现顺序去重
--   4) body 里还有别的候选时，剔掉 apply_team_config 自动塞的默认那对
--   5) 每个人在"自己结束位置 -> 下一个人开始位置"这一段里找 x/y
local function scan_team(raw)
    local owned = _state.hero_ids
    if type(raw) ~= 'string' or type(owned) ~= 'table' or #owned == 0 then
        return {}
    end

    local ownedset, nothero = {}, {}
    for _, h in ipairs(owned) do
        ownedset[h] = true
    end

    for _, h in ipairs(_state.team_not_hero or {}) do
        nothero[h] = true
    end

    -- Lua 模式没有 {n,m} 量词，用 * / + 代替；也不能像 Python 那样
    -- 一次 finditer 扫全文，改成 gmatch 收集 (位置, token)。
    local cands = {}
    local function scan(pat, quoted)
        local pos = 1
        while true do
            local s, e, tok = string.find(raw, pat, pos)
            if not s then
                break
            end
            pos = e + 1
            if not nothero[tok] then
                if not ownedset[tok] then
                    if quoted then
                        -- 带引号的是结构完整的字段名，不像英雄就丢掉
                    else
                        -- 裸 token 逐个前缀缩
                        local hit
                        for n = #tok - 1, 1, -1 do
                            if ownedset[string.sub(tok, 1, n)] then
                                hit = string.sub(tok, 1, n)
                                break
                            end
                        end
                        if hit then
                            cands[#cands + 1] = { s = s, e = e, t = hit }
                        end
                    end
                else
                    cands[#cands + 1] = { s = s, e = e, t = tok }
                end
            end
        end
    end

    scan('"([A-Za-z][A-Za-z0-9_]*)', true)
    scan('([A-Z][A-Za-z0-9_]+)', false)

    table.sort(cands, function (a, b)
        return a.s < b.s
    end)

    local hits, seen = {}, {}
    for _, c in ipairs(cands) do
        if not seen[c.t] then
            seen[c.t] = true
            hits[#hits + 1] = c
        end
    end

    -- 剔掉自动补的默认英雄（只在还有别的候选时剔）
    local def = {}
    for _, h in ipairs(_state.default_hero_ids or {}) do
        def[h] = true
    end
    local picked, non_def = {}, {}
    for _, h in ipairs(hits) do
        picked[#picked + 1] = h.t
        if not def[h.t] then
            non_def[#non_def + 1] = h.t
        end
    end

    local use, use_set = picked, {}
    if #non_def > 0 and #non_def < #picked then
        use = non_def
    end
    for _, h in ipairs(use) do
        use_set[h] = true
    end

    local slots = {}
    local cap = _state.team_cap or 5
    for i, c in ipairs(hits) do
        if not use_set[c.t] then
            -- 跳过
        else
            -- 段：从这个人名的结束位置，到下一个人名的开始位置
            local nxt = #raw + 1
            for j = i + 1, #hits do
                if hits[j].s > c.e then
                    nxt = hits[j].s
                    break
                end
            end
            local seg = string.sub(raw, c.e + 1, nxt - 1)
            -- Lua 模式没有先行断言，改成吃掉前一个非字母数字字符再捕获。
            local _, xs = string.match(seg, '([^%w_])x[^%w]*(%d+)')
            local _, ys = string.match(seg, '([^%w_])y[^%w]*(%d+)')
            slots[#slots + 1] = {
                heroId = c.t,
                x = tonumber(xs),
                y = tonumber(ys),
            }
            if #slots >= cap then
                break
            end
        end
    end
    return slots
end

-- 在请求体里找一个"表里确实存在"的键，返回 键, 值。
--
-- 不写死 T%d%d[SMX]%d%d 这种正则：StairsBattle.tsv 的 id 有两种形态
-- （T07S13 和 T_FIRE_S001），正则一漏就静默退回静态兜底，表现成
-- "天梯某一类关卡永远是第一关的敌人"。按表反查对任意 id 形态都成立。
local function find_keyed(raw, tbl, cap)
    if type(raw) ~= 'string' or type(tbl) ~= 'table' then
        return nil
    end
    cap = cap or 400
    local n = 0
    for tok in string.gmatch(raw, '[A-Za-z_][A-Za-z0-9_]*') do
        n = n + 1
        if n > cap then
            break
        end
        local v = tbl[tok]
        if v then
            return tok, v
        end
    end
    return nil
end

-- 【坏字节导致的"半个名字"】
--
-- 实测 15001 的请求体长这样（真机日志）：
--     {"isTen":true,"gachaId":"G
-- `_DoubleUp_ZhangY_BaiJ_1"}
-- 真正的池名是 Gacha_DoubleUp_ZhangY_BaiJ_1，但中间的 "acha" 被替换成了
-- 0x0A + 一个反引号。于是正则抠出来的 gachaId 是个污染名，直接查表必然落空。
--
-- Python 侧的做法是认不出来就回退到 Gacha_Base（rrcp_server.gacha_params +
-- build_gacha_response），能抽但池子是错的。这里做得更好一点：先用请求体里
-- **最长的干净片段**（只含字母数字下划线）去表里做"后缀反查"，
-- 因为污染通常只吃掉名字中间几个字母，后缀是完整的。上例中
-- "_DoubleUp_ZhangY_BaiJ_1" 唯一命中 Gacha_DoubleUp_ZhangY_BaiJ_1，
-- 于是能抽到玩家真正点的那个池；反查失败才回退 Gacha_Base。
local function find_gacha(raw, g)
    -- 返回卡池**裸名**（不带 |10 后缀）；实在认不出返回 'Gacha_Base'
    if type(g) ~= 'table' then
        return 'Gacha_Base'
    end

    -- 1) 请求体里直接就有完整池名
    if raw then
        local k = find_keyed(raw, g)
        if k then
            return (string.gsub(k, '|10$', ''))
        end
    end

    -- 2) 最长干净片段做"后缀反查"
    if raw then
        local best
        for tok in string.gmatch(raw, '[A-Za-z_][A-Za-z0-9_]*') do
            if not best or #tok > #best then
                best = tok
            end
        end
        -- 门槛 8：'gachaId'/'isTen' 这种键名片段太短，会误命中
        if best and #best >= 8 then
            local hit
            for key in pairs(g) do
                local bare = string.gsub(key, '|10$', '')
                if string.sub(bare, -#best) == best
                        and (not hit or #bare < #hit) then
                    hit = bare
                end
            end
            if hit then
                return hit
            end
        end
    end

    -- 3) 与 Python 一致地回退基础池
    return 'Gacha_Base'
end

-- 把预编码的英雄片段拼成数组，替换掉应答里的 __YQLR_TEAM__ 占位符。
-- 这里是"拼预编码片段"，不是"重新编码 JSON" —— 应答体里那 5 处空数组
-- [] 必须原样保留，cjson 往返会把它们变成 {}（见文件头）。
local function apply_team(body, stage)
    local tpl, ph = _state.hero_tpl, _state.team_ph
    if type(tpl) ~= 'table' or type(ph) ~= 'string' then
        return body
    end

    -- 用哪一队：请求体里抠到的优先，否则用落盘的，再否则用构建期默认
    local slots = _state.req_slots
    local ids, given = {}, {}
    for _, s in ipairs(slots or {}) do
        ids[#ids + 1] = s.heroId
        given[s.heroId] = s
    end
    if #ids == 0 and _state.team then
        for _, h in ipairs(_state.team) do
            ids[#ids + 1] = h
        end
    end
    if #ids == 0 then
        ids = _state.default_team or {}
    end
    if #ids == 0 then
        return body
    end

    local cap = _state.team_cap or 5
    while #ids > cap do
        ids[#ids] = nil
    end

    -- 【不足要补齐】请求里第 2 个以后的队员是紧凑打包的（实测 C01S04 第二成员
    -- 键是 "La6\x3f..." 而不是英雄 id），所以常常只能解出 1 个。
    -- 绝不能因此只派一个人上场 —— 用户实测就是"只会上一个角色"。
    -- 补位规则照抄 rrcp_server.gen_battle_data:3254-3281：
    --   先用"已拥有里非默认"的英雄补，一个都没有才退回服务端编队。
    --   不能拿默认那对来凑 —— 玩家看到的就是"一个默认一个我选的"。
    if #ids < cap then
        local def = {}
        for _, h in ipairs(_state.default_hero_ids or {}) do
            def[h] = true
        end
        local spare = {}
        for _, h in ipairs(_state.hero_ids or {}) do
            if not given[h] and not def[h] then
                spare[#spare + 1] = h
            end
        end
        if #spare == 0 and _state.team then
            for _, h in ipairs(_state.team) do
                if not given[h] then
                    spare[#spare + 1] = h
                end
            end
        end
        local missing = cap - #ids
        for i = 1, math.min(missing, #spare) do
            ids[#ids + 1] = spare[i]
        end
    end

    -- 这一关的默认站位 "x,y;x,y;..."
    local sp = {}
    local raw_sp = (_state.spots or {})[stage]
    if raw_sp then
        for part in string.gmatch(raw_sp, '[^;]+') do
            local a, b = string.match(part, '^(%-?%d+),(%-?%d+)$')
            if a then
                sp[#sp + 1] = { x = tonumber(a), y = tonumber(b) }
            end
        end
    end

    local attr = (_state.attrs or {})[stage] or '{}'
    -- 压地形的格子（MapDataId.landformSP）。玩家在编队界面能摆哪就摆哪，
    -- 不保证不压地形；Python 侧校验后回退到默认站位，Lua 必须一样 ——
    -- 压在���形上，那个地形技能会拿到 nil 的 target 直接崩
    -- （SpecialTerrain_XinShouHuiNeng0_4_2.lua:174/176）。
    local blocked = {}
    for c in string.gmatch((_state.terrain or {})[stage] or '', '[^;]+') do
        blocked[c] = true
    end

    local parts = {}
    local combat = 0
    for i, cid in ipairs(ids) do
        local frag = tpl[cid .. '#' .. i]
        if frag then
            local x, y
            local g = given[cid]
            if g and g.x and g.y and not blocked[g.x .. ',' .. g.y] then
                x, y = g.x, g.y
            elseif sp[i] then
                x, y = sp[i].x, sp[i].y
            else
                x, y = 1, 1 + i
            end
            -- x/y/attrs 在片段里都是**裸 token**（json 中不带引号），
            -- 所以按字面量替换，不加引号。占位符只由 build_lua_table.py
            -- 生成，形如 __YQLR_X__，只含字母和下划线，不是模式的魔法字符。
            -- 用函数式替换避开替换串里 % 的转义问题。
            frag = string.gsub(frag, _state.x_ph, function ()
                return tostring(x)
            end, 1)
            frag = string.gsub(frag, _state.y_ph, function ()
                return tostring(y)
            end, 1)
            frag = string.gsub(frag, _state.attr_ph, function ()
                return attr
            end, 1)
            parts[#parts + 1] = frag
            combat = combat + (_state.hero_combat or 0)
        end
    end
    if #parts == 0 then
        return body
    end

    -- friendCombat 是这一关友军的战功和（构建期算好）
    local fc = tonumber((_state.tcb or {})[stage]) or 0
    body = string.gsub(body, '"' .. ph .. '_TC"', function ()
        return tostring(combat + fc)
    end, 1)
    -- 只换引号里的哨兵，外层的 [ ] 保留
    return (string.gsub(body, '"' .. ph .. '"', function ()
        return table.concat(parts, ',')
    end, 1))
end

local function load_opcode_table()
    if type(OPCODE_TABLE) ~= 'table' then
        slog('opcode table missing (neither injected nor requirable)')
        return false
    end

    local t = OPCODE_TABLE
    _state.ops = t.opcodes
    _state.guideDataJson = t.guideDataJson
    _state.guidePlaceholder = t.guidePlaceholder
    _state.serverTimeTarget = t.serverTimeTarget
    _state.codeVersion = t.codeVersion
    _state.main_hero_ph = t.mainHeroPlaceholder
    _state.main_type_ph = t.mainTypePlaceholder
    _state.main_default = t.mainScreenDefault
    _state.debug_toggles = t.debugToggles
    -- 按关卡/卡池预编码的整份应答。Lua 只做"抠 id -> 查表"，不碰 JSON。
    _state.battles = t.battles
    _state.campaign_progress = t.campaignProgress
    _state.gacha = t.gacha
    -- 编队片段：heroTpl["<cid>#<slot>"] 里 x/y/uid/attrs 是占位符
    _state.hero_tpl = t.heroTpl
    _state.spots = t.spots
    _state.attrs = t.attrs
    _state.tcb = t.tcb
    _state.terrain = t.terrain
    _state.default_team = t.defaultTeam
    _state.hero_combat = t.heroCombat
    _state.team_ph = t.teamPh
    _state.x_ph = t.xPh
    _state.y_ph = t.yPh
    _state.uid_ph = t.uidPh
    _state.attr_ph = t.attrPh
    _state.hero_ids = t.heroIds
    _state.default_hero_ids = t.defaultHeroIds
    _state.team_cap = t.teamCap
    _state.team_not_hero = t.teamNotHero
    -- 关卡进度持久化：campaign_cd_ph 是 10001 里 CampaignData 的哨兵，
    -- campaign_cd[stage] 是对应关卡的片段，两者都齐了才能在 10001 里拼接。
    _state.campaign_cd = t.campaignCD
    _state.campaign_cd_ph = t.campaignCDPh
    _state.campaign_cd_default = t.campaignCDDefault
    _state.campaign_order = t.campaignOrder
    load_main_screen()
    load_team()
    -- 必须在 campaign_cd 赋值**之后**才能 load：它要校验落盘的关卡还在表里。
    load_campaign_state()

    local n = 0
    for _ in pairs(_state.ops) do
        n = n + 1
    end

    local function cnt(m)
        local c = 0
        if type(m) == 'table' then
            for _ in pairs(m) do
                c = c + 1
            end
        end
        return c
    end

    slog('opcode table loaded: %d entries, guideData=%s, serverTime=%s',
         n, tostring(_state.guideDataJson), tostring(_state.serverTimeTarget))
    slog('materialized: battles=%d campaignProgress=%d gacha=%d heroTpl=%d',
         cnt(_state.battles), cnt(_state.campaign_progress), cnt(_state.gacha),
         cnt(_state.hero_tpl))
    slog('campaign state: saved=%s default=%s cd=%d order=%d',
         tostring(_state.saved_stage), tostring(_state.campaign_cd_default),
         cnt(_state.campaign_cd), cnt(_state.campaign_order))
    return true
end

OfflineServer.load_opcode_table = load_opcode_table

-- 服务器时间：平移到 serverTimeTarget（本地时区），之后随真实时间前进。
-- 必须对齐 SignMonth.tsv 的有效期，否则客户端会用真实的 2026 年导致月份签到失效。
local function init_time_shift()
    local target = _state.serverTimeTarget
    _state.timeShift = 0
    if not target then
        return
    end
    local y, mo, d, h, mi, sec = target:match('(%d+)%-(%d+)%-(%d+) (%d+):(%d+):(%d+)')
    if not y then
        return
    end
    local tgt = os.time({
        year = tonumber(y), month = tonumber(mo), day = tonumber(d),
        hour = tonumber(h), min = tonumber(mi), sec = tonumber(sec), isdst = false,
    })
    _state.timeShift = tgt - os.time()
    slog('时间偏移：目标 %s，偏移 %+.1f 天', target, _state.timeShift / 86400.0)
end

OfflineServer.init_time_shift = init_time_shift

OfflineServer.server_time_ms = function ()
    return math.floor((os.time() + (_state.timeShift or 0)) * 1000)
end

local function be32(n)
    n = math.floor(n) % 4294967296
    return string.char(math.floor(n / 16777216) % 256,
                       math.floor(n / 65536) % 256,
                       math.floor(n / 256) % 256,
                       n % 256)
end

local function be64(n)
    local b = {}
    for i = 8, 1, -1 do
        b[i] = string.char(n % 256)
        n = math.floor(n / 256)
    end
    return table.concat(b)
end

local function be16(n)
    return string.char(math.floor(n / 256) % 256, n % 256)
end

-- 组响应体。布局与 rrcp_server.Server.build_response 完全一致：
--     [0] kind = 2
--     [1] comp = 0
--     [2:6] i32 req_id
--     [6:14] i64 timestamp
--     [14:18] i32 0
--     [18:20] i16 0
--     [20:24] u32 body_len
--     [24:] body
function build_response(req)
    if not _state.ops then
        return nil
    end

    local key = tostring(req.opcode)

    -- [10032] 调试面板指令。离线侧只能如实回答：应答体是构建期预编码的
    -- 字符串，改开关需要重跑 Python 侧的 apply_*()（要读 TSV），
    -- 这里做不到。明确报错好过静默走 default 空应答让人以为改了。
    if req.opcode == 10032 then
        local n = 0

        if _state.debug_toggles then
            for _ in pairs(_state.debug_toggles) do
                n = n + 1
            end
        end

        body = '{"resCode":1,"data":"离线构建不支持在线改服务端配置'
            .. '（应答体是构建期预编码的，改开关要重跑 apply_*）。'
            .. '可用开关 ' .. n .. ' 个：请用 Python mock，或改配置后重新构建。"}'
    -- [10038] changeHero = 设置主屏助理。
    -- 客户端只检查 resCode，真正生效靠应答里的 d.player 被
    -- Service.lua:71-77 派发成 EVT_SYNCHRONIZE_DIFF ->
    -- DevelopSystem:syncPlayer -> BasePlayer:synchronizeInfoDiff(:224-230)。
    -- 不回这个 diff，_mainScreenHeroId 就不变，于是"换了助理但语音还是上一个"。
    elseif req.opcode == 10038 then
        local raw = req.body or ''
        -- string.match，不是 find：find 给的是整个匹配的起止位置，
        -- string.sub(a+1, b) 会把 `"heroId":` 一起截进来。
        local function grab(name)
            return string.match(raw, '"' .. name .. '"%s*:%s*"([^"]*)"')
        end

        local hero = grab('heroId')
        local typ = grab('resourceType')

        -- resourceType 合法值只有 L2D / Por_Spine / Illustration
        -- （SelectPanelWidget.lua:10-12），其余沿用当前形态。
        local VALID = { L2D = true, Por_Spine = true, Illustration = true }

        if hero and hero ~= '' then
            if not typ or not VALID[typ] then
                typ = _state.main_type or 'Por_Spine'
            end

            _state.main_hero = hero
            _state.main_type = typ
            save_main_screen()
            slog('10038 changeHero -> %s / %s', tostring(hero), tostring(typ))
        end

        body = '{"resCode":0,"data":{},"d":{"player":{'
            .. '"mainScreenHeroId":"' .. tostring(_state.main_hero or '') .. '",'
            .. '"mainScreenType":"' .. tostring(_state.main_type or '') .. '"}}}'
    else
        body = _state.ops[key] or _state.ops['default']
    end

    if not body then
        body = '{"resCode":0,"data":{}}'
    end

    -- 10001 的引导进度：占位符换成本次要下发的 guideData
    if req.opcode == 10001 and _state.guidePlaceholder and _state.guideDataJson then
        local ph = '"' .. _state.guidePlaceholder .. '"'
        local from = 1
        local rep = nil
        while true do
            local a, b = string.find(body, ph, from, true)
            if not a then
                break
            end
            rep = string.sub(body, 1, a - 1) .. _state.guideDataJson
                  .. string.sub(body, b + 1)
            break
        end
        if rep then
            body = rep
        else
            slog('10001 里找不到占位符 %s，guideData 未下发', ph)
        end
    end

    -- [14002 / 21001 / 21005] 主线战斗 / 天梯战斗 / 天梯扫荡。
    --
    -- 构建期已按关卡把**整份应答**算好存进 OPCODE_TABLE.battles
    -- （1889 条 = 主线 203 + 天梯 1686）。Lua 侧只做"抠关卡号 -> 查表"，
    -- 不解码也不重编码：应答体里有空数组 []，cjson 往返会把它们变成 {}
    -- （reward / clubList 等会踩雷），所以整段只能原样发出。
    --
    -- 为什么不用占位符换 id：占位符只能换字符串字段，换不了整个 data。
    -- 敌人组成、站位、技能逐关不同（实测每关约 2.5 KB），全量 4.8 MB；
    -- 相对 1.7 GB 的 APK 可忽略，换来的是"每关敌方都正确"。
    if req.opcode == 14002 or req.opcode == 21001 or req.opcode == 21005 then
        local raw = req.body or ''
        local stage, hit = find_keyed(raw, _state.battles)
        if hit then
            -- 记住本次打的关卡：14003 的请求体里没有 campaignId（只有 15 B），
            -- 结算时只能靠这个 _state.last_stage 兜底。
            _state.last_stage = stage
            _state.req_slots = scan_team(raw)
            body = apply_team(hit, stage)
            local picked = {}
            for _, s in ipairs(_state.req_slots or {}) do
                picked[#picked + 1] = s.heroId
            end
            slog('%d 关卡 %s 命中预编码应答，我方编队 %s', req.opcode,
                 tostring(stage), table.concat(picked, ','))
        else
            slog('%d 请求里没解出关卡号，走静态兜底', req.opcode)
        end
    end

    -- [14003] 主线结算。
    --
    -- ⚠️ 关键：**14003 的请求体里没有 campaignId**（实测只有 15 B，
    -- 见 MEMORY 3017-3021）。Python 侧靠
    --     camp = self.extract_campaign(body) or self.last_campaign
    -- 记住"上一包 14002 打的是哪关"来兜底；离线端早期版本只从 body 里找，
    -- 15 B 的 body 根本没有关卡号 -> 查表落空 -> 走静态兜底 ->
    -- lastPassed 不推进 -> **关卡打过了但下一关不解锁**。
    -- 所以这里必须用 _state.last_stage（由 14002/21001/21005 写入）兜底。
    --
    -- 另外 campaignProgress 是构建期按"一路打上来"穷举的，
    -- 比在 Lua 里拼 CampaignData 稳得多（branchLastPassed 是嵌套 map，
    -- gsub 换不了）。
    if req.opcode == 14003 and _state.campaign_progress then
        local cid, hit = find_keyed(req.body or '', _state.campaign_progress)
        if not hit then
            cid = _state.last_stage
            hit = cid and _state.campaign_progress[cid] or nil
            if hit then
                slog('14003 请求体里无关卡号，用上一包 14002 的 %s 兜底', tostring(cid))
            end
        end
        if hit then
            body = hit
            slog('14003 关卡 %s 命中预编码结算应答', tostring(cid))
            -- 只在"确实更远了"时落盘。玩家打到 C03S05 后回头重打一关 C01S02，
            -- 如果无条件覆盖，下次启动进度就退回 C01S02 了。
            --
            -- 注意比的是 saved_stage 而不是 last_stage：last_stage 刚被上一包
            -- 14002 设成本次打的关，拿它比自己跟自己比，结果永远是"没变远"。
            if cid and campaign_farther(cid, _state.saved_stage) then
                _state.saved_stage = cid
                save_campaign_state()
            end
        else
            slog('14003 没解出关卡号（last_stage=%s），走静态兜底',
                 tostring(_state.last_stage))
        end
    end

    -- [15001] 抽卡。构建期每个卡池跑过单抽和十连，各存一份。
    -- 离线端没有随机源，固定结果反而更合脚：同一个池反复十连结果一样。
    if req.opcode == 15001 and _state.gacha then
        local raw = req.body or ''
        -- isTen 只决定取单抽还是十连那份。实测它后面也可能跟坏字节，
        -- 所以用 '[^%w]+' 容忍分隔，而不是写死 '"isTen":'。
        local is_ten = string.match(raw, '"isTen"[^%w]+true') ~= nil
        local name = find_gacha(raw, _state.gacha)
        local key = is_ten and (name .. '|10') or name
        local hit = _state.gacha[key]
        if not hit then
            -- 表里只有一种时互相兜一下
            local alt = is_ten and name or (name .. '|10')
            if _state.gacha[alt] then
                key, hit, is_ten = alt, _state.gacha[alt], not is_ten
            end
        end
        if hit then
            body = hit
            slog('15001 卡池 %s%s 命中预编码应答', tostring(name),
                 is_ten and ' 十连' or '')
        else
            slog('15001 卡池 %s 键 %s 未命中，走静态兜底', tostring(name),
                 tostring(key))
        end
    end

    -- [29001] 改编队。
    --
    -- 客户端实际上不发这个 opcode —— 编队是随 14002 的请求体一起过来的
    -- （实测 C01S02 的 body 里就有 teams 段）。这里仍按能收到来解析并存盘，
    -- 让离线端与 Python 侧的 team_state.json 保持同一份数据。
    if req.opcode == 29001 then
        local slots = scan_team(req.body or '')
        local ids = {}
        for _, s in ipairs(slots) do
            ids[#ids + 1] = s.heroId
        end
        if #ids > 0 then
            save_team(ids)
        end
        slog('29001 编队 %s', table.concat(ids, ','))
    end

    -- 10001 的主屏助理：占位符换成落盘状态。
    -- 这两个是标量字符串字段，gsub 替换是安全的（不需要重新编码整段 JSON）。
    if req.opcode == 10001 and _state.main_hero_ph then
        local function sub1(s, ph, val)
            local phq = '"' .. ph .. '"'
            local vq = '"' .. tostring(val or '') .. '"'
            local a, b = string.find(s, phq, 1, true)

            if not a then
                return s
            end

            return string.sub(s, 1, a - 1) .. vq .. string.sub(s, b + 1)
        end

        body = sub1(body, _state.main_hero_ph, _state.main_hero)
        body = sub1(body, _state.main_type_ph, _state.main_type)
    end

    -- 10001 的关卡进度：把构建期埋的哨兵换成本次要下发的 CampaignData。
    --
    -- 这一步**不能省**，而且**必须有兜底**。
    --  · 不能省：客户端每次冷启动先收 10001，进度是从这里读的；只在 14003
    --    落盘的话，重进游戏时 10001 照样把进度打回构建时的初值。
    --  · 要兜底：哨兵是个**字符串**，而 CampaignData 必须是**对象**。
    --    没有落盘（新装/清数据）时如果直接跳过替换，客户端就会拿到
    --    "CampaignData":"__YQLR_CD__"，进主线就炸。所以拿初值快照兜底，
    --    语义上等于"全新玩家"，和 Python 侧冷启动一致。
    --
    -- 替换的是整个值（哨兵是个字符串），不是逐字段改 —— 所以 Lua 不需要知道
    -- 原对象的字节范围，也不重新编码任何 JSON（campaignCD 是构建期编码好的片段）。
    if req.opcode == 10001 and _state.campaign_cd_ph then
        local stage = _state.saved_stage or _state.campaign_cd_default
        local cd = stage and _state.campaign_cd and _state.campaign_cd[stage]

        if cd then
            local phq = '"CampaignData":"' .. _state.campaign_cd_ph .. '"'
            local a, b = string.find(body, phq, 1, true)

            if a then
                body = string.sub(body, 1, a - 1) .. '"CampaignData":' .. cd
                      .. string.sub(body, b + 1)
                slog('10001 CampaignData 用 %s 替换（%s）', stage,
                     _state.saved_stage and '落盘进度' or '初值快照')
            else
                slog('!! 10001 里找不到 CampaignData 哨兵 %s，哨兵会发给客户端',
                     _state.campaign_cd_ph)
            end
        else
            -- 表里连初值都没有 = 构建期就出错了。宁可发一个最小合法对象，
            -- 也绝不能让哨兵字符串流到客户端。
            slog('!! 没有可用的 CampaignData 快照（saved=%s default=%s），下发空对象',
                 tostring(_state.saved_stage), tostring(_state.campaign_cd_default))
            local phq = '"CampaignData":"' .. _state.campaign_cd_ph .. '"'

            if string.find(body, phq, 1, true) then
                body = string.gsub(body, '"CampaignData":"' .. _state.campaign_cd_ph .. '"',
                                   '"CampaignData":{}', 1)
            end
        end
    end

    return string.char(2, 0)
           .. be32(req.req_id)
           .. be64(OfflineServer.server_time_ms())
           .. be32(0)
           .. be16(0)
           .. be32(#body)
           .. body
end

OfflineServer.build_response = build_response

-- 数据帧：[u32 BE crc32(rsp)][u32 BE len(rsp)][rsp]，外层 type = 0
function send_data_frame(sock, rsp)
    local wire = be32(bit.band(_crc32(rsp, 0), 0xFFFFFFFF)) .. be32(#rsp) .. rsp
    return send_frame(sock, T_DATA, wire)
end

OfflineServer.send_data_frame = send_data_frame

-- ---------------------------------------------------------------- socket 循环
local function on_readable(srv)
    local sock, err, partial = srv:accept()
    if not sock then
        if err ~= 'timeout' then
            slog('accept 失败: %s', tostring(err))
        end
        return
    end
    if _state.client then
        pcall(function () _state.client:close() end)
    end
    _state.client = sock
    _state.buf = ''
    _state.phase = 'new'
    sock:settimeout(0)
    slog('客户端已连接')
end

local function on_client_readable(sock)
    local data, err, partial = sock:receive(4096)

    -- 重要：LuaSocket 在非阻塞下即使有数据，也可能返回
    --     nil, "timeout", partial
    -- 即使返回了部分数据，那些字节也在 partial 里。只看 data 会把
    -- 握手全部丢掉 -> 永远解析不出帧。
    local chunk = data
    if (not chunk) and partial and #partial > 0 then
        chunk = partial
    end

    if chunk and #chunk > 0 then
        _state.buf = _state.buf .. chunk
        _state.nrecv = (_state.nrecv or 0) + 1
        if _state.nrecv <= 3 then
            slog('recv#%d 本次 %d B 累计 %d B (data=%s partial=%d B) | 前 64 B: %s',
                 _state.nrecv, #chunk, #_state.buf, data and 'yes' or 'no',
                 partial and #partial or 0, hexdump(_state.buf, 64))
            if #_state.buf >= 4 then
                slog('  解析头: len=%d mtype=0x%02X  (需要 %d B 才够)',
                     transport_len(u8(_state.buf, 1), u8(_state.buf, 2), u8(_state.buf, 3)),
                     u8(_state.buf, 4),
                     4 + transport_len(u8(_state.buf, 1), u8(_state.buf, 2), u8(_state.buf, 3)))
            end
        end
        while true do
            local fr = try_parse_frame(_state.buf)
            if not fr then
                break
            end
            _state.buf = fr.rest
            -- xpcall(f, handler) 不会把额外参数传给 f，必须用闭包把 fr 传进去。
            local ok, e = xpcall(function ()
                return on_frame(fr)
            end, function (err)
                return tostring(err) .. '\n' .. (debug.traceback('', 2) or '')
            end)
            if not ok then
                slog('on_frame 异常:\n%s', tostring(e))
            end
        end
        return true
    end
    -- err == 'timeout' 且没有任何新字节 = 这一轮没读到数据，不是断开
    if err == 'timeout' then
        return true
    end

    slog('客户端断开: err=%s 本地已收 %d B', tostring(err),
         partial and #partial or 0)
    pcall(function () sock:close() end)
    _state.client = nil
    _state.buf = ''
    return false
end

local function tick()
    if not _state.listen then
        return
    end
    local readable = {}
    local n = 0
    local srv = _state.listen
    n = n + 1
    readable[n] = srv
    if _state.client then
        n = n + 1
        readable[n] = _state.client
    end
    -- socket 模块在 start() 里是**局部变量**，全局 socket 为 nil，
    -- 这里必须用缓存的 SOCK，不能直接写 socket.select。
    local ok, r, e = pcall(SOCK.select, readable, nil, 0)
    if not ok then
        return
    end
    for i = 1, (r and #r or 0) do
        local s = r[i]
        if s == srv then
            on_readable(srv)
        elseif s == _state.client then
            local keep = on_client_readable(s)
            if not keep then
                _state.client = nil
            end
        end
    end
end

-- ---------------------------------------------------------------- 启动
function OfflineServer.start(port)
    port = port or SVR_PORT
    local sk = require('socket')
    SOCK = sk
    local srv = sk.bind('127.0.0.1', port)
    if not srv then
        slog('bind 127.0.0.1:%d 失败', port)
        return false
    end
    srv:settimeout(0)
    _state.listen = srv
    OfflineServer.tick = tick
    OfflineServer.stop = function ()
        if _state.client then
            pcall(function () _state.client:close() end)
            _state.client = nil
        end
        pcall(function () _state.listen:close() end)
        _state.listen = nil
        slog('已停止')
    end
    math.randomseed(os.time() + math.floor((os.clock() or 0) * 1000000) % 1000000)

    local key = {}
    for i = 1, SESSION_KEY_LEN do
        key[i] = string.char(math.random(0, 255))
    end
    _state.session_key = table.concat(key)

    OfflineServer.selfTestCrc32()
    OfflineServer.selfTestRsa()
    load_opcode_table()
    init_time_shift()
    slog('内置离线服务端已监听 127.0.0.1:%d（阶段 1：仅解析，不回包）', port)
    return true
end

-- 挂到主循环：socket 全部非阻塞（settimeout(0) + socket.select），
-- 每帧只 poll 一次，所以跑在 UI 线程也不会卡界面。
-- 调度器入口照 LuaScheduler.lua:2 / :137 的写法：
--     cc.Director:getInstance():getScheduler():scheduleScriptFunc(fn, interval, repeat)
function OfflineServer.install()
    if not OfflineServer.start(SVR_PORT) then
        return false
    end

    local ok, sched = pcall(function ()
        return cc.Director:getInstance():getScheduler()
    end)

    if not ok or not sched then
        slog('get no cocos Scheduler; not wired into main loop')
        return false
    end

    OfflineServer._tickCount = 0
    OfflineServer._errCount = 0

    -- 完全照搬游戏自己的每帧心跳：biubiu/schedule/LuaScheduler.lua:137
    --     self.tickEntry = getCCScheduler():scheduleScriptFunc(function (dt) ... end, 0, false)
    -- 差别就在“不重排”：本构建的 one-shot 定时器本身就会持续触发，
    -- 游戏的动画/表示系统就是这么跑的。
    -- 我们曾在回调里再 scheduleScriptFunc 一次 -> 定时器堆积，
    -- 实测原始回调高达 27 万 次/秒（每次都负担一次 pcall + 新建定时器），
    -- 卡得游戏停在 61% 资源加载。
    --
    -- 另外实测结果（同一构建）：
    --   repeat=true（interval 0 或 0.05）-> 回调一次都不跑，不可用
    --   repeat=false + 回调内重排 -> 27–78 万次/秒，不可用
    --   repeat=false + 只注册一次            -> 正常，本服务端采用此方式
    local function loop()
        local n = OfflineServer._tickCount + 1
        OfflineServer._tickCount = n

        if n <= 3 or n % 120 == 0 then
            slog('tick #%d buf=%d B listening=%s',
                 n, #_state.buf, tostring(_state.listen ~= nil))
        end

        local ok2, err = pcall(OfflineServer.tick)
        if not ok2 then
            OfflineServer._errCount = OfflineServer._errCount + 1
            local e = OfflineServer._errCount
            if e <= 3 or e % 120 == 0 then
                slog('tick ERROR #%d at tick %d: %s', e, n, tostring(err))
            end
        end
    end

    OfflineServer._entry = nil

    local ok3, entry = pcall(function ()
        return sched:scheduleScriptFunc(loop, 0, false)
    end)

    if ok3 then
        OfflineServer._entry = entry
        slog('wired to cocos Scheduler: scheduleScriptFunc(fn, 0, once), registered '
             .. 'ONCE and never re-armed - identical to LuaScheduler:137')
    else
        slog('scheduleScriptFunc registration failed: %s', tostring(entry))
    end

    return ok3
end
