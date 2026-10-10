# -*- coding: utf-8 -*-
"""离线验证内置 Lua 服务端的应答层（省一次 4.5 分钟的打包）。

做法和 build_patched_luac.py 一样把 opcode 表内联进 offline_server.lua，
然后在 luajit 里 load 进来，直接调 build_response，检查：
  - 24 字节头布局对不对
  - body 是不是合法 JSON
  - 10001 的 guideData 占位符是否被替换掉
"""
import io
import json
import os
import subprocess
import sys
import tempfile

HERE = r'D:\Temp\yqlr\_out_repack'
LUA_DIR = os.path.join(HERE, 'lua')
LUAJIT = r'E:\lib\LuaJIT\src\luajit.exe'
PH = 'if not OPCODE_TABLE then'


def spliced_src():
    src = io.open(os.path.join(LUA_DIR, 'offline_server.lua'), encoding='utf-8').read()
    tbl = io.open(os.path.join(LUA_DIR, 'opcode_table.lua'), encoding='ascii').read()
    assert PH in src, 'placeholder missing'
    return src.replace(PH, tbl + '\n' + PH, 1)


HARNESS = r'''
local chunk, err = loadfile([[__LUA__]])
if not chunk then print('LOAD FAIL: ' .. tostring(err)) os.exit(1) end
local ok, e = pcall(chunk)
if not ok then print('RUN FAIL: ' .. tostring(e)) os.exit(1) end

OfflineServer.load_opcode_table()
OfflineServer.init_time_shift()

-- 直接构造一条 10001 请求
local function be32(n)
  return string.char(math.floor(n/16777216)%256, math.floor(n/65536)%256,
                     math.floor(n/256)%256, n%256)
end
local req = { kind = 1, comp = 1, req_id = 7, opcode = 10001, body_len = 0 }

local rsp = OfflineServer.build_response(req)
if not rsp then print('build_response returned nil') os.exit(1) end
print('10001 rsp total = ' .. #rsp)

-- 头 24 字节
local function u32(s, i)
  local a, b, c, d = s:byte(i, i + 3)
  return ((a * 256 + b) * 256 + c) * 256 + d
end
print(string.format('  kind=%d comp=%d req_id=%d ts=%d b=%d c=%d len=%d',
      rsp:byte(1), rsp:byte(2), u32(rsp, 3), 0, u32(rsp, 15), 0, u32(rsp, 21)))
local blen = u32(rsp, 21)
print(string.format('  header len=%d  body len=%d  一致=%s',
      24, blen, tostring(blen == #rsp - 24)))
print('  ts 值 = ' .. tostring(OfflineServer.server_time_ms()))

local body = rsp:sub(25)
local out = io.open('__BODY__', 'wb')
out:write(body)
out:close()
print('  占位符残留 = ' .. tostring(body:find('__YQLR_GUIDEDATA__', 1, true) ~= nil))
print('  含 guideData = ' .. tostring(body:find('"guideData"', 1, true) ~= nil))
print('  主屏助理占位符残留 = '
      .. tostring(body:find('__YQLR_MAINHERO__', 1, true) ~= nil))

-- 未知 opcode 走 default
local r2 = OfflineServer.build_response({ req_id = 9, opcode = 99999 })
print('  default rsp total = ' .. #r2 .. ' body=' .. r2:sub(25))

-- ------------------------------------------------ 14002 主线战斗（逐关）
-- 关卡不同 -> 敌方必须不同。这是之前最大的坑：表里只有一份 C00S01，
-- 玩到第二关起敌人/站位全是第一关的。
local function battle_of(stage)
  local r = OfflineServer.build_response({
    req_id = 31, opcode = 14002, body = '{"campaignId":"' .. stage .. '"}' })
  return r:sub(25)
end

local function first_enemy(b)
  return tostring(string.match(b, '"enemyData".-"cid":"([^"]*)"'))
end

local b1, b2 = battle_of('C01S01'), battle_of('C05S03')
print('14001.. 14002 C01S01 len=' .. #b1 .. '  C05S03 len=' .. #b2)
print('  campaignId  = ' .. tostring(string.match(b1, '"campaignId":"([^"]*)"')))
print('  敌方 cid   = ' .. first_enemy(b1) .. '  vs  ' .. first_enemy(b2))
print('  两关敌方不同 = ' .. tostring(first_enemy(b1) ~= first_enemy(b2)))
print('  占位符残留   = '
      .. tostring(b1:find('__YQLR_', 1, true) ~= nil))

-- ------------------------------------------------ 编队替换
-- 请求体里带 teams 段（实测客户端就是这么发的，字段顺序还不固定）。
-- 应答里的 __YQLR_TEAM__ 必须被换成真实英雄对象数组。
local team_body = '{"battleData":{"teams":{"ShiZ":{"x":1,"y":1},'
    .. '"CaiH":{"x":1,"y":3}}},"campaignId":"C01S01"}'
local rt = OfflineServer.build_response({
  req_id = 32, opcode = 14002, body = team_body })
local bt = rt:sub(25)
print()
print('14002 带编队 len = ' .. #bt)
print('  占位符残留 = ' .. tostring(bt:find('__YQLR_', 1, true) ~= nil))
local heros = string.match(bt, '"heros":%[(.-)%]},"enemyData"')
print('  heros 段长度 = ' .. tostring(heros and #heros or -1))
local n = 0
for _ in string.gmatch(heros or '', '"uid":"100001_') do n = n + 1 end
print('  我方出战人数 = ' .. n)
for cid in string.gmatch(heros or '', '"cid":"([^"]*)"') do
  print('    cid = ' .. cid)
end
print('  片段前 160 字符 = ' .. string.sub(heros or 'NIL', 1, 160))
print('  totalCombat = '
      .. tostring(string.match(bt, '"totalCombat":(%d+)')))
-- x/y 必须都填成数字，不能留占位符
local bad = string.match(bt, '"x":[^%d]') or string.match(bt, '"y":[^%d]')
print('  x/y 全为数字 = ' .. tostring(bad == nil))

-- 没抠到编队时要用构建期默认队（5 人）
local bd = battle_of('C01S01')
local hd = string.match(bd, '"heros":%[(.-)%]},"enemyData"')
local nd = 0
for _ in string.gmatch(hd or '', '"uid":"100001_') do nd = nd + 1 end
print('  无编队时默认人数 = ' .. nd)

-- ------------------------------------------------ 21001/21005 天梯（逐关）
local function ladder_of(op, stage)
  local r = OfflineServer.build_response({
    req_id = 33, opcode = op, body = '{"id":"' .. stage .. '"}' })
  return r:sub(25)
end

local l1 = ladder_of(21001, 'T07S13')
local l2 = ladder_of(21001, 'T24S40')
print()
print('21001 T07S13 campaignId = '
      .. tostring(string.match(l1, '"campaignId":"([^"]*)"')))
print('  gridBattleId = '
      .. tostring(string.match(l1, '"gridBattleId":"([^"]*)"')))
print('21001 T24S40 campaignId = '
      .. tostring(string.match(l2, '"campaignId":"([^"]*)"')))
print('  敌方 cid = ' .. first_enemy(l1) .. '  vs  ' .. first_enemy(l2))
print('  两关敌方不同 = ' .. tostring(first_enemy(l1) ~= first_enemy(l2)))
print('  占位符残留 = ' .. tostring(l1:find('__YQLR_', 1, true) ~= nil))
print('21005 campaignId = '
      .. tostring(string.match(ladder_of(21005, 'T07S13'),
                               '"campaignId":"([^"]*)"')))

-- 21002 结算：pass 必须为 true，否则打赢被判失败
local r02 = OfflineServer.build_response({ req_id = 23, opcode = 21002, body_len = 0 })
local b02 = r02:sub(25)
print('21002 body = ' .. b02)
print('  pass = ' .. tostring(string.match(b02, '"pass":(%a+)')))
print('  withdraw = ' .. tostring(string.match(b02, '"withdraw":(%a+)')))

-- ------------------------------------------------ 14003 主线结算（逐关推进）
-- 必须带 d.player.CampaignData，且不同关的 lastPassed 不同，
-- 否则主线进度永远停在第一关。
local function prog_of(stage)
  local r = OfflineServer.build_response({
    req_id = 34, opcode = 14003, body = '{"campaignId":"' .. stage .. '"}' })
  return r:sub(25)
end

local p1, p2 = prog_of('C01S01'), prog_of('C02S03')
print()
print('14003 C01S01 lastPassed = '
      .. tostring(string.match(p1, '"lastPassed":"([^"]*)"')))
print('14003 C02S03 lastPassed = '
      .. tostring(string.match(p2, '"lastPassed":"([^"]*)"')))
print('  带 d.player = ' .. tostring(p1:find('"player"', 1, true) ~= nil))
print('  两关进度不同 = '
      .. tostring(string.match(p1, '"lastPassed":"([^"]*)"')
               ~= string.match(p2, '"lastPassed":"([^"]*)"')))
print('  占位符残留 = ' .. tostring(p1:find('__YQLR_', 1, true) ~= nil))

-- ------------------------------------------------ 15001 抽卡
-- ⚠️ 真机实测：gachaId 会带坏字节（真机日志 18:59:35）：
--     {"isTen":true,"gachaId":"G<0x0A>`_DoubleUp_ZhangY_BaiJ_1"}
-- 真正的池名是 Gacha_DoubleUp_ZhangY_BaiJ_1，中间的 "acha" 被吃掉了。
-- 抠出来的名字是脏的，直接查表必然落空 —— 必须能反查回真池。
local DIRTY = 'G\n`_DoubleUp_ZhangY_BaiJ_1'
local function gacha_of(js)
  local r = OfflineServer.build_response({
    req_id = 35, opcode = 15001, body = js })
  return r:sub(25)
end

local g1 = gacha_of('{"gachaId":"Gacha_Base","isTen":false}')
local g10 = gacha_of('{"gachaId":"Gacha_Base","isTen":true}')
local gdirty = gacha_of('{"isTen":true,"gachaId":"' .. DIRTY .. '"}')
-- 另一个卡池，确认不是只对 Gacha_Base 生效
local g2 = gacha_of('{"gachaId":"Gacha_SingleUp_S01","isTen":false}')
print()
print('15001 单抽 len = ' .. #g1 .. '  十连 len = ' .. #g10
      .. '  另一卡池 len = ' .. #g2)
print('  坏字节 gachaId len = ' .. #gdirty .. '  占位符残留 = '
      .. tostring(gdirty:find('__YQLR_', 1, true) ~= nil))
print('  含 result = ' .. tostring(g1:find('"result"', 1, true) ~= nil))
-- 出货在 data.result 里，每项形如 {"code":"ChuanSJ","type":"CHAR","amount":1}
local function codes(s)
  local r = {}
  for c in string.gmatch(s, '"code":"([^"]*)"') do r[#r + 1] = c end
  return r
end
local c1, c10, cd = codes(g1), codes(g10), codes(gdirty)
print('  单抽出货 = ' .. #c1 .. ' 种: ' .. table.concat(c1, ','))
print('  十连出货 = ' .. #c10 .. ' 种: ' .. table.concat(c10, ','))
print('  十连种类更多 = ' .. tostring(#c10 > #c1))
print('  坏字节卡池出货 = ' .. #cd .. ' 种（应为 10，说明反查到了真池）')

-- ------------------------------------------------ 29001 改编队
local r29 = OfflineServer.build_response({ req_id = 24, opcode = 29001, body_len = 0 })
print()
print('29001 body len = ' .. #r29:sub(25)
      .. '  带 d.player = '
      .. tostring(r29:sub(25):find('"d"', 1, true) ~= nil))

-- ------------------------------------------------ 14003 无 campaignId（真实请求体）
-- ⚠️ 回归用例：真客户端的 14003 请求体**只有 15 B，不带 campaignId**
-- （见 MEMORY 3017-3021）。Python 侧靠
--     camp = extract_campaign(body) or self.last_campaign
-- 记住上一包 14002 的关卡来兜底。
-- 早期离线端只从 body 里找关卡号，15 B 里根本没有 -> 查表落空 ->
-- 走静态兜底 -> lastPassed 不推进 -> 「关卡打过了但下一关不解锁」。
-- 这个用例必须**先发 14002 再发裸 14003**，不能像上面那样直接喂关卡号。
local function raw_req(op, body)
  return OfflineServer.build_response({ req_id = 90, opcode = op, body = body })
end

-- 1) 先打一关：14002 请求体里带 campaignId
--    注意关卡号必须是**真实存在**的（C03 只有 5 关，没有 C03S02，
--    用不存在的 id 会让 14002 直接走静态兜底，这条用例就测不到东西了）
raw_req(14002, '{"campaignId":"C01S02","battleData":{}}')
-- 2) 再结算：**空 body**，模拟真客户端那 15 B 的请求
local r14003 = raw_req(14003, '')
local b14003 = r14003:sub(25)
print()
print('=== 14003 空 body（模拟真实 15B 请求）===')
print('  lastPassed = ' .. tostring(string.match(b14003, '"lastPassed":"([^"]*)"')))
print('  占位符残留 = ' .. tostring(b14003:find('__YQLR_', 1, true) ~= nil))
print('  应与 C01S02 的预编码结算一致 = '
      .. tostring(string.match(b14003, '"lastPassed":"([^"]*)"') == 'C01S02'))

local function app_body(heroId, resourceType)
  return string.char(0,0,0,0, 9, 8) .. 'tester_11'
      .. '{"heroId":"' .. heroId .. '","resourceType":"' .. resourceType .. '"}'
end

local r38 = OfflineServer.build_response({
  req_id = 11, opcode = 10038, body = app_body('BaiJ', 'L2D') })
local b38 = r38:sub(25)
print('10038 body = ' .. b38)
print('  带 d.player = ' .. tostring(b38:find('"mainScreenHeroId"', 1, true) ~= nil))

-- 10001 要把这个选择带回来
local r38b = OfflineServer.build_response({ req_id = 12, opcode = 10001, body_len = 0 })
local bb = r38b:sub(25)
local function grab(s, k)
  return string.match(s, '"' .. k .. '"%s*:%s*"([^"]*)"')
end
print('10001 带回 mainScreenHeroId = ' .. tostring(grab(bb, 'mainScreenHeroId')))
print('10001 带回 mainScreenType   = ' .. tostring(grab(bb, 'mainScreenType')))

-- 形态非法要沿用，不写脏值
local r38c = OfflineServer.build_response({
  req_id = 13, opcode = 10038, body = app_body('AnWZ', '???') })
print('10038 非法形态后的 type = '
      .. tostring(grab(r38c:sub(25), 'mainScreenType')))

-- ------------------------------------------------ 10032 调试面板
local r32 = OfflineServer.build_response({ req_id = 14, opcode = 10032, body = '' })
print('10032 body = ' .. r32:sub(25):sub(1, 120))
'''


# 关卡进度持久化单独跑，因为要**跑两遍**才能验证冷启动：
# 第一遍打完关写盘，第二遍（新进程 = 真冷启动）读盘并检查 10001 的 CampaignData。
PERSIST_HARNESS = r'''
local chunk, err = loadfile([[__LUA__]])
if not chunk then print('LOAD FAIL: ' .. tostring(err)) os.exit(1) end
local ok, e = pcall(chunk)
if not ok then print('RUN FAIL: ' .. tostring(e)) os.exit(1) end

OfflineServer.campaign_path([[__STATE__]])
OfflineServer.load_opcode_table()

local function body_of(op, b)
  return OfflineServer.build_response({ req_id = 1, opcode = op, body = b }):sub(25)
end
local function cd_of(b10001)
  return string.match(b10001, '"CampaignData":(%b{})')
end
local function last_passed(b10001)
  return string.match(b10001, '"lastPassed":"([^"]*)"')
end

local b10001 = body_of(10001, '')
print('启动时 lastPassed = ' .. tostring(last_passed(b10001)))
print('  CampaignData 是对象(非哨兵) = '
      .. tostring(cd_of(b10001):sub(1, 1) == '{'))

if os.getenv('YQLR_PERSIST_PLAY') then
  -- 真实链路：14002 打关 -> 14003 空 body 结算 -> 落盘
  body_of(14002, '{"campaignId":"C01S02"}')
  body_of(14003, '\x00\x01\x02\x03')
  -- 再打一关更远的，进度要推进
  body_of(14002, '{"campaignId":"C02S03"}')
  body_of(14003, '\x00\x01\x02\x03')
  -- 重打一关旧的，进度**不能**被写回去
  body_of(14002, '{"campaignId":"C01S02"}')
  body_of(14003, '\x00\x01\x02\x03')
  print('通关后落盘内容 = ' .. io.open([[__STATE__]]):read('*a'))
end
'''


def main():
    tmpdir = tempfile.mkdtemp(prefix='yqlr_rsp_')
    lua_path = os.path.join(tmpdir, 'spliced.lua')
    body_path = os.path.join(tmpdir, 'body10001.json')
    with io.open(lua_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(spliced_src())
    with io.open(os.path.join(tmpdir, 'harness.lua'), 'w', encoding='utf-8', newline='\n') as f:
        f.write(HARNESS.replace('__LUA__', lua_path.replace('\\', '/'))
                 .replace('__BODY__', body_path.replace('\\', '/')))

    r = subprocess.run([LUAJIT, os.path.join(tmpdir, 'harness.lua')],
                       capture_output=True, text=True)
    print(r.stdout)
    if r.stderr:
        print('STDERR:', r.stderr)

    # ---------------------------------------------------- 关卡进度持久化
    state = os.path.join(tmpdir, 'campaign_state.json')
    with io.open(os.path.join(tmpdir, 'persist.lua'), 'w', encoding='utf-8', newline='\n') as f:
        f.write(PERSIST_HARNESS.replace('__LUA__', lua_path.replace('\\', '/'))
                 .replace('__STATE__', state.replace('\\', '/')))
    pj = os.path.join(tmpdir, 'persist.lua')

    print('=' * 68)
    print('=== 关卡进度持久化 ===')
    print('-- 第 1 次运行（冷启动，无落盘） --')
    r1 = subprocess.run([LUAJIT, pj], capture_output=True, text=True)
    print(r1.stdout, end='')

    print('-- 第 2 次运行（打完 3 关并落盘，同一进程内继续） --')
    env = dict(os.environ, YQLR_PERSIST_PLAY='1')
    r2 = subprocess.run([LUAJIT, pj], capture_output=True, text=True, env=env)
    print(r2.stdout, end='')

    saved = io.open(state, encoding='utf-8').read() if os.path.exists(state) else '(缺失)'
    print('落盘文件内容 = %s' % saved)
    print('  应为 C02S03（最后一关是旧关 C01S02，不能把进度写回去） = %s'
          % ('{"stage":"C02S03"}' == saved.strip()))

    print('-- 第 3 次运行（模拟冷启动：重新读盘） --')
    out = subprocess.run([LUAJIT, pj], capture_output=True, text=True, env=env)
    print(out.stdout, end='')
    print('  冷启动后 lastPassed 应为 C02S03 = %s'
          % ('启动时 lastPassed = C02S03' in out.stdout))
    print('  CampaignData 应为对象而非哨兵 = %s'
          % ('CampaignData 是对象(非哨兵) = true' in out.stdout))

    if os.path.exists(body_path):
        raw = io.open(body_path, 'rb').read().decode('ascii')
        try:
            d = json.loads(raw)
            print('body JSON 合法，顶层键 = %s' % sorted(d))
            gd = d.get('data', {}).get('player', {}).get('guideData')
            print('guideData = %s' % json.dumps(gd, ensure_ascii=False))
            p = d.get('data', {}).get('player', {})
            print('player 字段数 = %d' % len(p))
            print('player.coin = %s  level = %s' % (p.get('coin'), p.get('level')))
            bag = p.get('bag')
            if isinstance(bag, dict):
                items = bag.get('items')
                print('bag.items 条数 = %s' % (len(items) if hasattr(items, '__len__') else '?'))
            datas = p.get('datas')
            if isinstance(datas, dict):
                print('player.datas 键 = %s' % sorted(datas)[:12])
        except Exception as ex:
            print('body JSON 解析失败:', ex)
    return 0


if __name__ == '__main__':
    sys.exit(main())