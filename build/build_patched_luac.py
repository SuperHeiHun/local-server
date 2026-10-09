#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build_patched_luac.py -- 批量补丁：Lua 源码 -> LuaJIT 字节码 -> XXTEA -> 新路径 -> 同步清单

换加密资源的完整正确流程，缺一步都会被清单判为"文件缺失"：

  1. 读反编译源码，打补丁
  2. 用本地 LuaJIT 2.1.2026 编译成字节码
     - 必须 loadstring + string.dump(c, false)：默认就是 LuaJIT 原生格式 1b4c4a02；
       strip=false 保留调试信息（客户端 1,654 个脚本全部带调试信息）
     - 直接 -e 传 chunk 会产出标准 Lua 5.1 格式(1b4c7561)，客户端不认
  3. XXTEA 加密（沿用原 tag 的 b7/b8，保证 key 派生一致）
  4. 按 md5(新明文) 计算**新路径** —— 布局是内容寻址的
  5. 同步改 assets/32/assets.db 与 assets/64/assets.db 的 real/size/hash
  6. 输出替换清单（重建脚本需显式追加新条目）

每个待补丁资源先做 encrypt(decrypt(x))==x 的字节级往返验证。
"""
import hashlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import zipfile

sys.path.insert(0, r'D:\Temp\yqlr\_out_conf')
import attack_conf as A

with open(r'D:\Temp\yqlr\_out_conf\custom_conf.json', encoding='utf-8') as f:
    TBL = json.load(f)['xxtea'].encode('utf-8')
assert len(TBL) == 76

LUAJIT = r'E:\lib\LuaJIT\src\luajit.exe'
APK = r'D:\Temp\yqlr\yqlr_2.2.2_9game.apk'
OUT = r'D:\Temp\yqlr\_out_repack'
TMP = r'C:\Users\ADMINI~1\AppData\Local\Temp\opencode\bc'
os.makedirs(TMP, exist_ok=True)

MOCK_IP = '127.0.0.1'
MOCK_PORT = 8888

# ------------------------------------------------------------------
# 构建 profile
#
#   dev      : 挂全部探针（写 /sdcard/rp.txt、gp.txt），供本地逆向调试。
#              产物 yqlr_v5-dev.apk
#   release  : 剔除纯探针文件 + 关闭所有探针 I/O，供分发。
#              产物 yqlr_v5-offline.apk
#
# 切换（PowerShell）：
#   $env:YQLR_PROFILE='release' ; python build_patched_luac.py
#   $env:YQLR_PROFILE='dev'     ; python build_patched_luac.py
#
# 设计约定：**探针只经由 4 个 helper 落地**
#   _rp_probe -> /sdcard/rp.txt   _gp_probe -> /sdcard/gp.txt
#   _ap_probe -> /sdcard/rp.txt   _bu_probe -> /sdcard/rp.txt
# 所以 release 只需在这 4 个函数入口插入空返回，就能去掉全部文件 I/O，
# 不必逐个 patcher 改（改动面最小、回归风险最低）。
# ------------------------------------------------------------------
PROFILE = os.environ.get('YQLR_PROFILE', 'dev').strip().lower()
assert PROFILE in ('dev', 'release'), 'YQLR_PROFILE 只能是 dev / release'
IS_DEV = PROFILE == 'dev'
PROBE_FNS = (
    '_gp_probe',      # patch_guidewidget        -> gp.txt
    '_rp_probe',      # patch_redpointcontroller -> rp.txt
    '_gs_probe',      # patch_gamestyle          -> rp.txt
    '_ap_probe',      # patch_dmaudio            -> rp.txt（dev-only 文件）
    '_bu_probe',      # patch_heroinfomediator   -> rp.txt（dev-only 文件）
    '_probe_v',       # patch_dmviewmediator     -> probe.txt
    '_assist_probe',  # patch_assistsystem       -> rp.txt
)

# 整个文件都是探针的 patcher：release 直接不编译、不替换
DEV_ONLY_LOGICS = {
    'yq/assets/dmAudio.luac',
    'yq/gameplay/hero/view/HeroInfoMediator.luac',
}

if not IS_DEV:
    print('[profile] release：剔除纯探针文件 %d 个，关闭全部探针 I/O'
          % len(DEV_ONLY_LOGICS))

# 每个待补丁资源用 64 位条目的 tag（模拟器是 arm64）。
# b7/b8 就在文件头里，解密器自己读它们推 key，故两个架构可共用同一份新文件。
JOBS = [
    dict(logic='sdk/SDKHelper.luac',
         src=r'D:\Temp\yqlr\_out_decompile\lua\sdk\SDKHelper.lua',
         tagpath='assets/release/ce/8f/709ae35da868e01f8e56e427bb25.luac'),
    dict(logic='yq/gameplay/activity/model/ActivityList.luac',
         src=r'D:\Temp\yqlr\_out_decompile\lua\yq\gameplay\activity\model\ActivityList.lua',
         tagpath='assets/release/e8/f5/de01a786648ab72d0386fa87555f.luac'),
    dict(logic='yq/gameplay/stage/view/BattleSuccessMediator.luac',
         src=r'D:\Temp\yqlr\_out_decompile\lua\yq\gameplay\stage\view\BattleSuccessMediator.lua',
         tagpath='assets/release/50/6d/cde3d25404075daddf83fa767a56.luac'),
    dict(logic='yq/gameplay/playerLevel/controller/PlayerLevelSystem.luac',
         src=r'D:\Temp\yqlr\_out_decompile\lua\yq\gameplay\playerLevel\controller\PlayerLevelSystem.lua',
         tagpath='assets/release/40/eb/a7efc0f60158afa3f30e87c90145.luac'),
    dict(logic='yq/base/Service.luac',
         src=r'D:\Temp\yqlr\_out_decompile\lua\yq\base\Service.lua',
         tagpath='assets/release/99/44/af743d22c805a87f5f48804044e5.luac'),
    dict(logic='yq/launch/login/LoginSystem.luac',
         src=r'D:\Temp\yqlr\_out_decompile\lua\yq\launch\login\LoginSystem.lua',
         tagpath='assets/release/a7/98/4ae8af1f6569a573e27042239d8f.luac'),
    dict(logic='yq/launch/login/view/LoginMediator.luac',
         src=r'D:\Temp\yqlr\_out_decompile\lua\yq\launch\login\view\LoginMediator.lua',
         tagpath='assets/release/11/03/c903dc5b44f5c66fc9ab9170a7af.luac'),
    dict(logic='yq/gameplay/guide/view/GuideWidget.luac',
         src=r'D:\Temp\yqlr\_out_decompile\lua\yq\gameplay\guide\view\GuideWidget.lua',
         tagpath='assets/release/cd/aa/ea8028549dc1a966279ca04144eb.luac'),
    dict(logic='yq/gameplay/team/view/TeamMediator.luac',
         src=r'D:\Temp\yqlr\_out_decompile\lua\yq\gameplay\team\view\TeamMediator.lua',
         tagpath='assets/release/59/b1/89c7a0685a29a005adcdade4246f.luac'),
    dict(logic='yq/gameplay/redPoint/RedPointController.luac',
         src=r'D:\Temp\yqlr\_out_decompile\lua\yq\gameplay\redPoint\RedPointController.lua',
         tagpath='assets/release/5a/74/0122e0470061381b0599daae090f.luac'),
    dict(logic='yq/gameplay/assist/controller/AssistSystem.luac',
         src=r'D:\Temp\yqlr\_out_decompile\lua\yq\gameplay\assist\controller\AssistSystem.lua',
         tagpath='assets/release/30/01/f90ea37c8dc5dafaefca6b4cabe5.luac'),
    dict(logic='yq/assets/GameStyle.luac',
         src=r'D:\Temp\yqlr\_out_decompile\lua\yq\assets\GameStyle.lua',
         tagpath='assets/release/93/52/fc5cdacd3dcf4d2c2107fea6835c.luac'),
    # [探针] 配音链路：定位 sound/voice_jp/*.acb 存在但无声的断点
    dict(logic='yq/assets/dmAudio.luac',
         src=r'D:\Temp\yqlr\_out_decompile\lua\yq\assets\dmAudio.lua',
         tagpath='assets/release/11/a0/fa23d2579e18f7b5989e9fac6178.luac'),
    # [探针] 跃升(BeyondUp)面板：定位"临界3的立绘未解锁"卡在哪一关
    dict(logic='yq/gameplay/hero/view/HeroInfoMediator.luac',
         src=r'D:\Temp\yqlr\_out_decompile\lua\yq\gameplay\hero\view\HeroInfoMediator.lua',
         tagpath='assets/release/76/7d/4c07cc348d096daed0b976347777.luac'),
    # 注意：yq/gameplay/stage/controller/StageSystem.luac **故意不加入**。
    # 它的反编译源码自身就编译不过：反编译器在 StageSystem:screeningTeamSkill
    # 里留下了 `return` 之后还跟语句的死代码（第 123 行 `local element = {...}`），
    # 而 Lua 5.1 语法要求 return 必须是块内最后一个语句。
    # 已实测：ORIGINAL 与 PATCHED 均 FAIL -> unexpected symbol near 'local'。
    # 所以只能改 BattleSuccessMediator 这边去读 StageSystem 的字段。
]


def compile_luajit(src, chunkname):
    """src 可以是字符串，也可以是候选列表（fix_syntax 返回）。

    候选逐个试编译，第一个成功的即采用。全部失败才报错，
    这样 fix_syntax 的启发式修正是安全的 —— 不存在"改坏了但没人发现"。
    """
    cands = src if isinstance(src, list) else [src]
    sp = os.path.join(TMP, 'src.lua')
    op = os.path.join(TMP, 'out.luac')
    env = dict(os.environ)
    env['PATH'] = r'E:\lib\LuaJIT\src' + os.pathsep + env.get('PATH', '')
    last = ''
    for idx, cand in enumerate(cands):
        with open(sp, 'w', encoding='utf-8', newline='') as f:
            f.write(cand)
        if os.path.exists(op):
            os.remove(op)
        code = (
            'local f=io.open([[{sp}]],"rb") local s=f:read("*a") f:close() '
            'local c=assert(loadstring(s, [[{cn}]])) '
            'local o=assert(io.open([[{op}]],"wb")) o:write(string.dump(c,false)) o:close()'
        ).format(sp=sp.replace('\\', '/'), cn=chunkname, op=op.replace('\\', '/'))
        r = subprocess.run([LUAJIT, '-e', code], capture_output=True, text=True, env=env)
        if r.returncode == 0 and os.path.exists(op):
            if idx > 0:
                print('    候选%d 编译通过（共 %d 个候选）' % (idx + 1, len(cands)))
            return open(op, 'rb').read()
        last = (r.stdout.strip() + '\n' + r.stderr.strip()).strip()
        # 让编译器告诉我们砍到哪：'end' expected -> 回溯截断死代码
        cut = _truncate_from_error(cand, last)
        if cut and cut != cand:
            cands.append(cut)
            continue
    raise RuntimeError('luajit 编译失败（试过 %d 个候选）:\n%s' % (len(cands), last))


# ---------------------------------------------------------------- 补丁定义
# ---------------------------------------------------------------- 语法修复
# 反编译器缺陷：形如 `end, nil, , isLoop)` 会吐一个空实参（占位参数被反编译丢名）。
# 语义上等价于 `nil, isLoop`，对本次改动的代码路径无影响。
# 全量 1,654 个反编译文件里共 42 个含此类问题（BattleUIMediator/ChapterMapPlanetWidget/
# TeamMediator 等），只有 LoginMediator 挡在当前登录路径上。
import re


def fix_syntax(src, name):
    r"""修一类反编译缺陷：**丢失的实参**。

    反编译器遇到它无法表示的实参会留下空位：
        local video = VideoSprite.create(usmPath, nil, , , true)

    **必须补 `nil`，不能删逗号。** 这一点踩过坑：

        VideoSprite.create 的签名（yq/utils/VideoSprite.lua:8）是
            function create(audioPath, callback, player, isAsync, isLoop, noplay)
        `create(usmPath, nil, , , true)` 应该是
            audioPath=usmPath, callback=nil, player=nil, isAsync=nil, isLoop=true
        而删逗号压成 `create(usmPath, nil, true)` 之后，**true 落到了第 3 个
        参数 player 上**，运行时直接报：
            VideoSprite.lua: bad argument #1 to 'createWithPlayer'
            (cri. Player or nil expected, got boolean)
        所以替换串是 `, nil,` 而不是 `, `。

    另外两个必须的改动：

    1) `\s` 会匹配换行。原来的 `,(\s*),` 里 `\s*` 能跨行，于是 `,\n    ,`
       这种跨行结构也会被替换，**把换行吃掉、把两个独立语句粘成一行**。
       改成 `[^\S\n]*`（只吃空格和制表）后行数保持不变。

    2) 单遍修不掉 `nil, , , true`：
         第 1 遍只消掉前两个逗号 -> `nil, nil, , true`
         需要第 2 遍 -> `nil, nil, nil, true`
       所以要迭代到不动点。

    效果（实测）：TeamMediator.lua 迭代 3 遍后由 FAIL 变 OK，行数 3526 -> 3526 不变。

    **不**处理 "return 后残留死代码"：那种情况无法靠缩进可靠判断，
    改由 compile_luajit 读编译器的报错行号自动回退截断，见 _truncate_from_error。
    TeamGroundWidget.lua 正是这类，目前仍编译不过，不能从反编译源码改它。
    """
    pat = re.compile(r',([^\S\n]*),([^\S\n]*)')
    total = len(pat.findall(src))
    rounds = 0
    while rounds < 20:
        rounds += 1
        out = pat.sub(r', nil,', src)
        if out == src:
            break
        src = out
    if total:
        print('    补齐丢失实参 %d 处（迭代 %d 遍）' % (total, rounds))
    return src


def _truncate_from_error(src, err):
    """按编译报错回退截断，返回新候选或 None。

    场景：反编译器在函数中间插了一个 `return X`，却把后面的真实代码也留在
    函数体内没闭合，导致 LuaJIT 报
        file:461: 'end' expected (to close 'function' at line 450) near 'local'

    做法：在报错行往前回溯，找最近的顶层 return（缩进 1 tab），把它之后到
    下一个顶层 `function` 之间的内容整段丢掉 —— 那段是 `return` 之后不可达的
    残留，而后面的函数必须保留。

    **踩过的坑**：不要简单截断到文件末尾。LoginSystem 里 456-516 行是被误判成
    "死代码"的真实逻辑（含 getServerInfo 等），砍掉后字节数从 20018 掉到
    11804，缺了一大块。所以边界必须落在下一个顶层 function。
    """
    m = re.search(r':(\d+):\s*.end. expected', err)
    if not m:
        return None
    errline = int(m.group(1))
    lines = src.split('\n')
    if errline > len(lines):
        return None
    # 往回找最近的顶层 return
    start = None
    for i in range(min(errline, len(lines)) - 1, -1, -1):
        ln = lines[i]
        if ln.strip().startswith('return ') and (len(ln) - len(ln.lstrip('\t'))) == 1:
            start = i
            break
    if start is None:
        return None
    # 往后找下一个顶层 function，作为截断终点（保留它）
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if re.match(r'^function\b', lines[j]):
            end = j
            break
    removed = end - (start + 1)
    if removed <= 0:
        return None
    print('    按报错行 %d 回溯：丢弃 return 后 %d 行残留（第 %d-%d 行），保留后续函数'
          % (errline, removed, start + 2, end))
    cut = '\n'.join(lines[:start + 1]) + '\nend\n\n' + '\n'.join(lines[end:])
    return cut


def patch_sdkhelper(src, _c):
    OLD_INIT = 'return self._sdkInitResult == "initSDKSuccess", self._sdkInitResult ~= nil'
    OLD_EN = ('function SDKHelper:isEnableSdk()\n'
              '\tif GameConfigs and GameConfigs.disabledSDKLogin then\n'
              '\t\treturn false\n'
              '\tend\n'
              '\n'
              '\tif self:getSdkSource() ~= "" then\n'
              '\t\treturn true\n'
              '\tend\n'
              '\n'
              '\treturn false\n'
              'end')
    NEW_EN = ('function SDKHelper:isEnableSdk()\n'
              '\t-- [PATCH] 强制关闭，不依赖 GameConfigs\n'
              '\treturn false\n'
              'end')
    BANNER = ('-- [PATCH] 强制关闭 SDK 登录门（dev/devConfig.lua 实测未加载成功）\n'
              'GameConfigs = GameConfigs or {}\n'
              'GameConfigs.disabledSDKLogin = true\n'
              'GameConfigs.noUpdate = true\n'
              '-- [PATCH] 跳过系统解锁校验：**这一行已于 2026-10-08 移除**\n'
              '-- 之前打开它是错的（注释里的因果写反了）。真实代码：\n'
              '--     Unlock:getIsUnlock (Unlock.lua:103-111)\n'
              '--     if GameConfigs.closeCheckUnlockSystem then return true end\n'
              '--     return self._unlockSystemMap[systemId] and ....unlock, configData\n'
              '-- 打开它 = 对**所有**系统返回 true，于是\n'
              '--     HomeSystem:updatePlayTypeViewFuncsRedPoint (698-711)\n'
              '--     for v in {PostTask,Shop_main,Archive,PrismCore,Battlefield,Maze,EquipmentZone}\n'
              '--         if getIsUnlock(v) then updataRedPoint(v) end  -- 全部都会进\n'
              '-- 任何系统只要假设服务端已下发对应 datas 就崩 -> 进主界面连环弹\n'
              '-- Lua ERROR（PayShop/Achievement/PrismCore/... 共 6 轮）。\n'
              '-- 现在改为在 10001 的 UnlockSystemListData.unlockSystemMap 里精确声明\n'
              '-- 要解锁的系统；没声明的自然为 nil(falsy)，那些分支根本不会进。\n'
              '-- 注意：解锁条目**不能带 unlockCondition** ——\n'
              '-- Unlock:compaSystemId (81-101) 首次同步时 _oldUnlockData 为空，\n'
              '-- 若条目带该字段会索引 nil 报错。\n\n')
    assert OLD_INIT in src
    src = src.replace(OLD_INIT, 'return true, true')
    print('    isSdkInitSuccess -> return true, true')
    assert OLD_EN in src, 'isEnableSdk 函数体未匹配'
    src = src.replace(OLD_EN, NEW_EN)
    print('    isEnableSdk -> return false')
    src = BANNER + src
    print('    顶层注入 GameConfigs 标志')
    return src


def patch_loginsystem(src, _c):
    # _battleVersion 从没在 initialize 里赋过初值，只有 LoadingMediator:67 调
    # initBattleVersion() 才会设。而 battle_version 文件根本不在 APK 里
    # （已确认），initBattleVersion 找不到文件时兜底成 ""。
    # 一旦那条路径没跑到，getBattleVersion() 就是 nil，于是
    #   StageSystem:1248  resultData.version = getBattleVersion()   -- nil
    #   Service:24       cjson.encode(params)                      -- 含 nil 值 -> 返回 nil
    #   Service:45       string.char(..) .. rid .. paramsData      -- __concat 炸
    # 表现为战斗结算后 'attempt to concatenate local paramsData (a nil value)'。
    # 战斗本身完全正常，只有结算崩，所以很容易误判成服务端响应问题。
    OLD = '\tself._language = getCurrentLanguage()\nend'
    NEW = ('\tself._language = getCurrentLanguage()\n'
           '\t-- [PATCH] _battleVersion 兜底：battle_version 文件不在 APK 里，\n'
           '\t-- 且 initialize 从不给它初值，结算时 getBattleVersion() 可能为 nil，\n'
           '\t-- 会让 cjson.encode 返回 nil 从而在请求拼接处崩溃。\n'
           '\tself._battleVersion = ""\nend')
    assert OLD in src, 'LoginSystem:initialize 函数尾未匹配'
    src = src.replace(OLD, NEW)
    print('    _battleVersion 兜底为 ""')
    return src


def patch_service(src, _c):
    """给 Service:newRequest 加探针，定位 cjson.encode 返回 nil 的真正原因。

    崩溃点固定是这里：
        local paramsData = cjson.encode(params)
        paramsData = string.char(version, #rid) .. rid .. paramsData
    报错 'attempt to concatenate local paramsData (a nil value)'。

    **cjson.encode 对含 nil 值的表返回 nil**，所以只要 params 的任意层级里有个
    nil 值字段，整个请求就编码不出来。静态推理很难确定到底是哪个字段
    （battleResult 来自战斗模拟器，内部字段多且都可能为 nil），
    所以直接在崩溃点把 params 逐层打出来。

    同时做兜底：编码失败时用 "{}" 顶上，让请求能发出去，
    服务端（mock）回什么就当什么，不再因为客户端崩溃把流程卡死。
    """
    OLD = ('\tlocal cjson = require("cjson.safe")\n'
           '\tlocal paramsData = cjson.encode(params)\n')
    NEW = ('\tlocal cjson = require("cjson.safe")\n'
           '\tlocal paramsData = cjson.encode(params)\n'
           '\n'
           '\t-- [PATCH] 诊断 + 兜底\n'
           '\tif paramsData == nil then\n'
           '\t\tprint("[PROBE] opcode=" .. tostring(opcode) .. " cjson.encode 返回 nil，params 结构：")\n'
           '\t\tlocal seen = {}\n'
           '\t\tlocal function scan(t, path, depth)\n'
           '\t\t\tif type(t) ~= "table" or depth > 4 then\n'
           '\t\t\t\treturn\n'
           '\t\t\tend\n'
           '\t\t\tif seen[t] then\n'
           '\t\t\t\treturn\n'
           '\t\t\tend\n'
           '\t\t\tseen[t] = true\n'
           '\t\t\tfor k, v in pairs(t) do\n'
           '\t\t\t\tif v == nil then\n'
           '\t\t\t\t\tprint("[PROBE]   NIL  " .. path .. "." .. tostring(k))\n'
           '\t\t\t\telseif type(v) == "table" then\n'
           '\t\t\t\t\tscan(v, path .. "." .. tostring(k), depth + 1)\n'
           '\t\t\t\telse\n'
           '\t\t\t\t\tprint("[PROBE]   ok   " .. path .. "." .. tostring(k) .. " = " .. tostring(v))\n'
           '\t\t\t\tend\n'
           '\t\t\tend\n'
           '\t\tend\n'
           '\t\tscan(params, "params", 0)\n'
           '\t\tparamsData = "{}"\n'
           '\t\tprint("[PROBE] 已用空 JSON 兜底，请求继续发出")\n'
           '\tend\n')
    assert OLD in src, 'Service:newRequest 的 cjson.encode 位置未匹配'
    src = src.replace(OLD, NEW)
    print('    Service:newRequest 加 cjson 探针 + 空 JSON 兜底')
        # ------------------------------------------------------------------
    # [OFFLINE-SERVER] embedded offline server (phase 1, option B)
    #
    # Why Service.lua:
    #   it is yq/base/Service.lua, already in JOBS, so it goes through the
    #   full compile -> round-trip verify -> assets.db sync -> pack pipeline.
    #   Adding a brand-new logic does NOT work: the build reads the original
    #   tagpath out of the base APK for encrypt/decrypt verification, and a
    #   new file has no original tagpath.
    #
    # Phase 1 scope: bind + non-blocking accept + transport frame parse +
    #   CRC32 self test + RPC header parse. It deliberately does NOT answer
    #   the handshake yet (no RSA yet; a fake blob would only make the
    #   client fail to unwrap).
    #   Watch file: /sdcard/osrv.txt
    #
    # dev profile only for now; enable on release once RSA + responses land.
    # ------------------------------------------------------------------
    if IS_DEV and os.environ.get('YQLR_OSRV', '1') == '1':
        _lua_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lua')
        _srv_path = os.path.join(_lua_dir, 'offline_server.lua')
        _srv_src = io.open(_srv_path, encoding='utf-8').read()

        # 内联 opcode 应答表。生成脚本 build_lua_table.py 直接复用 Python mock
        # 的 Server（已跑通登录的那份），把每个 opcode 的响应体在构建期就
        # json.dumps 成字符串 —— Lua 侧一次都不重新编码，避免 cjson 把空数组
        # `[]` 变成 `{}`。
        _tbl_path = os.path.join(_lua_dir, 'opcode_table.lua')
        _ph = 'if not OPCODE_TABLE then'
        if not os.path.exists(_tbl_path):
            raise SystemExit('[osrv] missing %s; run build_lua_table.py first' % _tbl_path)
        _tbl_src = io.open(_tbl_path, encoding='ascii').read()
        if _tbl_src.find('OPCODE_TABLE = {') < 0:
            raise SystemExit('[osrv] %s does not define OPCODE_TABLE' % _tbl_path)
        # 插到 `if not OPCODE_TABLE then` 之前，注入值优先级最高
        _srv_src = _srv_src.replace(_ph, _tbl_src + '\n' + _ph, 1)

        _boot = ('\n'
                 '-- [OFFLINE-SERVER] boot embedded server\n'
                 'if OfflineServer and OfflineServer.install then\n'
                 '    OfflineServer.install()\n'
                 'end\n')
        src = src + '\n' + _srv_src + _boot
        print('    [osrv] embedded server injected (%d lines) + opcode table %.1f KB'
              % (_srv_src.count('\n'), len(_tbl_src) / 1024.0))
    else:
        print('    [osrv] not injected (profile=%s YQLR_OSRV=%s)'
              % (PROFILE, os.environ.get('YQLR_OSRV', '1')))
    return src


def patch_loginmediator(src, _c):
    # connectGameServer():654-655 从 serverData 取地址 -> 改成 mock
    OLD = ('\tlocal ip = self._serverData:getIp()\n'
           '\tlocal port = self._serverData:getPort()')
    NEW = ('\t-- [PATCH] 指向本地 rrcp 捕获/mock 服务\n'
           '\tlocal ip = "%s"\n'
           '\tlocal port = %d' % (MOCK_IP, MOCK_PORT))
    assert OLD in src, 'connectGameServer 取 ip/port 未匹配'
    src = src.replace(OLD, NEW)
    print('    connectGameServer -> %s:%d' % (MOCK_IP, MOCK_PORT))

    # accountStr 为空会走 LOGIN_UI7 提示并 return，先给个默认账号
    OLD2 = '\tself._accountStr = GameConfigs.rid or self._textField:getText()'
    NEW2 = ('\t-- [PATCH] 免账号输入\n'
            '\tself._accountStr = GameConfigs.rid or self._textField:getText()\n'
            '\tif self._accountStr == "" then self._accountStr = "tester" end')
    if OLD2 in src:
        src = src.replace(OLD2, NEW2)
        print('    账号为空时默认 "tester"')
    return src


def patch_playerlevelsystem(src, _c):
    """让 _oldLevel 的比较不成立，而不是去初始化它。

    报错是 `self._oldLevel < self:getPlayerLevel()` 拿 nil 比数字。
    正常游戏里 _oldLevel 由**升级事件**先调 initData() 记下，而我们的 mock
    不产生升级事件，所以它恒为 nil。

    **踩过的坑**：先试过在 initialize 里补 `self._oldLevel = self:getPlayerLevel()`，
    结果报 `PlayerLevelSystem.lua:60: attempt to index field '_developSystem' (a nil value)`。
    因为 :has(...):injectWith(...) 的依赖注入是在 initialize **之后**才完成的，
    initialize 里访问 self._developSystem 拿到的是 nil。

    所以改成在 checkPlayerLevelUp 里做防护 —— 那里 _developSystem 已注入完成，
    且 _oldLevel 为 nil 时直接跳过升级弹窗，语义正确（没有"旧等级"就无从判断升级）。
    """
    OLD = ('\tif self._oldLevel < self:getPlayerLevel() then\n')
    NEW = ('\t-- [PATCH] _oldLevel 由升级事件经 initData() 赋值，mock 不产生升级事件，\n'
           '\t-- 故恒为 nil；直接比较会报 "attempt to compare nil with number"。\n'
           '\t-- 注意不能改在 initialize 里补赋值：injectWith 的依赖注入在 initialize\n'
           '\t-- 之后才完成，那��访问 self._developSystem 也是 nil。\n'
           '\tif self._oldLevel and self._oldLevel < self:getPlayerLevel() then\n')
    cnt = src.count(OLD)
    assert cnt == 1, 'checkPlayerLevelUp 比较处未唯一匹配（命中 %d 次）' % cnt
    src = src.replace(OLD, NEW)
    print('    checkPlayerLevelUp -> 加 _oldLevel 判空防护')
    return src


def patch_activitylist(src, _c):
    """ActivityList:getActivityById 的 assert 改为返回 nil。

    报错链（主场景红点检查，每次进主界面都会跑）：
        MainSceneMediator -> HomeSystem._checkFunc -> PayShopSystem:updatePayShopRedPoint
        -> isShowPayShopSecondRedPoint -> PayShopSystem:getSecondId
        -> ActivitySystem:isOpenSecondId -> ActivityList:getActivityById
        -> assert(activity ~= nil, 'not find activity by Id:Activity_MainLineFund')

    这些 id 来自 PayShop 配置表（getModel():inquirePaySort(pageId, 'SecondSortId')），
    是**数据驱动**的，我们没法预先枚举 —— 试过往 datas.ActivityData 里补 id，
    但那些 id 在 Activity.tsv（351 行）里不存在，反而多出一处
    `DataReader No record: (table='Activity', id='Activity_DailyTask')`。

    所以改成幂等返回 nil：调用方本来就已经在检查返回值
    （ActivitySystem:isOpenSecondId 里 `if ... then`），assert 只是额外保护。
    """
    OLD = ('\tassert(activity ~= nil, "not find activity by Id:" .. tostring(id))\n\n'
           '\treturn activity\nend')
    NEW = ('\t-- [PATCH] 去掉 assert：这些 id 来自 PayShop 配置表（数据驱动），\n'
           '\t-- 服务端不提供活动数据时会频繁命中，直接返回 nil 让调用方自行判断。\n'
           '\t-- 调用方（ActivitySystem:isOpenSecondId 等）本来就有判空。\n'
           '\tif activity == nil then\n'
           '\t\treturn nil\n'
           '\tend\n\n'
           '\treturn activity\nend')
    cnt = src.count(OLD)
    assert cnt == 1, 'getActivityById 的 assert 未唯一匹配（命中 %d 次）' % cnt
    src = src.replace(OLD, NEW)
    print('    getActivityById -> assert 改为返回 nil')

    # syncAloneActivity:32 的 requireRecordById 同样是无保护调用：
    # 第 34 行的 `if config then` 是死代码，因为 requireRecordById 找不到记录
    # 会自己 assert（"[DataReader] No record: (table='Activity', id='xxx')"）。
    # 传入的 id 来自 datas.ActivityData，属于服务端可控数据。
    OLD2 = ('\t\tlocal config = ConfigReader:requireRecordById("Activity", id)\n\n'
            '\t\tif config then\n')
    NEW2 = ('\t\t-- [PATCH] 改用 getRecordById（找不到返回 nil 而不是 assert）。\n'
            '\t\t-- 原代码下面的 `if config then` 是死代码：requireRecordById\n'
            '\t\t-- 找不到记录时自己就 assert 了，config 永远非 nil。\n'
            '\t\tlocal config = ConfigReader:getRecordById("Activity", id)\n\n'
            '\t\tif config then\n')
    cnt2 = src.count(OLD2)
    assert cnt2 == 1, 'syncAloneActivity 的 requireRecordById 未唯一匹配（命中 %d 次）' % cnt2
    src = src.replace(OLD2, NEW2)
    print('    syncAloneActivity -> requireRecordById 改 getRecordById')
    return src


def patch_battlesuccess(src, _c):
    """**已停用**：结算页问题定位完成，探针全部撤掉。

    根因：不是 BattleSuccessMediator 的问题，是 GuideWidget 那两处补丁
    （saveCurGuideStepId 跳过 openGuide() + checkIsGuideWorking 恒 false）
    把引导系统留在**半初始化**状态 —— 步骤照常推进、照常通过 10027 上报、
    checkGuideStatus() 的接管分支照常存在，但引导层从来没真正打开过。
    结算页正好有一个这样的分支
        if self._guideSystem:checkGuideStatus() then ... else ... end
    结果 view 本体 + 全部 12 个直接子节点都挂上 Touch 监听后，
    一次点击都没命中任何节点；还原引导后立刻恢复。

    过程中排除过的假设：
      - 按钮绑定失败        -> 否，touchLayer 找得到、751x350、addClickEventListener 非 nil
      - Click 被 (A)/(B) 拦 -> 否，事件类型收到 2 期望 2、checkRe=true、无 checkfn
      - 触摸被别的子节点吞   -> 否，命中普查证明恢复后正是 child[07]=touchLayer 命中
      - view 没挂上 GRoot   -> 否，view:getRoot() == fgui.GRoot:getInstance()
      - touchLayer 是悬空对象 -> 否，节点普查 isnull=ok=false、尺寸正常
    """
    return src


def patch_dmviewmediator(src, _c):
    """在 mapButtonHandlerClick 的点击回调里打点，区分"事件被吞"还是"被 return 掉"。

    文件探针实测到的矛盾现象：
        08:52:34  initView 走完    08:52:39  close 被调用     <- 点了有效
        09:07:31  initView 走完    （无 close）                <- 点了没反应
        09:40:44  initView 走完    （无 close）                <- 点了没反应

    所以是**间歇性**失效，不是稳定失败。

    mapButtonHandlerClick（yq/base/view/DmViewMediator.lua:93）的回调里
    有两个会吞掉点击的 return：

        169  tempFunc(button, function (sender, eventType)
        170      if eventType and options.eventType ~= eventType and options.eventType ~= 4 then
        171          return              <-- (A) 事件类型不匹配
        172      end
        ...
        199      if checkRe or options.skipCheckResult then
        200          method(...)         <-- (B) checkfn 返回 false 就不调
        205      end

    已核实 BattleSuccessMediator 的 kBtnHandlers 里 touchLayer/guideBtn/dataBtn
    都只有 clickAudio + func，**没有 checkfn**，所以 checkMethod 为 nil、
    checkRe 恒为 true，(B) 不可能命中。只剩下 (A)。

    这里在回调入口、(A) 的 return 上、以及 (B) 的判定上各打一个点，
    用结果反推到底是回调没进来（触摸被上层节点吞）还是 (A) 命中。
    """
    helper = '''-- [PATCH] 探针：print 不走 logcat，改写文件
local function _probe_v(msg)
    pcall(function ()
        local fh = io.open("/sdcard/probe.txt", "a")
        fh:write(os.date("%H:%M:%S") .. " " .. tostring(msg) .. "\\n")
        fh:close()
    end)
end
'''
    anchor = 'function mapButtonHandlerClick('
    assert src.count(anchor) == 1, 'mapButtonHandlerClick 定义未唯一匹配'
    src = src.replace(anchor, helper + '\n' + anchor)

    # 绑定阶段：确认节点到底找没找到。
    # mapButtonHandlerClick 第 103-107 行有个静默失败点：
    #     if DEBUG and DEBUG > 0 then
    #         assert(button ~= nil, ...)
    #     end
    #     if button then          <-- button 为 nil 时整段跳过，不报错
    # DEBUG 关闭时节点找不到也不会有任何错误，而 initView 照样走完，
    # 表现就是"点了完全没反应，也没有任何日志"。
    OLD0 = '''\tif DEBUG and DEBUG > 0 then
\t\tassert(button ~= nil, string.format("Button '%s' not found!", tostring(buttonNameOrObj)))
\tend

\tif button then
'''
    NEW0 = '''\tif button == nil then
\t\t_probe_v(("!! 绑定失败：节点 '%s' 在视图里不存在（DEBUG=%s，assert 被跳过）"):format(
\t\t\ttostring(buttonNameOrObj), tostring(DEBUG)))
\telse
\t\t_probe_v(("绑定 '%s' -> 找到节点  visible=%s  touchEnabled=%s  swallowTouches=%s  size=%sx%s"):format(
\t\t\ttostring(buttonNameOrObj),
\t\t\ttostring(button.isVisible and button:isVisible() or "n/a"),
\t\t\ttostring(button.isTouchEnabled and button:isTouchEnabled() or "n/a"),
\t\t\ttostring(button.isSwallowTouches and button:isSwallowTouches() or "n/a"),
\t\t\ttostring(button.getContentSize and button:getContentSize().width or "?"),
\t\t\ttostring(button.getContentSize and button:getContentSize().height or "?")))
\tend

\tif DEBUG and DEBUG > 0 then
\t\tassert(button ~= nil, string.format("Button '%s' not found!", tostring(buttonNameOrObj)))
\tend

\tif button then
'''
    cnt0 = src.count(OLD0)
    assert cnt0 == 1, '绑定前的 DEBUG/if button 块未唯一匹配（命中 %d 次）' % cnt0
    src = src.replace(OLD0, NEW0)

    # 谁在反复调 mapButtonHandlersClick？
    # 实测 initView 只跑一次，但 kBtnHandlers 的 4 个按钮在 17 秒里被绑了 8 轮，
    # 说明有别的地方在反复调用。这里抓调用栈定位。
    OLDT = '''\tif DEBUG and DEBUG > 0 then
\t\tassert(button ~= nil, string.format("Button '%s' not found!", tostring(buttonNameOrObj)))
\tend

\tif button then
'''
    NEWT = '''\tif tostring(buttonNameOrObj) == "touchLayer" then
\t\tlocal ok, tb = pcall(function ()
\t\t\treturn debug.traceback("", 2)
\t\tend)
\t\t_probe_v("touchLayer 绑定调用栈:\\n" .. (ok and tostring(tb) or "<traceback 失败>"))
\tend

\tif DEBUG and DEBUG > 0 then
\t\tassert(button ~= nil, string.format("Button '%s' not found!", tostring(buttonNameOrObj)))
\tend

\tif button then
'''
    cntT = src.count(OLDT)
    assert cntT == 1, '插入 traceback 的锚点未唯一匹配（命中 %d 次）' % cntT
    src = src.replace(OLDT, NEWT)

    # tempFunc 是否可用：Layout 之类的节点没有 addClickEventListener
    OLDA = '''\t\t\tlocal tempFunc = options.eventType ~= ccui.TouchEventType.ended and button.addTouchEventListener or button.addClickEventListener
'''
    NEWA = '''\t\t\tlocal tempFunc = options.eventType ~= ccui.TouchEventType.ended and button.addTouchEventListener or button.addClickEventListener

\t\t\t_probe_v(("   '%s' 绑定用 addClickEventListener? %s  (tempFunc=%s)"):format(
\t\t\t\ttostring(buttonNameOrObj),
\t\t\t\ttostring(options.eventType == ccui.TouchEventType.ended),
\t\t\t\ttostring(tempFunc ~= nil)))

\t\t\tif tempFunc == nil then
\t\t\t\t_probe_v(("   !! '%s' 既没有 addClickEventListener 也没有 addTouchEventListener，无法绑定"):format(
\t\t\t\t\ttostring(buttonNameOrObj)))
\t\t\tend
'''
    cntA = src.count(OLDA)
    assert cntA == 1, 'tempFunc 赋值行未唯一匹配（命中 %d 次）' % cntA
    src = src.replace(OLDA, NEWA)

    # 入口：确认回调到底有没有被触发
    OLD = '''\t\t\ttempFunc(button, function (sender, eventType)
\t\t\t\tif eventType and options.eventType ~= eventType and options.eventType ~= 4 then
\t\t\t\t\treturn
\t\t\t\tend
'''
    NEW = '''\t\t\ttempFunc(button, function (sender, eventType)
\t\t\t\t_probe_v((">> 回调触发 button=%s 收到 eventType=%s  期望 eventType=%s  method=%s"):format(
\t\t\t\t\ttostring(buttonNameOrObj), tostring(eventType),
\t\t\t\t\ttostring(options.eventType), tostring(method)))
\t\t\t\tif eventType and options.eventType ~= eventType and options.eventType ~= 4 then
\t\t\t\t\t_probe_v(("   !! 被 (A) return 掉：收到 %s，期望 %s"):format(
\t\t\t\t\t\ttostring(eventType), tostring(options.eventType)))
\t\t\t\t\treturn
\t\t\t\tend
'''
    cnt = src.count(OLD)
    assert cnt == 1, '点击回调入口未唯一匹配（命中 %d 次）' % cnt
    src = src.replace(OLD, NEW)

    # (B) checkfn 判定
    OLD2 = '''\t\t\t\tif checkRe or options.skipCheckResult then
\t\t\t\t\tif not isInstance then
\t\t\t\t\t\tmethod(sender, eventType)
\t\t\t\t\telse
\t\t\t\t\t\tmethod(mediator, sender, eventType)
\t\t\t\t\tend
\t\t\t\tend
'''
    NEW2 = '''\t\t\t\t_probe_v(("   checkRe=%s  skipCheckResult=%s  hasCheckMethod=%s"):format(
\t\t\t\t\ttostring(checkRe), tostring(options.skipCheckResult), tostring(checkMethod ~= nil)))
\t\t\t\tif checkRe or options.skipCheckResult then
\t\t\t\t\t_probe_v("   即将调用 method")
\t\t\t\t\tif not isInstance then
\t\t\t\t\t\tmethod(sender, eventType)
\t\t\t\t\telse
\t\t\t\t\t\tmethod(mediator, sender, eventType)
\t\t\t\t\tend
\t\t\t\telse
\t\t\t\t\t_probe_v("   !! 被 (B) 拦截：checkRe 为 false 且没有 skipCheckResult")
\t\t\t\tend
'''
    cnt2 = src.count(OLD2)
    assert cnt2 == 1, '(B) 判定块未唯一匹配（命中 %d 次）' % cnt2
    src = src.replace(OLD2, NEW2)

    print('    mapButtonHandlerClick -> 加回调入口 / (A) / (B) 探针')
    return src


def patch_stagesystem(src, _c):
    """已废弃：StageSystem.lua 的反编译源码自身编译不过，不要用。"""
    raise RuntimeError('StageSystem 反编译源码编译不过，别从这里改')


def patch_teammediator(src, _c):
    """修引导强制上场角色的硬编码站位。

    背景（用户实测）：
      第一关：因为 (3,3) 被占位阻挡，上不了角色
      第二关：因为某角色没有默认上场，少人

    根因是 TeamMediator:setCurTeamHero 里引导激活时会往编队里硬塞角色，
    而这些坐标是写死的、与实际配置对不上（已逐关核对 GridBattle.tsv）：

      C00S01  LaJ     (3,3)  -> 不在玩家区（actionNum 跳过 13，友军 C00S01_ShiZ 占用）
      C00S02  ChuanSJ (4,3)  -> 不在玩家区（敌方 C00S02_DEF 占用）
      C00S03  MoG     (3,2)  -> 不在玩家区（actionNum 跳过 12）
      C00S04  MoG(1,3) / ChuanSJ(3,3) / LaJ(2,3) -> 三格都在玩家区且未被占，**不动**

    对应源码（setCurTeamHero，TeamMediator.lua:2622-2669）：
      if self._guideSystem:checkGuideStatus() then
        if self._id == "C00S01" and ... not self:checkIsHaveHeroId(team, "LaJ") then
          team[#team + 1] = { id = "LaJ", uid = "LaJ", sort = 0,
                              pos = cc.p(3, 3), type = HeroRecruitType.OWNED }
        elseif self._id == "C00S02" and ... not self:checkIsHaveHeroId(team, "ChuanSJ") then
          team[#team + 1] = { id = "ChuanSJ", uid = "ChuanSJ", sort = 0,
                              pos = cc.p(4, 3), type = HeroRecruitType.OWNED }
        elseif self._id == "C00S03" and ... not self:checkIsHaveHeroId(team, "MoG") then
          team[#team + 1] = { id = "MoG", uid = "MoG", sort = 0,
                              pos = cc.p(3, 2), type = HeroRecruitType.OWNED }
        elseif self._id == "C00S04" then ... end
      end

    非法坐标会导致 controllerHero 里 isMySpace() 为 false，pos 变 nil，
    角色放不上场 —— 表现就是"上不了角色 / 少人"。

    改成 (2,3)：该格在这三关都在 PlayerPositonArea 内、不在 EnemyPositonArea 内，
    且不是用户明确要求避开的 (3,3)。替换后会在构建时对着 GridBattle.tsv 复核。
    """
    # 构建时复核：替换后的格子必须在该关玩家区内、且不被敌方/友军占用
    grid = {}
    tsv = os.path.join(r'D:\Temp\yqlr\_out_text\tables', 'GridBattle.tsv')
    try:
        with open(tsv, encoding='utf-8') as f:
            import csv as _csv
            for row in _csv.DictReader(f, delimiter='\t'):
                grid[row['rowId']] = row
    except Exception as ex:
        print('    !! 读 GridBattle.tsv 失败 %r，跳过复核' % ex)

    # (关卡, 角色, 原 pos 文本, 新 pos 文本)
    # C00S02 不在这里处理：它的角色要从 戈琳 换成 塔可，下面一次性改完。
    FIX = [
        ('C00S01', 'LaJ', 'cc.p(3, 3)', 'cc.p(2, 3)'),
        ('C00S03', 'MoG', 'cc.p(3, 2)', 'cc.p(2, 3)'),
    ]
    NEW = '(2, 3)'

    # ------------------------------------------------------------------
    # 按关卡分开写默认编队。
    #
    # 需求（用户实测）：
    #   第一关：塔可(LaJ) 不要默认上场
    #   第二关：要有默认上场的人（否则又变成 0 人）
    #
    # 为什么放在这里而不是服务端：
    #   CampaignData.team 是**一张全局表**。查过 getTeamByType，
    #   它只被 EquipZoneSystem 使用（EquipZoneSystem.lua:226），
    #   主线编队没有按关卡分表的机制 —— StageSystem:getTeam() 取的是
    #   CampaignModel._team 这一张表，所有关卡共用。
    #   所以"按关卡分开"只能落在引导这段按 self._id 分支的代码上。
    #
    # 改法：
    #   C00S01 的分支条件改成永远不成立（if false then ...），
    #   这样第一关不再由引导自动放塔可；同时 elseif 链会继续往下走，
    #   不会影响其它关卡。
    #   C00S02 的分支把角色从 戈琳(ChuanSJ) 换成 塔可(LaJ)。
    #
    # 角色中文名来自 Text.tsv 的 Char_Name_*（明文）：
    #   LaJ=塔可(Tako)  MoG=姬露…(J-001)  ChuanSJ=戈琳(Golin)
    #   ShiZ=利昂列夫(Leonlev)  HuL=佩璐(Peru)
    # ------------------------------------------------------------------
    C1_OLD = ('\t\tif self._id == "C00S01" and self._guideSystem:isFinshGuide("Guide1_Step6")'
              ' and not self:checkIsHaveHeroId(team, "LaJ") then\n')
    C1_NEW = ('\t\t-- [PATCH] 第一关不预置塔可：引导原本在 C00S01 且编队里没有 LaJ 时，\n'
              '\t\t-- 自动塞一个塔可到 (3,3)（原坐标，且该格被友军 ShiZ 占着）。\n'
              '\t\t-- 现在条件恒不成立 -> 第一关完全空场，由玩家/引导自己安排。\n'
              '\t\tif false and self._id == "C00S01" then\n')
    c1 = src.count(C1_OLD)
    assert c1 == 1, 'C00S01 分支条件未唯一匹配（命中 %d 次）' % c1
    src = src.replace(C1_OLD, C1_NEW)
    print('    C00S01 -> 不再自动预置塔可')

    C2_OLD = ('\t\telseif self._id == "C00S02" and self._guideSystem:isFinshGuide("Guide1_Step35")'
              ' and not self:checkIsHaveHeroId(team, "ChuanSJ") then\n')
    C2_NEW = ('\t\t-- [PATCH] 第二关默认上场塔可(LaJ)，而不是戈琳(ChuanSJ)：\n'
              '\t\t-- 戈琳由 Guide1_Step29/Step36 引导玩家自己拖进编队，预置会顶掉那一步。\n'
              '\t\telseif self._id == "C00S02" and self._guideSystem:isFinshGuide("Guide1_Step35")'
              ' and not self:checkIsHaveHeroId(team, "LaJ") then\n')
    c2 = src.count(C2_OLD)
    assert c2 == 1, 'C00S02 分支条件未唯一匹配（命中 %d 次）' % c2
    src = src.replace(C2_OLD, C2_NEW)

    S2_OLD = ('\t\t\tteam[#team + 1] = {\n'
              '\t\t\t\tid = "ChuanSJ",\n'
              '\t\t\t\tuid = "ChuanSJ",\n'
              '\t\t\t\tsort = 0,\n'
              '\t\t\t\tpos = cc.p(4, 3),\n'
              '\t\t\t\ttype = HeroRecruitType.OWNED\n'
              '\t\t\t}\n')
    S2_NEW = ('\t\t\tteam[#team + 1] = {\n'
              '\t\t\t\tid = "LaJ",\n'
              '\t\t\t\tuid = "LaJ",\n'
              '\t\t\t\tsort = 0,\n'
              '\t\t\t\tpos = cc.p(2, 3),\n'
              '\t\t\t\ttype = HeroRecruitType.OWNED\n'
              '\t\t\t}\n')
    s2 = src.count(S2_OLD)
    assert s2 == 1, 'C00S02 的角色块未唯一匹配（命中 %d 次）' % s2
    src = src.replace(S2_OLD, S2_NEW)
    print('    C00S02 -> 默认上场改为塔可(LaJ)@(2, 3)')

    # ------------------------------------------------------------------
    # 关键补充：默认编队不能挂在引导分支上。
    #
    # 原来靠这个条件触发：
    #     elseif self._id == "C00S02" and self._guideSystem:isFinshGuide("Guide1_Step35")
    #         and not self:checkIsHaveHeroId(team, "LaJ") then
    # 但 isFinshGuide（GuideModule.lua:114-130）比较的是"已完成的最后一步"的 Order：
    #     local lastId = self:getFinishLastGuideId(groupId)
    #     return config.Order <= lastConfig.Order
    # 而 Guide1_Step35 本身就是"点开始战斗"（Order=32, ActionType=CLICK _battleBtn）。
    # 也就是说**必须先点过一次开始战斗，这个分支才可能成立** —— 循环依赖，
    # 实测第二关确实没有塔可（12:49:02 引导刚上报到 Guide1_Step35）。
    #
    # 所以这里在引导块**外面**再加一份按关卡的默认编队，不看引导状态：
    #   C00S01 -> 不放任何角色（上面的 if false 已经保证）
    #   C00S02 -> 塔可(LaJ) @ (2,3)
    # ------------------------------------------------------------------
    ANCHOR = '\tend\n\n\tdump(team, "+++++++++++TeamMediator:setCurTeamHero(): team:  ")\n'
    ADD = ('\tend\n\n'
           '\t-- [PATCH] 按关卡的默认编队，**不依赖引导状态**（原因见 build 脚本注释）\n'
           '\tif self._id == "C00S02" and not self:checkIsHaveHeroId(team, "LaJ") then\n'
           '\t\tteam[#team + 1] = {\n'
           '\t\t\tid = "LaJ",\n'
           '\t\t\tuid = "LaJ",\n'
           '\t\t\tsort = 0,\n'
           '\t\t\tpos = cc.p(2, 3),\n'
           '\t\t\ttype = HeroRecruitType.OWNED\n'
           '\t\t}\n'
           '\tend\n\n'
           '\tdump(team, "+++++++++++TeamMediator:setCurTeamHero(): team:  ")\n')
    ac = src.count(ANCHOR)
    assert ac == 1, 'setCurTeamHero 里的 dump 锚点未唯一匹配（命中 %d 次）' % ac
    src = src.replace(ANCHOR, ADD)
    print('    C00S02 -> 在引导块外追加不依赖引导状态的默认编队')

    # 复核 C00S02 新站位
    _r = grid.get('Campaign_C00S02')
    _pa = {(a['x'], a['y']) for a in json.loads(_r['PlayerPositonArea'] or '[]')}
    _ea = {(s['x'], s['y']) for s in json.loads(_r['EnemyPositonArea'] or '[]')}
    assert (2, 3) in _pa, 'C00S02 新站位 (2,3) 不在玩家区内！'
    assert (2, 3) not in _ea, 'C00S02 新站位 (2,3) 被敌方/友军占用！'

    for cid, hero, old, new in FIX:
        blk = ('\t\t\tteam[#team + 1] = {\n'
               '\t\t\t\tid = "%s",\n'
               '\t\t\t\tuid = "%s",\n'
               '\t\t\t\tsort = 0,\n'
               '\t\t\t\tpos = %s,\n'
               '\t\t\t\ttype = HeroRecruitType.OWNED\n'
               '\t\t\t}' % (hero, hero, old))
        rep = blk.replace(old, new)
        cnt = src.count(blk)
        assert cnt == 1, '%s 的 %s 硬编码块未唯一匹配（命中 %d 次）' % (cid, hero, cnt)
        src = src.replace(blk, rep)

        row = grid.get('Campaign_%s' % cid)
        assert row, '找不到 Campaign_%s 的 GridBattle 配置' % cid
        pa = {(a['x'], a['y']) for a in json.loads(row['PlayerPositonArea'] or '[]')}
        ea = {(s['x'], s['y']) for s in json.loads(row['EnemyPositonArea'] or '[]')}
        x, y = [int(v) for v in NEW.strip('()').split(',')]
        assert (x, y) in pa, '%s 新站位 %s 不在玩家区内！可用: %s' % (cid, NEW, sorted(pa))
        assert (x, y) not in ea, '%s 新站位 %s 被敌方/友军占用！' % (cid, NEW)
        assert (x, y) != (3, 3), '%s 新站位不能是 (3,3)' % cid
        print('    %s %s: %s -> %s  (已核对玩家区 %d 格、无占用)' % (
            cid, hero, old, NEW, len(pa)))

    return src


def patch_guidewidget(src, _c):
    """第二关引导循环（Step36 永不执行）定点修复 + 探针。

    现象（服务端日志已确认，本会话回退 3 次）：
        Step35(点战斗按钮) ->【14002】-> Step35_1 ->【14003】-> Step16 -> ...
    `Guide1_Step36`（Order=35，CLICK `_guide_ChuanSJ`）**一次都没执行过**。
    战斗从 9 秒拉到 39 秒仍然循环，**时长假设已排除**。
    判据：`Step36.Param7=true`，若它打开过，`callBack`(481-487) 会 pauseBattle()，
    14003 不会到来 —— 所以能确定它从未显示。

    静态逐个闸门核算，**全部"应该通过"**：
      - `_guideUIOpenStatus=true`    : saveCurGuideStepId(266) -> openGuide()
      - `checkGuideStatus()`=true    : GuideSystem:95-101
      - `isFinshGuide("Guide1_Step36")`=false : `_finishLastGuideId` 为空
        （本会话服务端未下发过 guideData，登录发生在进度累积之前）
      - `_curGuideStepId`=`Guide1_Step36`
      - `Step36.Param1=battlePlayer` 与顶层视图匹配
      - 戈琳在 C00S02 的 playerData 里（cid=ChuanSJ）

    真正的触发链在 BattleUIMediator:changeCardState(610-636)：
    某张战斗卡片 state=="show" 时，`_cid=="ChuanSJ"` 且
    `not isFinshGuide("Guide1_Step36")` -> dispatch EVT_CHECKGUIDE {index="guide601"}
    -> MainSceneMediator:185（全项目唯一监听点）-> GuideWidget:showGuide(205)
    -> checkCurGuideStep -> callBack -> pauseBattle 等点击。

    **问题出在时序**：这个 `"show"` 只在战斗开始那一刻来一次，
    而那时 `_curGuideStepId` 还是 `Step35_1`。AUTO 步跑完后
    `saveGuideStep`(426) 才把 id 推进到 `Step36`，而
    `isPlayingNextStep`(655) 读到的已经是 Step36，
    走 `GuideLink=="1"` 分支(668-674)：hideGuideUIView + onResumeBattle，
    **这条分支不 dispatch EVT_CHECKGUIDE** —— 于是再没有任何人触发显示。
    战斗打完没人再查引导，视图变成 battleSuccessView（Step16/17 的 Param1），
    整段"进第二关"的流程就重播一遍。

    对照：Step35_1 的 GuideLink 是 ""，走 664-667 分支**会** dispatch，
    所以它能正常显示并自动完成。

    修改：GuideLink=="1" 分支补一次 dispatch。
    `_saving=false` 是因为 callbackfinsh(433) 本来就在 saveFinish 之后才置 false，
    这里提前置 false 是为了避免新触发的 callBack 处在 saving 态。
    """
    helper = '''-- [PATCH] 引导探针：print 不走 logcat，必须写文件
local function _gp_probe(msg)
    pcall(function ()
        local fh = io.open("/sdcard/gp.txt", "a")
        fh:write(os.date("%H:%M:%S") .. " " .. tostring(msg) .. "\\n")
        fh:close()
    end)
end
local function _gp_nodename(n)
	if not n then
		return "NIL"
	end

	local ok, v = pcall(function ()
		return n:getName()
	end)

	return ok and tostring(v) or ("NO_NAME(" .. type(n) .. ")")
end
'''
    anchor = 'function GuideWidget:showGuide(event)'
    assert src.count(anchor) == 1, 'showGuide 锚点异常'
    src = src.replace(anchor, helper + '\n' + anchor, 1)

    # ---- 探针 1：showGuide，看 EVT_CHECKGUIDE 到底有没有来、来了能不能显示 ----
    old = ('\tlocal eventData = event:getData() or {}\n'
           '\tlocal curGuideConfig = self:checkCurGuideStep(eventData.guideId)\n')
    new = ('\tlocal eventData = event:getData() or {}\n'
           '\tlocal curGuideConfig = self:checkCurGuideStep(eventData.guideId)\n'
           '\t_gp_probe("showGuide idx=" .. tostring(eventData.index) ..'
           ' " gid=" .. tostring(eventData.guideId) ..'
           ' " cur=" .. tostring(self._curGuideStepId) ..'
           ' " open=" .. tostring(self._guideUIOpenStatus) ..'
           ' " view=" .. tostring(self.curTopViewName) ..'
           ' " -> " .. (curGuideConfig and ("DISPLAY " .. tostring(curGuideConfig.Id)) or "SKIP"))\n')
    assert src.count(old) == 1, 'showGuide 探针锚点异常'
    src = src.replace(old, new, 1)

    # ---- 探针 2：checkCurGuideStep，视图不匹配时静默 return，这里补记录 ----
    old = ('\tlocal config = GameStyle:getGuideById(self._curGuideStepId)\n'
           '\tlocal isTrue = self:checkCurGuideIdAndCurViewName(config)\n'
           '\n'
           '\tif not isTrue then\n'
           '\t\treturn\n'
           '\tend\n')
    new = ('\tlocal config = GameStyle:getGuideById(self._curGuideStepId)\n'
           '\tlocal isTrue = self:checkCurGuideIdAndCurViewName(config)\n'
           '\n'
           '\tif not isTrue then\n'
           '\t\t_gp_probe("  MISMATCH cur=" .. tostring(self._curGuideStepId) ..'
           ' " want=" .. tostring(config and config.Param1) ..'
           ' " got=" .. tostring(self.curTopViewName))\n'
           '\t\treturn\n'
           '\tend\n')
    assert src.count(old) == 1, 'checkCurGuideStep 探针锚点异常'
    src = src.replace(old, new, 1)

    # ---- 行为修改 + 探针 3：isPlayingNextStep 的 GuideLink=="1" 分支 ----
    old = ('\telseif cur.GuideLink == "1" then\n'
           '\t\tself:hideGuideUIView()\n'
           '\n'
           '\t\tif self.curTopViewName == "battlePlayer" then\n'
           '\t\t\tself:onResumeBattle()\n'
           '\t\tend\n'
           '\tend\n')
    new = ('\telseif cur.GuideLink == "1" then\n'
           '\t\tself:hideGuideUIView()\n'
           '\n'
           '\t\tif self.curTopViewName == "battlePlayer" then\n'
           '\t\t\tself:onResumeBattle()\n'
           '\t\tend\n'
           '\n'
           '\t\t-- [PATCH] 原版这条分支不 dispatch，导致战斗内的下一步\n'
           '\t\t-- （Step36：点戈琳）永远没人去显示。补一次检查。\n'
           '\t\t_gp_probe("isPlayingNextStep Link1 cur=" .. tostring(self._curGuideStepId) ..'
           ' " link=" .. tostring(cur.GuideLink))\n'
           '\t\tself._saving = false\n'
           '\t\tDmGame:getInstance():dispatch(Event:new(EVT_CHECKGUIDE, {\n'
           '\t\t\tindex = "patchGuideLink1"\n'
           '\t\t}))\n'
           '\tend\n')
    assert src.count(old) == 1, 'isPlayingNextStep 锚点异常'
    src = src.replace(old, new, 1)

    # ---- 探针 4：callBack 入口，确认真的进来了、ActionType 与目标节点名 ----
    old = ('\tself:setVisible(true)\n'
           '\tself:setBgGroundAlpha(tonumber(curGuideData.Alpha))\n')
    new = ('\t_gp_probe("callBack id=" .. tostring(curGuideData.Id) ..'
           ' " act=" .. tostring(curGuideData.ActionType) ..'
           ' " view=" .. tostring(self.curTopViewName) ..'
           ' " P2=" .. tostring(curGuideData.Param2) ..'
           ' " P7=" .. tostring(curGuideData.Param7))\n'
           '\tself:setVisible(true)\n'
           '\tself:setBgGroundAlpha(tonumber(curGuideData.Alpha))\n')
    assert src.count(old) == 1, 'callBack 锚点异常'
    src = src.replace(old, new, 1)

    # ---- 探针 5：getBtnNodeByName，确认目标节点解析结果 ----
    old = ('\treturn node1, node2, node3\n'
           'end\n'
           '\n'
           'function GuideWidget:showBtn(curGuideData)\n')
    new = ('\t_gp_probe("btnNode P2=" .. tostring(curGuideData.Param2) ..'
           ' " -> " .. tostring(node1 and _gp_nodename(node1)) ..'
           ' " P3=" .. tostring(curGuideData.Param3) ..'
           ' " -> " .. tostring(node2 and _gp_nodename(node2)))\n'
           '\treturn node1, node2, node3\n'
           'end\n'
           '\n'
           'function GuideWidget:showBtn(curGuideData)\n')
    assert src.count(old) == 1, 'getBtnNodeByName 锚点异常'
    src = src.replace(old, new, 1)

    # ---- 探针 6：windowFit，确认节点尺寸/坐标（取不到就是被挪到 -300 的那种）----
    old = ('\tlocal size, scale = nil\n'
           '\tsize = node:getContentSize()\n'
           '\tscale = node._scale1 or 1\n')
    new = ('\tlocal size, scale = nil\n'
           '\tsize = node:getContentSize()\n'
           '\tscale = node._scale1 or 1\n'
           '\t_gp_probe("  windowFit HIT name=" .. tostring(_gp_nodename(node)) ..'
           ' " size=" .. tostring(size.width) .. "x" .. tostring(size.height))\n')
    assert src.count(old) == 1, 'windowFit 锚点异常'
    src = src.replace(old, new, 1)

    old = ('\tif not node then\n'
           '\t\tmaskNode:setPivot(0.5, 0.5, true)\n'
           '\t\tmaskNode:setContentSize(cc.size(0, 0))\n')
    new = ('\tif not node then\n'
           '\t\t_gp_probe("  windowFit MISS -> 引导被挪到屏幕外")\n'
           '\t\tmaskNode:setPivot(0.5, 0.5, true)\n'
           '\t\tmaskNode:setContentSize(cc.size(0, 0))\n')
    assert src.count(old) == 1, 'windowFit MISS 锚点异常'
    src = src.replace(old, new, 1)

    print('    [改行为] isPlayingNextStep: GuideLink=="1" 分支补 dispatch')
    print('    [探针] /sdcard/gp.txt : showGuide / MISMATCH / isPlayingNextStep / callBack / btnNode / windowFit')
    return src


def patch_redpointcontroller(src, _c):
    """红点总入口加 pcall 兜底 —— 一次掐掉整类"缺服务端数据就弹框"的错误。

    背景：进主界面时
        HomeMediator:initVariable(799) -> initBottomListRed(827)
          -> refreshRedPointCtrl(854) -> RedPointController:new/initialize/refresh
          -> HomeSystem:L_checkFunc -> 逐个系统算红点
    只要某个系统假设"服务端已下发对应 datas"就会崩。已修过的实例：
        PayShopModel:282 / PayShopSystem:531 / PayShopSystem:715
        SuccessSystem:80 / PrismCoreModel:245 / GuildModel:string.split(nil)
    剩下的 ApexRank(taskModel)、BattlePass(getOpenBattlePass)、
    getFirstGift 等仍依赖我们没有的数据，一个一个补 datas 是打地鼠。

    为什么不填 datas 而是加兜底：红点是**纯提示**，缺数据时正确行为是
    "不显示红点"，而不是弹一个模态错误框卡住玩家。pcall 正好表达这个语义。

    位置：refresh(35-68) 里唯一调用聚合函数的地方
        local show, num = self._checkFunc()
    改成 pcall，失败就记文件并按"无红点"处理（show=false, num=0），
    这样后面的 setVisible/setText 分支仍能正常跑，不会留下脏状态。
    """
    helper = '''-- [PATCH] 红点探针：print 不走 logcat，必须写文件
local function _rp_probe(msg)
    pcall(function ()
        local fh = io.open("/sdcard/rp.txt", "a")
        fh:write(os.date("%H:%M:%S") .. " " .. tostring(msg) .. "\\n")
        fh:close()
    end)
end
'''
    anchor = 'function RedPointController:refresh()'
    assert src.count(anchor) == 1, 'refresh 锚点异常'
    src = src.replace(anchor, helper + '\n' + anchor, 1)

    old = '\tlocal show, num = self._checkFunc()\n'
    new = ('\t-- [PATCH] 聚合红点检查可能因为缺少服务端数据而报错。\n'
           '\t-- 红点只是提示，缺数据时应当"不显示"，而不是弹模态错误框卡住玩家。\n'
           '\tlocal ok, show, num = pcall(self._checkFunc)\n'
           '\n'
           '\tif not ok then\n'
           '\t\t_rp_probe("checkFunc 抛错，已跳过本轮红点: " .. tostring(show))\n'
           '\t\tshow, num = false, 0\n'
           '\tend\n')
    assert src.count(old) == 1, 'checkFunc 调用锚点异常'
    src = src.replace(old, new, 1)

    print('    [兜底] RedPointController:refresh 的 _checkFunc 加 pcall')
    print('    [探针] /sdcard/rp.txt 记录被跳过的红点计算')
    return src


def patch_assistsystem(src, _c):
    """给 16 个 assist_* 统一加 pcall 兜底 —— home 左侧玩法按钮的"状态"数据源。

    这是 `patch_redpointcontroller` 的姊妹补丁，覆盖**另一条**入口。
    RedPointController 只管红点控制器，而 home 左侧那排玩法按钮各自有
    自己的 refreshUI，没有聚合点：
        HomeLeftMazeWidget:refreshUI(50-56)
            local redPoint = self._homeSystem:updateMazeRedPoint()
            local param    = self._assistSystem:assist_maze()
            self._tips:setText(param.desc)
    10 个 HomeLeft*Widget 都直接继承 BaseWidget（无中间基类），逐个改要动 10 个文件；
    而 `assist_*` 全在 AssistSystem 这一个文件里，且两条路（updateMazeRedPoint 内部
    也是调 assist_maze）都经过它，所以在文件末尾统一包一层最省。

    已实测会走到这里并抛错的实例：
        MazeSystem:updateMazeRedPoint(3148) -> assist_maze(267)
          -> MazeSystem:getMazeHomeStatus(3080) -> getMazeMapItems(408)
          -> getCurlTypeMazeIds(215) -> getModel():getSceneMap()
        （没有 MazeListData -> _sceneMap 为空/nil）

    兜底后返回 `{status="", desc="", redpoint=false}`，widget 的
    `setText(param.desc)` 与 `setRedPointStatus(redPoint)` 都能正常跑。
    抛错的名字记到 /sdcard/rp.txt，能看出还有哪些系统缺数据。
    """
    tail = '''
-- [PATCH] assist_* 统一 pcall 兜底（缺服务端数据时不弹错误框，按"无状态"处理）
--
-- 为什么要"运行时探测存放位置"：
--   AssistSystem 由 objectlua 的 subclass 创建，是**实例**不是普通表
--   （objectlua/Class.lua:97-114  `local class = metaclass:new()`），
--   字段/方法不走普通 rawset，所以加载时 `AssistSystem["assist_maze"]` 读回来是 nil。
--   所以不能想当然地挂 AssistSystem，要挨个试，看哪个表真的能读到方法。
local _assist_probe = function (_tag, _msg)
    pcall(function ()
        local _fh = io.open("/sdcard/rp.txt", "a")
        _fh:write(os.date("%H:%M:%S") .. " " .. tostring(_tag) .. " " .. tostring(_msg) .. "\\n")
        _fh:close()
    end)
end

_assist_probe("AssistSystem 已加载(打了补丁), type=", type(AssistSystem))
_assist_probe("getmetatable 的 type=", type(getmetatable(AssistSystem)))

local _names = {
    "assist_onlineTime", "assist_equipJobAndTicketCount", "assist_rewardTask",
    "assist_homeland", "assist_rogue", "assist_schedule", "assist_explore",
    "assist_maze", "assist_arena", "assist_camp", "assist_stairs",
    "assist_status", "assist_task", "assist_mail", "assist_chat", "assist_pay"
}

local function _count_hits(_t)
    local _n = 0

    if type(_t) ~= "table" then
        return 0
    end

    for _, _k in ipairs(_names) do
        if type(_t[_k]) == "function" then
            _n = _n + 1
        end
    end

    return _n
end

-- 沿 objectlua 的原型链广度搜索，找出真正存放 assist_* 的那张表。
-- 实测（四版探针结论，逐步排除）：
--   type(AssistSystem)          == table
--   getmetatable(AssistSystem)  == string  <- 受保护 __metatable，普通 getmetatable 拿不到
--   AssistSystem["assist_maze"] == nil     <- 实例/类表上读不到方法
--   _M（模块环境）在文件尾部是 nil
--   沿 __index/class/prototype/superclass 搜了 19 张表全 0 命中
-- 最终在 objectlua/bootstrap.lua 找到答案：
--   function redirectAssignmentToPrototype(t, k, v)   -- :27-38
--       local prototype = t.__prototype__
--       rawset(prototype, k, v)
--   即 `function AssistSystem:assist_maze()` 被 __newindex 重定向，
--   **方法存在 __prototype__ 表里**（该表元表又链到父类的 __prototype__）。
--   所以必须用 debug.getmetatable 绕过 "private" 保护，再取 __prototype__。
local _host, _host_path = nil, nil
local _visited = {}

local function _bfs(_t, _path, _depth)
    if _host or _depth > 6 or type(_t) ~= "table" or _visited[_t] then
        return
    end

    _visited[_t] = true

    local _hits = _count_hits(_t)

    _assist_probe("BFS 探测 " .. _path .. ": 命中", _hits .. "/" .. #_names)

    if _hits > 0 then
        _host, _host_path = _t, _path

        return
    end

    for _, _k in ipairs({ "__prototype__", "__index", "class", "prototype", "superclass", "_class" }) do
        local _ok, _v = pcall(function () return _t[_k] end)

        if _ok and type(_v) == "table" then
            _bfs(_v, _path .. "." .. _k, _depth + 1)

            if _host then
                return
            end
        end
    end
end

local _okmt, _mt = pcall(function () return debug.getmetatable(AssistSystem) end)
_assist_probe("debug.getmetatable 的 type=", type(_mt))

if type(_mt) == "table" then
    _bfs(_mt, "mt", 0)
end

_bfs(AssistSystem, "AssistSystem", 0)

if _host == nil then
    _assist_probe("!! BFS 没找到存放 assist_* 的表, 兜底未生效. 已访问表数=", (function ()
        local _c = 0
        for _ in pairs(_visited) do _c = _c + 1 end
        return _c
    end)())
else
    local _raw = {}

    for _, _n in ipairs(_names) do
        local _ok, _f = pcall(function () return _host[_n] end)

        if _ok and type(_f) == "function" then
            _raw[_n] = _f
        end
    end

    for _n, _f in pairs(_raw) do
        _host[_n] = function (...)
            local _ok, _a, _b, _c = pcall(_f, ...)

            if _ok then
                return _a, _b, _c
            end

            _assist_probe(_n .. " 抛错, 按空状态处理:", _a)

            return { status = "", desc = "", redpoint = false }, "", false
        end
    end

    local _cnt = 0
    for _ in pairs(_raw) do _cnt = _cnt + 1 end

    _assist_probe("兜底已挂在 " .. _host_path .. ", 已包", _cnt .. " 个方法")
end
'''
    assert 'AssistSystem:assist_pay' in src, 'assist_pay 锚点异常'
    assert src.rstrip().endswith('end'), '文件末尾结构与预期不符'
    src = src.rstrip('\n') + '\n' + tail
    print('    [兜底] AssistSystem: 运行时探测方法表 + 16 个 assist_* 加 pcall')
    print('    [探针] /sdcard/rp.txt: 加载标记 + 候选表命中数 + 抛错记录')
    return src


def patch_gamestyle(src, _c):
    """getResourceIconById / getSmallIconById 加 nil 守卫（约 30 处调用点受益）。

    现象：full unlock 后 HomeRightScheduleBtnWidget:updateView(48-54) 报
        GameStyle.lua getResourceIconById -> attempt to index local 'config'
    源码是：
        function GameStyle:getResourceIconById(id)
            local config = self:getItemConfig(id)
            return kItemIconPath .. config.Icon .. ".png"     -- config 为 nil 就炸
        end

    注意：这类失败**不是服务端数据缺口**。已核实：
      - ConfigValue.tsv 里 ScheduleRewardId = 'IR_Schedule_Ticket' 存在
      - Item.tsv 里 IR_Schedule_Ticket / IR_Schedule_Resurgence 都存在
    说明运行时的配置表查找在这些 key 上返回 nil（离线 mock 没跑完整配置初始化），
    服务端改数据解决不了。

    全项目 getResourceIconById 有约 30 个调用点（BattleSuccessMediator、
    HeroInfoMediator、DailyScheduleSystem、CardPoolBuyMediator ...），
    逐个系统查不现实，所以在 getter 里加守卫：
      - config 为 nil -> 返回空串并写 /sdcard/rp.txt，调用方 setURL("") 不会崩
      - 正常路径行为完全不变
    """
    helper = '''-- [PATCH] 道具图标查询探针
local function _gs_probe(msg)
    pcall(function ()
        local fh = io.open("/sdcard/rp.txt", "a")
        fh:write(os.date("%H:%M:%S") .. " " .. tostring(msg) .. "\\n")
        fh:close()
    end)
end
'''
    anchor = 'function GameStyle:getResourceIconById(id)'
    assert src.count(anchor) == 1, 'getResourceIconById 锚点异常'
    src = src.replace(anchor, helper + '\n' + anchor, 1)

    old = ('function GameStyle:getResourceIconById(id)\n'
           '\tlocal config = self:getItemConfig(id)\n'
           '\n'
           '\treturn kItemIconPath .. config.Icon .. ".png"\n'
           'end\n')
    new = ('function GameStyle:getResourceIconById(id)\n'
           '\tlocal config = self:getItemConfig(id)\n'
           '\n'
           '\t-- [PATCH] 查不到道具配置时不要崩：返回空串并记录。\n'
           '\t-- 离线 mock 的配置表未完整初始化，config 会是 nil；\n'
           '\t-- 调用方拿到 "" 只会图标空白，比弹错误框卡住玩家好。\n'
           '\tif not config then\n'
           '\t\t_gs_probe("getResourceIconById 查不到道具配置, 返回空串: " .. tostring(id))\n'
           '\n'
           '\t\treturn ""\n'
           '\tend\n'
           '\n'
           '\treturn kItemIconPath .. config.Icon .. ".png"\n'
           'end\n')
    assert src.count(old) == 1, 'getResourceIconById 锚点内容异常'
    src = src.replace(old, new, 1)

    old2 = ('function GameStyle:getSmallIconById(id)\n'
            '\tlocal config = self:getItemConfig(id)\n'
            '\n'
            '\treturn kItemIconPath .. config.IconSmall .. ".png"\n'
            'end\n')
    new2 = ('function GameStyle:getSmallIconById(id)\n'
            '\tlocal config = self:getItemConfig(id)\n'
            '\n'
            '\t-- [PATCH] 同 getResourceIconById\n'
            '\tif not config then\n'
            '\t\t_gs_probe("getSmallIconById 查不到道具配置, 返回空串: " .. tostring(id))\n'
            '\n'
            '\t\treturn ""\n'
            '\tend\n'
            '\n'
            '\treturn kItemIconPath .. config.IconSmall .. ".png"\n'
            'end\n')
    assert src.count(old2) == 1, 'getSmallIconById 锚点内容异常'
    src = src.replace(old2, new2, 1)

    print('    [兜底] GameStyle:getResourceIconById / getSmallIconById 加 nil 守卫')
    print('    [探针] /sdcard/rp.txt 记录查不到配置的道具 id')
    return src


def patch_dmaudio(src, _c):
    """[PATCH] 配音链路探针：把每个失败分支写进 /sdcard/rp.txt。

    背景：JP 语音资源齐全（sound/voice_jp/*.acb + *.awb 各 117 个，均在包内），
    BGM/UI 音效正常，只有角色配音无声，而游戏自带的 print() 已进不了 logcat。
    所以把 dmAudio 里所有关键判定点改写成文件探针，定位到底断在哪一步。

    覆盖的判定点：
      1) getVoiceLanguage()          实际选中的语言 -> 决定 sound/voice_<lang>/
      2) filePath / awbFilePath       isFileExist 结果
      3) audioDirector:loadAcbFile    返回的 acbHn 是否为 nil
      4) playCueByNameFromBlock       返回的 audioPlayback 是否为 nil
      5) configData.CueName / PkgName 传给 native 的参数
    """
    helper = """
-- [PATCH] 配音探针：print 进不了 logcat，改写文件
local function _ap_probe(msg)
    pcall(function ()
        local fh = io.open("/sdcard/rp.txt", "a")
        fh:write(os.date("%H:%M:%S") .. " [voice] " .. tostring(msg) .. "\\n")
        fh:close()
    end)
end
"""
    # [PROBE] 方案B 可行性内省：内置 Lua 服务端需要的能力是否齐备
    # 只在模块加载时跑一次，把结论写进 rp.txt。
    introspect = """
-- [PROBE] 内置服务端可行性内省（模块加载时跑一次）
local function _srv_introspect()
    local out = {}
    local function add(k, v)
        out[#out + 1] = k .. "=" .. tostring(v)
    end
    add("_G.socket", type(_G.socket))
    local ok, sk = pcall(require, "socket")
    add("require_socket", ok)
    add("socket_type", type(sk))
    if ok and type(sk) == "table" then
        local names = {}
        for k, v in pairs(sk) do
            names[#names + 1] = tostring(k) .. "/" .. type(v)
        end
        table.sort(names)
        add("socket_members", table.concat(names, ","))
    end
    local ok2, tcp = pcall(function ()
        return ok and sk.tcp and sk.tcp() or nil
    end)
    add("socket_tcp", ok2)
    add("tcp_type", type(tcp))
    if ok2 and type(tcp) == "table" or ok2 and type(tcp) == "userdata" then
        local mt = getmetatable(tcp)
        local mts = mt and getmetatable(mt)
        local m = {}
        for k in pairs(mt or {}) do m[#m + 1] = tostring(k) end
        table.sort(m)
        add("tcp_mt_keys", table.concat(m, ","))
        local m2 = {}
        for k in pairs(mts or {}) do m2[#m2 + 1] = tostring(k) end
        table.sort(m2)
        add("tcp_mt_mt_keys", table.concat(m2, ","))
        -- 真正试一次 bind + listen + accept 的可达性
        local okb, errb = pcall(function ()
            tcp:settimeout(0)
            assert(tcp:bind("127.0.0.1", 18899))
        end)
        add("tcp_bind", okb)
        add("tcp_bind_err", errb)
        local okl, errl = pcall(function ()
            assert(tcp:listen(1))
        end)
        add("tcp_listen", okl)
        add("tcp_listen_err", errl)
        local oka, erra = pcall(function ()
            return tcp:accept()
        end)
        add("tcp_accept", oka)
        add("tcp_accept_err", erra)
        local oks, errs = pcall(function ()
            assert(tcp:settimeout(0.05))
            assert(tcp:send("ping"))
            tcp:receive(4)
        end)
        add("tcp_io", oks)
        add("tcp_io_err", errs)
        pcall(function () tcp:close() end)
    end
    add("cjson", type(cjson))
    add("string_pack", type(string) == "table" and type(string.pack) or "n/a")
    add("string_unpack", type(string) == "table" and type(string.unpack) or "n/a")
    add("bit", type(bit))
    add("bit32", type(bit32))
    add("bit_tobit", type(bit) == "table" and type(bit.tobit) or "n/a")
    add("os_time", type(os.time))
    add("jit", jit and jit.version or "no-jit")
    _ap_probe("INTROSPECT " .. table.concat(out, " | "))
end
_ap_probe("---- srv introspect begin ----")
pcall(_srv_introspect)
_ap_probe("---- srv introspect end ----")
"""
    anchor = "AudioType = {"
    assert src.count(anchor) == 1, 'AudioType 锚点异常'
    src = src.replace(anchor, helper + "\n" + anchor, 1)

    # [PROBE] 把 srv_introspect 内省块插到 _ap_probe 定义之后（同一次替换）
    src = src.replace(anchor, introspect + "\n" + anchor, 1)

    # 1) getVoiceLanguage 返回值
    old = ("""function getVoiceLanguage(packageName)
	local lang = getCurrentLanguageForVoice()
""")
    new = ("""function getVoiceLanguage(packageName)
	local lang = getCurrentLanguageForVoice()
	_ap_probe("getVoiceLanguage pkg=" .. tostring(packageName) ..
		" pref=" .. tostring(lang) ..
		" default=" .. tostring(GameDefaultVoiceLanguage) ..
		" support=" .. tostring(_G.isSupportLangAudio and
			_G.isSupportLangAudio[lang]))
""")
    assert src.count(old) == 1, 'getVoiceLanguage 锚点异常 x%d' % src.count(old)
    src = src.replace(old, new, 1)

    # 2) 播放路径：filePath + isFileExist
    old = ("""	if not fileUtils:isFileExist(filePath) then
		print("audio file not find:" .. filePath)

		return
	end
""")
    new = ("""	if not fileUtils:isFileExist(filePath) then
		_ap_probe("!! file NOT exist path=" .. tostring(filePath) ..
			" type=" .. tostring(ttype) .. " pkg=" .. tostring(pkgName))

		return
	end

	_ap_probe("file OK path=" .. tostring(filePath) ..
		" type=" .. tostring(ttype) ..
		" cue=" .. tostring(configData and configData.CueName))
""")
    assert src.count(old) == 1, 'isFileExist 分支锚点异常 x%d' % src.count(old)
    src = src.replace(old, new, 1)

    # 3) loadAcbFile 返回值
    old = ("""	local acbHn, fileExist = dmAudio.loadAcbFile(pkgName, ttype)
""")
    new = ("""	local acbHn, fileExist = dmAudio.loadAcbFile(pkgName, ttype)

	_ap_probe("loadAcbFile -> acbHn=" .. tostring(acbHn) ..
		" fileExist=" .. tostring(fileExist) .. " pkg=" .. tostring(pkgName))
"""
)
    assert src.count(old) == 1, 'loadAcbFile 调用锚点异常 x%d' % src.count(old)
    src = src.replace(old, new, 1)

    # 4) loadAcbFile 内部：awb/acb 存在性与 native 返回
    old = ("""		local awbExist = fileUtils:isFileExist(awbFilePath)

		if awbExist then
""")
    new = ("""		local awbExist = fileUtils:isFileExist(awbFilePath)

		_ap_probe("acbPath=" .. tostring(filePath) ..
			" awbPath=" .. tostring(awbFilePath) ..
			" awbExist=" .. tostring(awbExist) ..
			" acbExist=" .. tostring(fileUtils:isFileExist(filePath)))

		if awbExist then
"""
)
    assert src.count(old) == 1, 'awbExist 锚点异常 x%d' % src.count(old)
    src = src.replace(old, new, 1)

    old = ("""		if acbHn == nil then
			print("loadAcbFile error:", packageName, ttype)
""")
    new = ("""		if acbHn == nil then
			_ap_probe("!! native loadAcbFile FAILED pkg=" .. tostring(packageName) ..
				" type=" .. tostring(ttype) ..
				" acb=" .. tostring(filePath) ..
				" awb=" .. tostring(awbFilePath))
"""
)
    assert src.count(old) == 1, 'acbHn nil 分支锚点异常 x%d' % src.count(old)
    src = src.replace(old, new, 1)

    # 5) cue 播放结果
    old = ("""	audioPlayback = audioPlayer:playCueByNameFromBlock(acbHn, configData.CueName, blockIndex)
""")
    new = ("""	audioPlayback = audioPlayer:playCueByNameFromBlock(acbHn, configData.CueName, blockIndex)

	_ap_probe("playCue -> playback=" .. tostring(audioPlayback) ..
		" cue=" .. tostring(configData and configData.CueName) ..
		" block=" .. tostring(blockIndex))
"""
)
    assert src.count(old) == 1, 'playCue 锚点异常 x%d' % src.count(old)
    src = src.replace(old, new, 1)

    print('    [探针] dmAudio 配音链路 6 个判定点已写入 rp.txt')
    return src


def patch_heroinfomediator(src, _c):
    """[PATCH] 跃升(BeyondUp)面板探针：定位"临界3的立绘未解锁"卡在哪一关。

    refreshHeroBeyondUp():1788-1819 有三道闸：
        :1789 funcUnlock  = getByondUpFuncUnlock() -> UnlockSystem:getIsUnlock("Hero_Awaken")
        :1790 btnIsShow   = getBeyondUpBtnIsShow()  按 Character.tsv 的 OpenParam 判 level/star/rank
        :1791 btnIsHave   = getBeyondUpIsHave()    判 _config.OpenParam 是否存在
        任一为假 -> :1794 node_up:setVisible(false) 直接隐藏整个面板
        全过 -> :1801 unLock = getBeyondUpIsUnlock()  判 beyondUp.id
        假 -> :1807 grayed=true（截图里那个锁）
    点击路径另外还有两个 DLC 资源闸：
        HeroInfoMediator:1739 GameStyle:checkResourceReady("Hero_Awaken", true)
        HeroInfoMediator:1751 GameStyle:checkHeroResourceReady(heroId, "Illustration")
    """
    helper = """
-- [PATCH] 跃升探针：print 进不了 logcat，改写文件
local function _bu_probe(msg)
    pcall(function ()
        local fh = io.open("/sdcard/rp.txt", "a")
        fh:write(os.date("%H:%M:%S") .. " [beyondUp] " .. tostring(msg) .. "\\n")
        fh:close()
    end)
end
"""
    anchor = "HeroInfoMediator = class("
    assert src.count(anchor) == 1, 'class 锚点异常 x%d' % src.count(anchor)
    src = src.replace(anchor, helper + "\n" + anchor, 1)

    old = """	local unLock = self._heroConfig:getBeyondUpIsUnlock()

	if not unLock then
"""
    new = """	local unLock = self._heroConfig:getBeyondUpIsUnlock()

	_bu_probe("gates hero=" .. tostring(self._heroId) ..
		" funcUnlock=" .. tostring(funcUnlock) ..
		" btnIsShow=" .. tostring(btnIsShow) ..
		" btnIsHave=" .. tostring(btnIsHave) ..
		" unLock=" .. tostring(unLock) ..
		" beyondId=" .. tostring(self._heroConfig:getBeyondUpId()) ..
		" level=" .. tostring(self._heroConfig:getBeyondUpLevel()) ..
		" max=" .. tostring(self._heroConfig:getBeyondUpMax()) ..
		" cfgBeyondUpId=" .. tostring(self._heroConfig._config and
			self._heroConfig._config.BeyondUpId))

	if not unLock then
"""
    assert src.count(old) == 1, 'refreshHeroBeyondUp 锚点异常 x%d' % src.count(old)
    src = src.replace(old, new, 1)

    # 点击路径的两个 DLC 闸
    old = """				local ready, info = GameStyle:checkHeroResourceReady(self._heroId, "Illustration")
"""
    new = """				local ready, info = GameStyle:checkHeroResourceReady(self._heroId, "Illustration")

				_bu_probe("click hero=" .. tostring(self._heroId) ..
					" resourceReady(Awaken)=见上一处" ..
					" illustrationReady=" .. tostring(ready) ..
					" info=" .. tostring(type(info) == "table" and
						(info.desc or "?") or info))
"""
    assert src.count(old) == 1, 'checkHeroResourceReady 锚点异常 x%d' % src.count(old)
    src = src.replace(old, new, 1)

    print('    [探针] HeroInfoMediator 跃升面板 2 处判定已写入 rp.txt')
    return src


PATCHERS = {'sdk/SDKHelper.luac': patch_sdkhelper,
             'yq/base/Service.luac': patch_service,
             'yq/gameplay/playerLevel/controller/PlayerLevelSystem.luac': patch_playerlevelsystem,
             'yq/launch/login/LoginSystem.luac': patch_loginsystem,
             'yq/launch/login/view/LoginMediator.luac': patch_loginmediator,
             'yq/gameplay/guide/view/GuideWidget.luac': patch_guidewidget,
             'yq/gameplay/team/view/TeamMediator.luac': patch_teammediator,
             'yq/gameplay/stage/view/BattleSuccessMediator.luac': patch_battlesuccess,
             'yq/gameplay/redPoint/RedPointController.luac': patch_redpointcontroller,
             'yq/gameplay/assist/controller/AssistSystem.luac': patch_assistsystem,
             'yq/assets/GameStyle.luac': patch_gamestyle,
             'yq/assets/dmAudio.luac': patch_dmaudio,
             'yq/gameplay/hero/view/HeroInfoMediator.luac': patch_heroinfomediator,
                     'yq/gameplay/activity/model/ActivityList.luac': patch_activitylist}

# ---------------------------------------------------------------- 主流程
# [PROFILE] release 下剔除纯探针文件
if not IS_DEV:
    _before = len(JOBS)
    JOBS[:] = [j for j in JOBS if j['logic'] not in DEV_ONLY_LOGICS]
    for _k in DEV_ONLY_LOGICS:
        PATCHERS.pop(_k, None)
    print('[profile] release：JOBS %d -> %d（剔除 %s）'
          % (_before, len(JOBS), sorted(DEV_ONLY_LOGICS)))

replacements = {}
new_records = []   # (logic, new_real, new_size, new_md5)
db_updates = {}
gated_probes = []  # [PROFILE] (logic, fn) 被关掉的探针

# [PROFILE] 清理上一轮遗留的 _patched_src dump。
# 必须清：dev-only 文件在 release 下不编译，若留着旧 dump，
# 审计"还有哪些探针没关掉"时会被陈旧文件误导（已经踩过一次）。
_dumps = os.path.join(OUT, '_patched_src')
_keep = {j['logic'].replace('/', '__') + '.lua' for j in JOBS}
if os.path.isdir(_dumps):
    for _f in os.listdir(_dumps):
        if _f.endswith('.lua') and _f not in _keep:
            os.remove(os.path.join(_dumps, _f))
            print('[profile] 清理陈旧 dump: %s' % _f)

with zipfile.ZipFile(APK) as z:
    for job in JOBS:
        logic = job['logic']
        print('\n=== %s ===' % logic)
        src = open(job['src'], encoding='utf-8').read()
        print('  原始 %d 行 %d bytes' % (src.count('\n') + 1, len(src.encode('utf-8'))))
        cands = [PATCHERS[logic](fix_syntax(src, logic), None)]

        # [PROFILE] release：把探针 helper 变成空操作，彻底去掉 /sdcard 文件 I/O。
        # 只改最终产物的源码，不回改各个 patcher，改动面最小。
        if not IS_DEV:
            import re as _re2
            src = cands[0]
            for _fn in PROBE_FNS:
                # 用正则而非字面量匹配：helper 的参数签名有两种
                #   local function _rp_probe(msg)
                #   local function _assist_probe(_tag, _msg)
                # helper 有两种写法，都要覆盖：
                #   local function _rp_probe(msg)              -- patch_guidewidget 等
                #   local _assist_probe = function (_tag, _msg) -- patch_assistsystem
                _e = _re2.escape(_fn)
                _pat = _re2.compile(
                    r'(?:local function %s\([^)]*\)|local %s = function\s*\([^)]*\))'
                    % (_e, _e))
                if _pat.search(src):
                    src = _pat.sub(
                        lambda m: 'local YQLR_PROBE = false\n\n' + m.group(0) +
                        '\n\tif not YQLR_PROBE then return end',
                        src, count=1)
                    gated_probes.append((logic, _fn))
            cands = [src]

        # 导出补丁后的源码：debug.traceback() 报的行号对应的是**这份**补丁后的文件，
        # 不是 _out_decompile 里的原始文件（探针插了几十行，两者行号会错位）。
        # 没有它就无法把 traceback 的 luac:NNN 映射回具体代码。
        dumped = cands[0]
        dp = os.path.join(OUT, '_patched_src', logic.replace('/', '__') + '.lua')
        os.makedirs(os.path.dirname(dp), exist_ok=True)
        with open(dp, 'w', encoding='utf-8', newline='') as fh:
            fh.write(dumped)

        chunk = '@' + logic
        bc = compile_luajit(cands, chunk)
        print('  编译 %d bytes magic=%s' % (len(bc), bc[:4].hex(' ')))
        assert bc[:4] == bytes.fromhex('1b4c4a02'), 'magic 错误'

        md5 = hashlib.md5(bc).hexdigest()
        newreal = 'release/%s/%s/%s.luac' % (md5[0:2], md5[2:4], md5[4:32])
        newpath = 'assets/' + newreal
        print('  md5=%s' % md5)
        print('  新路径 assets/%s' % newreal)

        # 往返验证 + 加密
        raw = z.read(job['tagpath'])
        b7, b8 = raw[7], raw[8]
        dec = A.decrypt_blob(raw, tbl=TBL)
        if dec is None:
            print('  !! tag 条目解密失败'); sys.exit(2)
        if A.encrypt_blob(dec, b7, b8, tbl=TBL) != raw:
            print('  !! 往返验证 FAIL'); sys.exit(3)
        print('  往返 PASS (原 %d B, tag b7=%d b8=%d)' % (len(dec), b7, b8))

        ct = A.encrypt_blob(bc, b7, b8, tbl=TBL)
        assert A.decrypt_blob(ct, tbl=TBL) == bc
        assert ct[:7] == bytes.fromhex('405923512b4726') and ct[7] == b7 and ct[8] == b8
        replacements[newpath] = ct
        new_records.append((logic, newreal, len(bc), md5))
        print('  新密文 %d B' % len(ct))

# ---------------------------------------------------------------- 改清单
print('\n=== 修改两份 assets.db ===')
with zipfile.ZipFile(APK) as z:
    for dbpath in ['assets/32/assets.db', 'assets/64/assets.db']:
        tmpdb = os.path.join(TMP, dbpath.replace('/', '_'))
        with open(tmpdb, 'wb') as fh:
            fh.write(z.read(dbpath))
        c = sqlite3.connect(tmpdb)
        have = {r[0] for r in c.execute("select name from sqlite_master where type='table'")}
        tables = [t for t in ('assets', 'm_57') if t in have]
        print('  %s -> 表 %s' % (dbpath, tables))
        for logic, newreal, newsize, newmd5 in new_records:
            for table in tables:
                rows = list(c.execute(
                    'select logic,version,real,size,hash from %s where logic=?' % table, (logic,)))
                if not rows:
                    print('    [%s] %s 未找到记录，跳过' % (table, logic))
                    continue
                for lg, ver, real, size, hsh in rows:
                    print('    [%s] %s 原 size=%s hash=%s' % (table, logic, size, hsh))
                    c.execute('update %s set real=?, size=?, hash=? where logic=? and version=?'
                              % table, (newreal, newsize, newmd5, lg, ver))
                    db_updates[table] = db_updates.get(table, 0) + 1
        c.commit()
        for logic, newreal, newsize, newmd5 in new_records:
            for table in tables:
                for r in c.execute('select real,size,hash from %s where logic=?' % table, (logic,)):
                    print('    [%s] 新 size=%s hash=%s real=%s' % (table, r[1], r[2], r[0]))
        c.close()
        with open(tmpdb, 'rb') as fh:
            replacements[dbpath] = fh.read()

# ---------------------------------------------------------------- 输出
with open(os.path.join(OUT, 'replacements_v5.json'), 'w', encoding='utf-8') as f:
    json.dump({k: v.hex() for k, v in replacements.items()}, f, indent=1)

# 供 patch_runtime_db.py 读取：设备上那份运行时清单才是真正生效的，
# 这里把 logic -> (md5, size) 落盘，避免在下游脚本里硬编码（之前就因此对不上）。
with open(os.path.join(OUT, 'patch_manifest.json'), 'w', encoding='utf-8') as f:
    json.dump({logic: {'md5': md5, 'size': size, 'real': real}
               for logic, real, size, md5 in new_records}, f, indent=1)

print('\n=== patch_manifest.json ===')
for logic, real, size, md5 in new_records:
    print('  %-46s size=%-7d md5=%s' % (logic, size, md5))

print('\n=== 替换清单 %d 条 ===' % len(replacements))
for k, v in replacements.items():
    print('  %-62s %9d B' % (k, len(v)))
if gated_probes:
    print('\n[profile] release 已关闭 %d 处探针 I/O：' % len(gated_probes))
    for _l, _f in gated_probes:
        print('    %-56s %s' % (_l, _f))
else:
    print('\n[profile] %s' % ('dev：全部探针启用' if IS_DEV else 'release：无探针'))
print('\n清单更新: %s' % db_updates)
print('输出: replacements_v5.json')