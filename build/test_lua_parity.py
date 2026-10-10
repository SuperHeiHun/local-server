# -*- coding: utf-8 -*-
"""Python mock 与内置 Lua 服务端的逐 opcode 对拍。

背景：离线端是"预录应答回放器"（应答体在构建期就 json.dumps 成字符串，
Lua 侧一次都不重新编码）。这种结构下"两边都有这个 opcode"完全不代表
"行为一样" —— 之前 Lua 的 14002 就只有 C00S01 一份，第二关起敌人全是
第一关的。本测试对同一输入同时喂给 Python 和 Lua，逐字段比应答。

做法：
  1. 起一个真的 rrcp_server.Server（离线环境，不监听端口）
  2. 把 opcode 表内联进 offline_server.lua，在 luajit 里 load
  3. 同一批请求分别发给两边，比较结果

只比较**双方都应当一致**的部分：敌方阵容、我方站位、出战顺序、进度推进、
抽卡出货。10032 是 Lua 有意不支持的（改配置要重跑 apply_*），单独标注。
"""
import csv
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = r'D:\Temp\yqlr\_out_repack'
PY_SRC = r'E:\Test\Temp\yqlr\_out_rrcp'
LUA_DIR = os.path.join(HERE, 'lua')
LUAJIT = r'E:\lib\LuaJIT\src\luajit.exe'
PH = 'if not OPCODE_TABLE then'

# 主线抽几关 + 天梯抽几关，覆盖不同 AttrCoef / 站位数 / 地形。
# 14002 只喂 C 开头的：Python 侧 14002 走 extract_campaign，天梯 id 在它那里
# 会退回默认 C00S01，那是两种 opcode 的分工，不是缺陷。
MAIN_STAGES = ['C00S01', 'C01S01', 'C02S03', 'C05S03', 'C10S05']
STAIR_STAGES = ['T01S01', 'T07S13', 'T24S40', 'T_FIRE_S001']
STAGES = MAIN_STAGES + STAIR_STAGES
# 请求体里带的编队（字段顺序故意和常见的不同，贴近实测 C01S02）
TEAM_BODY = ('{"battleData":{"teams":{"ShiZ":{"x":1,"y":1},'
             '"CaiH":{"x":1,"y":3},"AnWZ":{"x":1,"y":5}}},'
             '"campaignId":"%s"}')


def spliced_src(dst):
    src = io.open(os.path.join(LUA_DIR, 'offline_server.lua'),
                  encoding='utf-8').read()
    tbl = io.open(os.path.join(LUA_DIR, 'opcode_table.lua'),
                  encoding='ascii').read()
    assert PH in src, 'placeholder missing'
    out = src.replace(PH, tbl + '\n' + PH, 1)
    with io.open(dst, 'w', encoding='utf-8', newline='\n') as f:
        f.write(out)


LUA_HARNESS = r'''
local chunk = assert(loadfile([[__LUA__]]))
chunk()
OfflineServer.load_opcode_table()

local function body_of(op, body)
  local r = OfflineServer.build_response({
    req_id = 1, opcode = op, body = body or '' })
  return r:sub(25)
end

local out = {}
local function dump(op, body)
  out[#out + 1] = op .. '\t' .. body_of(op, body)
end

__DUMPS__

local f = assert(io.open('__OUT__', 'wb'))
for i, line in ipairs(out) do
  if i > 1 then f:write('\n') end
  f:write(line)
end
f:close()
'''


def lua_dump(tmpdir):
    """让 Lua 侧把一批应答写出来，返回 {opcode: body}。"""
    lua_path = os.path.join(tmpdir, 'spliced.lua')
    out_path = os.path.join(tmpdir, 'lua_out.tsv')
    spliced_src(lua_path)

    dumps = []
    for s in MAIN_STAGES:
        dumps.append('dump(%d, [[%s]])' % (14002, TEAM_BODY % s))
    for s in STAIR_STAGES:
        dumps.append('dump(%d, [[{"id":"%s"}]])' % (21001, s))
    for s in ('C01S01', 'C02S03', 'C10S05'):
        dumps.append('dump(%d, [[{"campaignId":"%s"}]])' % (14003, s))
    for g in ('Gacha_Base', 'Gacha_SingleUp_S01'):
        dumps.append('dump(15001, [["gachaId":"%s","isTen":true]])' % g)

    harness = (LUA_HARNESS
               .replace('__LUA__', lua_path.replace('\\', '/'))
               .replace('__OUT__', out_path.replace('\\', '/'))
               .replace('__DUMPS__', '\n'.join(dumps)))
    hp = os.path.join(tmpdir, 'harness.lua')
    with io.open(hp, 'w', encoding='utf-8', newline='\n') as f:
        f.write(harness)

    r = subprocess.run([LUAJIT, hp], capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout)
        print('STDERR:', r.stderr)
        raise SystemExit('lua harness failed')

    got = {}
    order = []
    for line in io.open(out_path, encoding='ascii').read().split('\n'):
        if not line.strip():
            continue
        op, body = line.split('\t', 1)
        got.setdefault(op, []).append(body)
        order.append(op)
    return got, order


def main():
    sys.path.insert(0, PY_SRC)
    import rrcp_server

    # 让 Python 侧也别读机器上遗留的 team_state.json / campaign_state.json，
    # 否则它会带上你上次真机编的队，对拍就不公平了。
    tmp = tempfile.mkdtemp(prefix='yqlr_parity_')
    saved = (rrcp_server.Server.CAMPAIGN_STATE_PATH,
             rrcp_server.Server.TEAM_STATE_PATH)
    rrcp_server.Server.CAMPAIGN_STATE_PATH = os.path.join(tmp, 'no_camp.json')
    rrcp_server.Server.TEAM_STATE_PATH = os.path.join(tmp, 'no_team.json')
    try:
        class Cfg(object):
            out = tmp
            host = '127.0.0.1'
            port = 8888
            algo = 0
            keylen = 16
            timeout = 5.0
            quiet = True
            table = os.path.join(PY_SRC, 'opcodes_table.json')
            logfile = os.path.join(tmp, 'parity.log')

        def fresh_server():
            s = rrcp_server.Server(Cfg())
            s.w = lambda *a, **k: None
            return s

        srv = fresh_server()

        def rsp(op, body=''):
            raw = body.encode('utf-8')
            frame = srv.build_response(
                {'opcode': op, 'req_id': 1, 'app_raw': raw, 'body': raw},
                srv.server_time_ms())
            # build_response 返回的是完整帧，body 在 [24:]，长度在 [20:24]
            blen = struct.unpack('>I', frame[20:24])[0]
            # 必须 json 往返一次断开引用：14003 的 resp['d']['player'] 就是
            # 服务端 table 里那个**活的** dict，之后每次 14003 都会原地改它。
            # 直接留引用的话，前面取到的"快照"会被后面的调用改掉，
            # 比对结果会莫名其妙地漂。
            return json.loads(json.dumps(
                json.loads(frame[24:24 + blen].decode('utf-8'))))

        lua, order = lua_dump(tmp)

        fails = []
        info = []
        checks = 0

        def cmp(name, a, b):
            nonlocal checks
            checks += 1
            if a != b:
                fails.append('%s\n    python = %s\n    lua    = %s'
                             % (name, a, b))

        # ---------------------------------------------------------- 14002
        for s in MAIN_STAGES:
            body = TEAM_BODY % s
            p = rsp(14002, body)
            lj = json.loads(lua['14002'][MAIN_STAGES.index(s)])
            cmp('14002 %s 敌方阵容' % s,
                p['data']['enemyData']['heros'],
                lj['data']['enemyData']['heros'])
            cmp('14002 %s campaignId' % s, p['data']['campaignId'],
                lj['data']['campaignId'])
            cmp('14002 %s gridBattleId' % s, p['data']['gridBattleId'],
                lj['data']['gridBattleId'])
            cmp('14002 %s 我方出战顺序' % s,
                [(h['cid'], h['x'], h['y'], h['uid'])
                 for h in p['data']['playerData']['heros']],
                [(h['cid'], h['x'], h['y'], h['uid'])
                 for h in lj['data']['playerData']['heros']])
            cmp('14002 %s totalCombat' % s,
                p['data']['playerData']['totalCombat'],
                lj['data']['playerData']['totalCombat'])

        # ---------------------------------------------------------- 21001
        for ti, s in enumerate(STAIR_STAGES):
            p = rsp(21001, '{"id":"%s"}' % s)
            lj = json.loads(lua['21001'][ti])
            cmp('21001 %s campaignId' % s, p['data']['campaignId'],
                lj['data']['campaignId'])
            cmp('21001 %s gridBattleId' % s, p['data']['gridBattleId'],
                lj['data']['gridBattleId'])
            cmp('21001 %s 敌方阵容' % s,
                p['data']['enemyData']['heros'],
                lj['data']['enemyData']['heros'])

        # ---------------------------------------------------------- 14003
        #
        # Python 侧是有状态机：branchLastPassed 来自 campaign_passed 集合
        # （本次会话 + campaign_state.json 里的历史），离线端没有状态机，
        # campaignProgress 是构建期按"一路打上来"穷举的。
        # 要公平比较，Python 也得按同样顺序先打通前面的关 —— 否则拿
        # "空历史 + 跳着打第 95 关" 去比"从第 1 关打上来"，比的不是同一件事。
        camp_order = [r['rowId'] for r in
                      csv.DictReader(io.open(
                          r'E:\Test\Temp\yqlr\_out_text\tables\Campaign.tsv',
                          encoding='utf-8'), delimiter='\t')
                      if r.get('rowId')]
        for i, s in enumerate(('C01S01', 'C02S03', 'C10S05')):
            # 每个子用例都从**全新的** Server 起：14003 是有状态的
            # （campaign_passed 一直累积），共用一个实例的话后一个用例
            # 会带着前一个用例打过的关，比的就不是同一件事了。
            srv = fresh_server()
            played = set()
            for prev in camp_order[:camp_order.index(s) + 1]:
                if prev not in played:
                    rsp(14003, '{"campaignId":"%s"}' % prev)
                    played.add(prev)
            p = rsp(14003, '{"campaignId":"%s"}' % s)
            lj = json.loads(lua['14003'][i])
            cmp('14003 %s pass' % s, p['data']['pass'], lj['data']['pass'])
            cmp('14003 %s lastPassed' % s,
                p['d']['player']['datas']['CampaignData']['lastPassed'],
                lj['d']['player']['datas']['CampaignData']['lastPassed'])
            cmp('14003 %s lastCampaign' % s,
                p['d']['player']['datas']['CampaignData']['lastCampaign'],
                lj['d']['player']['datas']['CampaignData']['lastCampaign'])
            pb = p['d']['player']['datas']['CampaignData']['branchLastPassed']
            lb = lj['d']['player']['datas']['CampaignData']['branchLastPassed']
            for ch in sorted(set(lb) - set(pb)):
                info.append('14003 %s: Lua 多出章节 %s=%s（剧情/事件关，'
                            'Python 侧本次历史里没打过）' % (s, ch, lb[ch]))
            for ch in sorted(set(pb) & set(lb)):
                if pb[ch] == lb[ch]:
                    continue
                # Lua 离线端假设"从第 1 关一路打上来"，所以 branchLastPassed
                # 可能比 Python 本次会话的历史更靠后。只要 Lua 那格在
                # campaign Order 上确实更靠后，就是同一套算法的不同输入，
                # 不算不一致；反过来（Lua 更靠前）才是真问题。
                rp = srv.campaign_order_rank(pb[ch])
                rl = srv.campaign_order_rank(lb[ch])
                if rl > rp:
                    info.append('14003 %s: 章节 %s Lua 更靠后（%s vs %s）'
                                '—— 离线端按"一路打上来"穷举，本次会话历史'
                                '里还没打过 %s' % (s, ch, lb[ch], pb[ch], lb[ch]))
                else:
                    cmp('14003 %s 分支 %s' % (s, ch), pb[ch], lb[ch])

        # ---------------------------------------------------------- 15001
        #
        # 抽卡是随机的，构建期只跑了一次把结果冻住；Python 每次调用重新摇。
        # 离线端没有随机源，"固定结果"是刻意的（否则反复十连会不断重置）。
        # 所以比结构（条目数 + 每条的键），不比具体出货英雄。
        for i, g in enumerate(('Gacha_Base', 'Gacha_SingleUp_S01')):
            p = rsp(15001, '{"gachaId":"%s","isTen":true}' % g)
            lj = json.loads(lua['15001'][i])
            cmp('15001 %s 出货条数' % g,
                len(p['data']['result']), len(lj['data']['result']))
            cmp('15001 %s 出货结构' % g,
                [sorted(x[0]) for x in p['data']['result']],
                [sorted(x[0]) for x in lj['data']['result']])
            cmp('15001 %s 全是 CHAR' % g,
                all(x[0].get('type') == 'CHAR' for x in lj['data']['result']),
                True)

        # ---------------------------------------------------------- 汇总
        print()
        print('=== Python <-> Lua 对拍 ===')
        print('  比对项 = %d' % checks)
        print('  不一致 = %d' % len(fails))
        for f in fails:
            print('  FAIL ' + f)
        if not fails:
            print('  全部一致')
        if info:
            print()
            print('  以下为**已知且可解释**的差异，不计入不一致：')
            for m in info:
                print('   - ' + m)
        print()
        print('  注：10032（调试面板）Lua 有意不支持 —— 改开关要重跑 Python')
        print('      的 apply_* 读 TSV，离线端做不到，Lua 会如实返回 resCode=1。')
        print('  注：15001 出货英雄不比 —— 离线端把构建期那一次的结果冻住了，')
        print('      Python 每次重摇；比的是条目数与结构。')
        print('  注：14003 的 branchLastPassed 离线端是累计值（见上方注释），')
        print('      只逐项校验 Python 侧也有的章节。')
        return 1 if fails else 0
    finally:
        (rrcp_server.Server.CAMPAIGN_STATE_PATH,
         rrcp_server.Server.TEAM_STATE_PATH) = saved
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
