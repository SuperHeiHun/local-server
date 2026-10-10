# -*- coding: utf-8 -*-
"""把 Python mock 的 opcode 应答表**物化**成一份 JSON，供内置 Lua 服务端内嵌。

为什么不把 apply_hero/ladder/resource/site 这些逻辑抄进 Lua：
  - 它们依赖 6 个 TSV（Character/CharLevel/CharUpRank/CharUpgrade/CharBeyondUp/
    Favorability/Item/ShowBackGround/AchievementMedal/Guide），抄一遍必然分叉；
  - Python mock 是唯一权威实现，改配置只改一处；
  - 内置 Lua 端只需要「取预编码字符串 + 组帧 + 发包」，体积小、风险低。

关键设计：每个 opcode 的响应体在**构建期就 json.dumps 成字符串**。
  不能在 Lua 侧 decode -> encode 往返：表里有 5 处空数组 `[]`，cjson 会解码成空表
  再编码成 `{}`，把数组悄悄变成对象（reward/clubList 等会踩雷）。
  预编码后 Lua 一次都不重新编码，除 10001 的 guideData 用占位符做一次字符串替换。

用法：
    python build_lua_table.py
输出：
    D:\\Temp\\yqlr\\_out_repack\\lua\\opcode_table.json   (纯 ASCII，供构建期内嵌)
"""
import copy
import io
import json
import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, r'E:\Test\Temp\yqlr\_out_rrcp')

import rrcp_server  # noqa: E402

# 10001 里 guideData 的占位符；Lua 端做一次 gsub 替换。
GUIDE_PLACEHOLDER = '__YQLR_GUIDEDATA__'

# 主屏助理（opcode 10038 changeHero 改的那两个字段）的占位符。
#
# 这两个是**标量字符串字段**，Lua 侧可以安全地做 gsub 替换 —— 这是
# offline 侧唯一能在不重新编码 JSON 的前提下改的形状。Lua 不能像 Python
# 那样 decode -> 改 -> encode：应答体是预编码的字符串（见 MEMORY 46.2），
# cjson 往返会把 5 处空数组 [] 变成空对象 {}。
MAIN_HERO_PLACEHOLDER = '__YQLR_MAINHERO__'
MAIN_TYPE_PLACEHOLDER = '__YQLR_MAINTYPE__'

# 10001 里 d.player.datas.CampaignData 的占位符。
#
# 离线端的 campaignProgress 是构建期穷举的**静态快照**，运行时没有任何状态机，
# 所以关卡进度只活在一个内存变量里 —— 冷启动就回到构建时的初值。
# 客户端每次启动先收 10001，进度是从这里读的，所以落盘之后还必须在 10001
# 把这个占位符换成对应关卡的 CampaignData 快照，否则重进游戏进度照样打回原形。
#
# 为什么能整个替换：CampaignData 是**对象**，但我们不按字段改，而是把它的
# 值整个换成哨兵字符串，运行时做一次纯标量拼接（见 offline_server.lua）。
# 这样 Lua 不需要知道原对象的字节范围，也不用重新编码任何 JSON。
CAMPAIGN_PLACEHOLDER = '__YQLR_CD__'

RESP_KEYS = set(rrcp_server.Server.RESP_KEYS)
JUNK_EXTRA = ('note', 'comment', 'desc', 'fields', 'required', 'schema', 'bug',
              'chain', 'chain2', 'resIds', 'gridConfig', 'taskTypes', 'heroIds',
              'bug2')


def lua_str(s):
    """把一个字符串安全地写成 Lua 短字符串字面量（只做 \\ 和 " 的转义）。

    生成的响应体是纯 ASCII、无换行的 JSON，所以不需要处理换行/控制字符。
    """
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def emit_lua(payload):
    """payload -> 一段 Lua 源码，直接赋值给全局 OPCODE_TABLE。

    刻意**不用** JSON 承载：游戏里的 cjson 只在设备上有，宿主 luajit 没有，
    离线自测就跑不起来。而这里的值本来就全是字符串，转成 Lua 字面量后
    连 cjson 都不需要了。
    """
    lines = []
    # 本文件以 ascii 编码写出，所以这里的所有字面量都必须是纯 ASCII。
    lines.append('-- [GENERATED] by build_lua_table.py - do not edit by hand')
    lines.append('-- data source: rrcp_server.Server (the python mock, single source of truth)')
    lines.append('OPCODE_TABLE = {')
    lines.append('    codeVersion = %s,' % lua_str(payload['codeVersion']))
    lines.append('    guideDataJson = %s,' % lua_str(payload['guideDataJson']))
    lines.append('    serverTimeTarget = %s,' % lua_str(payload['serverTimeTarget']))
    lines.append('    guidePlaceholder = %s,' % lua_str(payload['guidePlaceholder']))
    # 主屏助理：10038 changeHero 的两个标量字段用占位符，Lua 侧按落盘状态
    # gsub 替换（应答体是预编码字符串，不能 decode->encode，见 MEMORY 46.2）。
    lines.append('    mainHeroPlaceholder = %s,' % lua_str(payload['mainHeroPlaceholder']))
    lines.append('    mainTypePlaceholder = %s,' % lua_str(payload['mainTypePlaceholder']))
    # 10001 里 d.player.datas.CampaignData 的值整个被换成这个哨兵字符串，
    # Lua 启动时按 campaign_state.json 里的关卡号换成 campaignCD[stage] 片段。
    lines.append('    campaignCDPh = %s,' % lua_str(payload['campaignCDPh']))
    # 没有落盘时 10001 要下发的初值（Campaign.tsv 第一行）。
    # 哨兵**绝对不能**发到客户端：CampaignData 必须是对象，不是字符串。
    lines.append('    campaignCDDefault = %s,' % lua_str(payload['campaignCDDefault']))
    lines.append('    mainScreenDefault = {')
    lines.append('        heroId = %s,' % lua_str(payload['mainScreenDefault']['heroId']))
    lines.append('        type = %s,' % lua_str(payload['mainScreenDefault']['type']))
    lines.append('    },')
    lines.append('    debugActivityId = %s,' % lua_str(payload['debugActivityId']))
    lines.append('    ladderTemplateId = %s,' % lua_str(payload['ladderTemplateId']))
    # 只是给 Lua 侧数个数，好在 10032 的拒绝信息里说清楚"有多少个开关"。
    lines.append('    debugToggles = {')
    for name in payload['debugToggles']:
        lines.append('        %s,' % lua_str(name))
    lines.append('    },')
    lines.append('    opcodes = {')
    for opcode in sorted(payload['opcodes']):
        lines.append('        [%s] = %s,' % (lua_str(opcode),
                                           lua_str(payload['opcodes'][opcode])))
    lines.append('    },')

    def emit_map(name, mapping, note):
        lines.append('    -- %s' % note)
        lines.append('    %s = {' % name)
        for k in sorted(mapping):
            lines.append('        [%s] = %s,' % (lua_str(k),
                                                lua_str(mapping[k])))
        lines.append('    },')

    # 按关卡预编码的整份应答。Lua 侧只做「抠 id -> 查表 -> 原样发」，
    # 不碰 JSON（应答体是预编码字符串，cjson 往返会把 [] 变 {}）。
    # 注释一律 ASCII：本文件按 ascii 编码写出，含中文会 UnicodeEncodeError。
    emit_map('battles', payload['battles'],
             '14002/21001/21005: campaignId or T<num><type><num> -> whole reply')
    emit_map('heroTpl', payload['heroTpl'],
             'player hero fragment: "<cid>#<slot>", x/y/uid/attrs are placeholders')
    emit_map('spots', payload['spots'],
             'per-stage player spots: "x,y;x,y;..." one per team slot')
    emit_map('attrs', payload['attrs'],
             'per-stage player attrs object (from GridBattle.AttrCoef)')
    emit_map('tcb', payload['tcb'],
             'per-stage friend combat sum; total = n*heroCombat + this')
    emit_map('terrain', payload['terrain'],
             'per-stage blocked cells "x,y;x,y" (MapDataId.landformSP)')
    lines.append('    defaultTeam = {')
    for h in payload['defaultTeam']:
        lines.append('        %s,' % lua_str(h))
    lines.append('    },')
    lines.append('    heroCombat = %d,' % payload['heroCombat'])
    lines.append('    teamCap = %d,' % payload['teamCap'])
    lines.append('    defaultHeroIds = {')
    for h in payload['defaultHeroIds']:
        lines.append('        %s,' % lua_str(h))
    lines.append('    },')
    lines.append('    teamNotHero = {')
    for h in payload['teamNotHero']:
        lines.append('        %s,' % lua_str(h))
    lines.append('    },')
    lines.append('    teamPh = %s,' % lua_str(payload['teamPh']))
    lines.append('    xPh = %s,' % lua_str(payload['xPh']))
    lines.append('    yPh = %s,' % lua_str(payload['yPh']))
    lines.append('    uidPh = %s,' % lua_str(payload['uidPh']))
    lines.append('    attrPh = %s,' % lua_str(payload['attrPh']))
    emit_map('campaignProgress', payload['campaignProgress'],
             '14003: whole reply incl. d.player CampaignData after clearing it')
    # 同一个 CampaignData 的另一种切法，只给 10001 用（冷启动读进度）。
    # 和 campaignProgress 同源，但小得多：不含结算奖励、不含 d 包装。
    emit_map('campaignCD', payload['campaignCD'],
             '10001: CampaignData object per stage (spliced into the sentinel)')
    # 关卡 -> Campaign.tsv 行序。Lua 靠它避免"重打旧关卡把主线进度写回去"。
    lines.append('    -- 1-based row order in Campaign.tsv; same order the snapshots accumulate in')
    lines.append('    campaignOrder = {')
    for k in sorted(payload['campaignOrder']):
        lines.append('        [%s] = %d,' % (lua_str(k), payload['campaignOrder'][k]))
    lines.append('    },')
    emit_map('gacha', payload['gacha'],
             "15001: gachaId, or 'gachaId|10' for ten-pull -> whole reply")
    lines.append('    -- heroIds: lets Lua spot hero names inside the packed 14002 body')
    lines.append('    heroIds = {')
    for h in payload['heroIds']:
        lines.append('        %s,' % lua_str(h))
    lines.append('    },')
    lines.append('}')
    lines.append('')
    return '\n'.join(lines)


class _Cfg(object):
    """Server.__init__ 只用到这几个字段。"""
    def __init__(self, out):
        self.out = out
        self.logfile = os.path.join(out, 'build_lua_table.log')
        self.table = r'E:\Test\Temp\yqlr\_out_rrcp\opcodes_table.json'
        self.port = 8888
        self.algo = 0
        self.keylen = 16
        self.quiet = True


def strip_junk(spec):
    """与 rrcp_server.Server.build_response 的剥说明字段逻辑保持一致。"""
    if not isinstance(spec, dict):
        return spec
    return dict((k, v) for k, v in spec.items() if k in RESP_KEYS)


def main():
    tmp = tempfile.mkdtemp(prefix='yqlr_tbl_')
    saved_team_state = rrcp_server.Server.TEAM_STATE_PATH
    saved_camp_state = rrcp_server.Server.CAMPAIGN_STATE_PATH
    try:
        cfg = _Cfg(tmp)
        # 把状态文件指到不存在的路径。否则会读到你上次在真机上编的队
        # （team_state.json 里存着摆好的 x/y），spots 采到的就是那套坐标，
        # 而不是 GridBattle.PlayerPositonArea 算出来的默认站位 ——
        # 表现是"离线端我方站位和 Python 端对不上"。
        rrcp_server.Server.TEAM_STATE_PATH = os.path.join(tmp, 'no_team.json')
        rrcp_server.Server.CAMPAIGN_STATE_PATH = os.path.join(
            tmp, 'no_campaign.json')
        srv = rrcp_server.Server(cfg)

        # guide_data() 在 GUIDE_SKIP_STORY=True 时返回固定映射，不读状态文件；
        # 仍然先塞一个空 _guide_seen，避免它去碰磁盘上的引导状态。
        srv._guide_seen = {}
        guide = srv.guide_data() or {}
        guide_json = json.dumps(guide, ensure_ascii=True, separators=(',', ':'))

        table = srv.table

        # 必须在替换占位符**之前**取：strip_junk 只做浅拷贝，
        # resp['data']['player'] 和 table['10001']['data']['player']
        # 是同一个对象，往里写占位符会顺手把 srv.table 也改了。
        _player0 = table.get('10001', {}).get('data', {}).get('player') or {}
        main_screen_default = {'heroId': _player0.get('mainScreenHeroId'),
                               'type': _player0.get('mainScreenType')}

        encoded = {}
        dropped = {}

        for opcode, spec in table.items():
            if opcode.startswith('_'):
                # '_comment' / '_schema' 等是我们自己写的说明，不是 opcode
                if not opcode.startswith('_'):
                    continue
            # Python 侧把 '14003.data.passReward' 这种嵌套键也存进了表里，
            # 真正会被请求到的只有纯数字 opcode。
            if not opcode.isdigit() and opcode != 'default':
                continue

            if isinstance(spec, dict) and 'raw' in spec:
                resp = json.loads(spec['raw'])
            else:
                resp = spec

            before = list(resp.keys()) if isinstance(resp, dict) else []
            resp = strip_junk(resp)
            if isinstance(resp, dict):
                gone = [k for k in before if k not in resp]
                if gone:
                    dropped[opcode] = gone

            # 10001 要把引导进度塞进 data.player.guideData，
            # 否则客户端判定服务端进度为 0（见 MEMORY r18-r21）。
            if opcode == '10001':
                p = resp.get('data', {}).get('player') if isinstance(resp, dict) else None
                if isinstance(p, dict):
                    p['guideData'] = GUIDE_PLACEHOLDER
                    # 主屏助理改成占位符，Lua 侧按落盘状态替换。
                    if 'mainScreenHeroId' in p:
                        p['mainScreenHeroId'] = MAIN_HERO_PLACEHOLDER
                    if 'mainScreenType' in p:
                        p['mainScreenType'] = MAIN_TYPE_PLACEHOLDER
                    # 关卡进度改成哨兵，Lua 侧按 campaign_state.json 替换。
                    #
                    # ⚠️ 这里**必须深拷贝 datas**：上面那几个标量写进 p 是安全的，
                    # 因为写完就编码、没人再读；但 CampaignData 会被后面的
                    # gen_campaign_progress() 通过 s2.table 读到并 update()，
                    # 直接写会把 srv.table 里的真数据换成哨兵，
                    # 于是 205 条预编码进度应答里的 CampaignData 全变成那个字符串。
                    datas = p.get('datas')
                    if isinstance(datas, dict) and 'CampaignData' in datas:
                        datas = copy.deepcopy(datas)
                        datas['CampaignData'] = CAMPAIGN_PLACEHOLDER
                        p['datas'] = datas
                else:
                    raise SystemExit('10001 的 data.player 不存在，无法放 guideData 占位符')

            encoded[opcode] = json.dumps(resp, ensure_ascii=True,
                                         separators=(',', ':'))

        # ------------------------------------------------------------------
        # 运行时才算出来的 opcode（Python 侧在 build_response 里分支生成，
        # 不在 opcodes_table.json 里），离线构建要单独物化。
        #
        # 21001/21005 LADDER_FIGHT_STAR / LADDER_SWEEP_BATTLE
        #   客户端拿应答直接开战（见 MEMORY r57）：
        #     LadderSystem:enterStageBattle(:1096-1097)
        #         local campaignId = data.campaignId or data.id
        #         local gridBattleId = data.gridBattleId or self:getGridBattleID(campaignId)
        #     LadderSystem:getGridBattleID(:1071-1073)
        #         assert(battleData, "battleData:" .. tostring(id))
        #   id 为 nil 就崩（实测 battleData:nil）。这里用构建期算好的一份
        #   天梯战斗当模板，关卡号留占位符由 Lua 侧按请求体替换。
        #
        # 21002 LADDER_FIGHT_END
        #   请求体是空的，胜负完全由应答决定。LadderSystem:964-968 只看
        #   responseData.pass，缺字段就进 battleFailedView（打赢被判失败）。
        #
        # 29001 改编队（TeamsService:requestSetTeams）
        #   离线侧没有编队存储逻辑，如实回当前 player，不吞。
        # ------------------------------------------------------------------
        LADDER_PLACEHOLDER = '__YQLR_LADDER_ID__'
        LADDER_GRID_PH = '__YQLR_LADDER_GRID__'

        ladder_gen = None
        ladder_id = ''
        try:
            rows = [r for r in srv.read_tsv('StairsBattle.tsv') if r.get('rowId')]
            # 选一个真实存在的天梯关当模板（与实测日志里的 T24S40 同类）
            pick = next((r for r in rows if r['rowId'] == 'T24S40'), None) \
                or (rows[0] if rows else None)
            if pick:
                ladder_id = pick['rowId']
                ladder_gen = srv.gen_stairs_battle_data(ladder_id)
        except Exception as ex:
            print('  !! 天梯战斗生成失败：%r' % (ex,))

        if ladder_gen:
            ladder_gen = json.loads(json.dumps(ladder_gen))
            ladder_gen['campaignId'] = LADDER_PLACEHOLDER
            ladder_gen['gridBattleId'] = LADDER_GRID_PH
            ladder_body = {'resCode': 0, 'data': ladder_gen}
            encoded['21001'] = json.dumps(ladder_body, ensure_ascii=True,
                                          separators=(',', ':'))
            encoded['21005'] = encoded['21001']
        else:
            print('  !! 没有可用的天梯战斗模板，21001/21005 留空')

        rewards = (table.get('14003', {}).get('data', {}) or {}).get('passReward') or []
        encoded['21002'] = json.dumps(
            {'resCode': 0, 'data': {'pass': True, 'firstPass': True,
                                    'withdraw': False, 'reviewFailed': False,
                                    'passReward': rewards}},
            ensure_ascii=True, separators=(',', ':'))
        encoded['29001'] = json.dumps(
            {'resCode': 0, 'data': {},
             'd': {'player': _player0}},
            ensure_ascii=True, separators=(',', ':'))

        # ------------------------------------------------------------------
        # 【按关卡预编码的整份应答】
        #
        # 离线端是"预录应答回放器"：构建期把每关的完整应答算好并 json.dumps，
        # Lua 侧只做"从请求体抠出关卡号 -> 查表 -> 原样发出"。
        #
        # 为什么不给 14002/21001 用占位符：敌人组成、站位、技能**逐关不同**
        # （实测 203 关平均 2534 B、1686 关天梯平均 2627 B，合计 4.71 MB）。
        # 占位符只能换字符串字段，换不了整个 data。4.71 MB 相对 1.7 GB 的
        # APK 完全可忽略（构建多花约 195 s），所以直接全量物化。
        #
        # 不在 Lua 侧拼 JSON 是硬约束：应答体是预编码字符串，
        # cjson 往返会把空数组 [] 变成 {}（见文件头）。
        # ------------------------------------------------------------------
        def _enc(obj):
            return json.dumps(obj, ensure_ascii=True, separators=(',', ':'))

        # 编队占位符。x/y/attrs 是**裸 token**（json 里不带引号），Lua 侧替换成
        # 数字或对象字面量；uid 保留引号，替换成 "100001_3" 这种字符串。
        # 之所以能让整个英雄对象变成可拼接的片段：实测同关换编队后，
        # 敌方、totalCombat、以及每个英雄除 x/y/uid 外的全部字段都不变，
        # level/star 也是全局的（见下面 build_hero_tpl 的注释）。
        X_PH = '__YQLR_X__'
        Y_PH = '__YQLR_Y__'
        UID_PH = '__YQLR_UID__'
        ATTR_PH = '__YQLR_ATTRS__'
        TEAM_PH = '__YQLR_TEAM__'
        TEAM_CAP = 5

        def _owned(s):
            return (s.table.get('10001', {}).get('data', {})
                    .get('player', {}).get('datas', {})
                    .get('HeroesData', {}).get('heroes') or {})

        def _unquote(enc, token):
            """把 json 里带引号的 "token" 换成裸 token。"""
            return enc.replace('"%s"' % token, token)

        def build_hero_tpl():
            """heroTpl['<cid>#<slot>'] -> 预编码的我方英雄对象（x/y/uid/attrs 占位）。

            不自己拼 _hero_base，而是改写 player_team_hero_ids 让**真的**
            gen_battle_data 出战指定 5 人 —— 这样 apply_hero_config / hero_skills /
            _change_body 的字段规则只存在于 Python 一份，将来加字段自动跟上。
            只需跑 12 次（60 个英雄 / 每队 5 个），与关卡数无关。
            """
            ids = sorted(_owned(srv))
            tpl = {}
            real = srv.player_team_hero_ids
            try:
                for i in range(0, len(ids), TEAM_CAP):
                    chunk = list(ids[i:i + TEAM_CAP])
                    srv.player_team_hero_ids = lambda c=chunk: list(c)
                    d = srv.gen_battle_data('C00S01')
                    if not d:
                        continue
                    for h in d['playerData']['heros']:
                        uid = str(h.get('uid') or '')
                        # 我方出战英雄 uid 固定是 100001_<slot>；友军不是
                        if not uid.startswith('100001_'):
                            continue
                        h = dict(h)
                        h['x'], h['y'], h['attrs'] = X_PH, Y_PH, ATTR_PH
                        h['uid'] = UID_PH
                        base = _unquote(_unquote(_unquote(_enc(h), X_PH),
                                                 Y_PH), ATTR_PH)
                        # 除 uid 外，片段与槽位无关（x/y 运行时才填），
                        # 所以同一个英雄铺满 5 个槽位。
                        for slot in range(1, TEAM_CAP + 1):
                            tpl['%s#%d' % (h['cid'], slot)] = base.replace(
                                '"%s"' % UID_PH, '"100001_%d"' % slot)
            finally:
                srv.player_team_hero_ids = real
            return tpl

        def _terrain_of(grid):
            """这一关压地形的格���（MapDataId.landformSP 的键）。

            Lua 侧要用它校验玩家在编队界面摆的坐标：压在地形上时
            gen_battle_data 会退回默认站位（否则战斗里那个地形技能会
            拿到 nil 的 target 直接崩，见 rrcp_server.py:3155-3167）。
            """
            out = set()
            try:
                m = json.loads(grid.get('MapDataId') or '{}')
                for k in (m.get('landformSP') or {}):
                    kx, ky = k.split('_')
                    out.add('%d,%d' % (int(kx), int(ky)))
            except Exception:
                pass
            return sorted(out)

        def gen_battles():
            battles, spots, attrs, tcb, terrain = {}, {}, {}, {}, {}
            t = time.time()
            hero_tpl = build_hero_tpl()
            default_ids = [h for h in srv.player_team_hero_ids()][:TEAM_CAP]
            combats = set()
            # 逐关生成会打 1889 行日志（每关一行"出战编队"），把 w 静音。
            real_w = srv.w
            srv.w = lambda *a, **k: None
            try:
                def take(stage, d, grid):
                    terrain[stage] = ';'.join(_terrain_of(grid or {}))
                    if not d:
                        return
                    pd = d['playerData']
                    team, friends = [], []
                    for h in pd['heros']:
                        (team if str(h.get('uid') or '').startswith('100001_')
                         else friends).append(h)
                    # spots：默认编队第 i 个人的站位就是 spots[i]，
                    # Python 取值也是 spots[i] if i<len(spots) else (1,1+i)，
                    # 所以直接抄默认编队的站位即可，不复算 PlayerPositonArea。
                    sp = []
                    for i in range(TEAM_CAP):
                        if i < len(team):
                            sp.append('%d,%d' % (team[i]['x'], team[i]['y']))
                        else:
                            sp.append('1,%d' % (1 + i))
                    spots[stage] = ';'.join(sp)
                    attrs[stage] = _enc(team[0]['attrs']) if team else '{}'
                    for h in team:
                        combats.add(int(h.get('combat') or 0))
                    # totalCombat = 出战人数 * 每人 combat + 友军总和。
                    # 友军那部分是每关常量，友军英雄对象原样留在应答里，
                    # Lua 侧只需人数 * heroCombat + friendSum。
                    tcb[stage] = '%d' % sum(int(h.get('combat') or 0)
                                            for h in friends)
                    # 把我方出战那 5 个位置换成裸占位符，友军原样留在后面
                    her = list(pd['heros'])
                    cut = min(len(team), TEAM_CAP)
                    pd['heros'] = ([TEAM_PH] + her[cut:]) if cut else her
                    pd['totalCombat'] = TEAM_PH + '_TC'
                    battles[stage] = _enc({'resCode': 0, 'data': d})

                rows = [r for r in srv.read_tsv('GridBattle.tsv')
                        if r.get('rowId', '').startswith('Campaign_')]
                static14002 = None
                for r in rows:
                    cid = r['rowId'][len('Campaign_'):]
                    # C00S01 是**唯一**不走动态生成的关卡：rrcp_server 的
                    # 14002 分支写死了 `camp != 'C00S01'`，因为这份手写静态
                    # 响应是唯一在真机上从头验通过的（英雄固定 (2,3)，正好
                    # 避开该关 landformSP 的 1_2 / 2_2 两格，见 rrcp_server
                    # :3166）。离线端要跟 Python 一致，就原样照抄它。
                    if cid == 'C00S01':
                        static14002 = srv.table.get('14002')
                        terrain[cid] = ';'.join(_terrain_of(r))
                        continue
                    try:
                        take(cid, srv.gen_battle_data(cid), r)
                    except Exception:
                        pass
                if static14002 is not None:
                    battles['C00S01'] = _enc(static14002)
                n1 = len(battles)
                for r in srv.read_tsv('StairsBattle.tsv'):
                    bid = r.get('rowId')
                    if not bid:
                        continue
                    try:
                        take(bid, srv.gen_stairs_battle_data(bid), None)
                    except Exception:
                        pass
            finally:
                srv.w = real_w
            hero_combat = (list(combats)[0] if len(combats) == 1
                           else (max(combats) if combats else 0))
            if len(combats) > 1:
                # 不唯一就不能按人数算 totalCombat。友军仍按各自 combat 累加，
                # 我方每人 combat 取众数并记录警告（实测恒为 60000）。
                print('  !! 我方 combat 不唯一 %s，按 %s 计算 totalCombat'
                      % (sorted(combats), hero_combat))
            print('  \u6218\u6597\u5e94\u7b54 %d \u6761\uff08\u4e3b\u7ebf %d + \u5929\u68af %d\uff09\uff0c%.1f MB\uff0c%.0fs'
                  % (len(battles), n1, len(battles) - n1,
                     sum(len(v) for v in battles.values()) / 1048576.0,
                     time.time() - t))
            print('  \u7f16\u961f\u7247\u6bb5 %d \u6761\uff0c\u7ad9\u4f4d %d \u6761\uff0c\u6bcf\u4eba combat=%s'
                  % (len(hero_tpl), len(spots), hero_combat))
            return (battles, hero_tpl, spots, attrs, tcb, terrain,
                    default_ids, hero_combat)


        def gen_campaign_progress():
            """14003 逐关的整份应答。

            离线端没有状态机，所以把"通关 X 之后玩家数据长什么样"
            在构建期穷举好：205 关各一份，Lua 侧按最近通关的关卡查表。
            比在 Lua 里拼 CampaignData 稳得多（branchLastPassed 是嵌套
            map，gsub 换不了）。
            """
            out = {}
            t = time.time()
            Server = rrcp_server.Server
            tmpdir = tempfile.mkdtemp(prefix='yqlr_prog_')
            saved_camp = Server.CAMPAIGN_STATE_PATH
            saved_team = Server.TEAM_STATE_PATH
            try:
                # 必须把状态路径指到**不存在的文件**。
                # 否则 Server.__init__ 会把开发机上 campaign_state.json 里
                # "你上次打到哪"（实测 13 关，含 C01S09）读进来，于是
                # 每一条应答的 branchLastPassed 都掺进那 13 关的残留 ——
                # 表现为"刚开始玩，分支进度就已经是 C01S09 了"。
                Server.CAMPAIGN_STATE_PATH = os.path.join(tmpdir, 'no_campaign.json')
                Server.TEAM_STATE_PATH = os.path.join(tmpdir, 'no_team.json')
                s2 = rrcp_server.Server(_Cfg(tmpdir))
                s2.w = lambda *a, **k: None
                for r in srv.read_tsv('Campaign.tsv'):
                    rid = r.get('rowId')
                    if not rid:
                        continue
                    s2.campaign_passed.add(rid)
                    cd = s2.table['10001']['data']['player']['datas'][
                        'CampaignData']
                    cd.update(s2.build_campaign_progress(rid))
                    blp = {}
                    for p in s2.campaign_passed:
                        ch = s2.campaign_chapter(p)
                        if not ch:
                            continue
                        cur = blp.get(ch)
                        if not cur or s2.campaign_order_rank(p) > \
                                s2.campaign_order_rank(cur):
                            blp[ch] = p
                    cd['branchLastPassed'] = blp
                    rewards = s2.table.get('14003', {}).get('data', {}) \
                        .get('passReward') or []
                    out[rid] = _enc({
                        'resCode': 0,
                        'data': {'pass': True, 'firstPass': True,
                                 'withdraw': False, 'reviewFailed': False,
                                 'passReward': rewards},
                        'd': {'player': {'datas': {'CampaignData': cd}}},
                    })
                print('  主线进度应答 %d 条，%.0f KB，%.0fs'
                      % (len(out),
                         sum(len(v) for v in out.values()) / 1024.0,
                         time.time() - t))
            finally:
                Server.CAMPAIGN_STATE_PATH = saved_camp
                Server.TEAM_STATE_PATH = saved_team
                shutil.rmtree(tmpdir, ignore_errors=True)
            return out

        def gen_campaign_cd(progress):
            """从 14003 的整份应答里抠出 CampaignData 子对象，供 10001 冷启动替换。

            解码发生在**构建期**（Python 的 json，随便解），运行时的 Lua 全程
            不碰 JSON —— 所以这里不受「cjson 往返会把 [] 变 {}」的限制。

            和 campaignProgress 是同一份数据的两种切法：campaignProgress 给 14003
            用（含结算奖励），campaignCD 只给 10001 用（纯玩家进度）。
            """
            out = {}
            bad = 0
            for stage, body in progress.items():
                try:
                    resp = json.loads(body)
                    cd = resp['d']['player']['datas']['CampaignData']
                    out[stage] = json.dumps(cd, ensure_ascii=True,
                                            separators=(',', ':'))
                except Exception as ex:
                    bad += 1
                    print('  !! %s 抠 CampaignData 失败: %r' % (stage, ex))
            print('  CampaignData %d 条，%.0f KB%s'
                  % (len(out), sum(len(v) for v in out.values()) / 1024.0,
                     ('，%d 条失败' % bad) if bad else ''))
            return out

        def gen_campaign_order():
            """关卡 -> Campaign.tsv 行序，给 Lua 判断"这次是不是更远了"。

            为什么要这个：Lua 侧只在 14003 时知道"刚打了哪关"，而 campaign_state.json
            里存的是"上次最远打到哪"。如果玩家先打到 C03S05、再去重打一关 C01S02，
            直接覆盖会把进度**往回退**，下次启动就丢了 C03S05。

            为什么用**行序**而不是 campaign_order_rank()：
            实测 205 关只有 **178 个不同的 rank** —— C00S01 和 C00M01 这类
            剧情关共用同一个 rank。用 rank 比会**打平**，于是"打完 C00M01 再打
            C00S01"这种正常的推进不会更新落盘值（`n > o` 为假），
            冷启动就会拿 C00M01 的快照，章节进度反而不对。
            行序正好也是 campaignProgress 快照的累加顺序
            （gen_campaign_progress 就是按它逐行 campaign_passed.add 的），
            所以"行序更大" == "快照包含更多关卡"，语义完全对齐。

            行序恒 >= 0；保留 `order < 0` 的判断只是防御（万一以后换成
            别的排序键），不会真的触发。
            """
            out = {}
            seq = 0
            for r in srv.read_tsv('Campaign.tsv'):
                rid = r.get('rowId')
                if not rid:
                    continue
                seq += 1
                out[rid] = seq
            print('  关卡行序 %d 条（1..%d，Lua 按它防止进度回退）'
                  % (len(out), seq))
            return out

        def gen_gacha():
            """15001 抽卡：构建期每个卡池跑一次，单抽/十连各存一份。

            请求体里 isTen 决定走哪份，所以键用 '<gachaId>' 和 '<gachaId>|10'。
            离线端没有随机源，固定一份结果反而更合脚：每次十连结果一样，
            不会像在线服那样反复重置。
            """
            out = {}
            t = time.time()
            names = sorted(getattr(srv.gacha, 'gacha', {}) or {})
            ok = 0
            for gid in names:
                # build_gacha_response 从 req['app_raw'] 的**原始字节**里正则抽
                # gachaId / isTen（见 rrcp_server.gacha_params），不是读 dict，
                # 所以这里必须拼出同样形态的字节。
                for is_ten in (False, True):
                    raw = ('{"gachaId":"%s","isTen":%s}'
                           % (gid, 'true' if is_ten else 'false')
                           ).encode('ascii')
                    key = gid + '|10' if is_ten else gid
                    try:
                        out[key] = _enc(srv.build_gacha_response(
                            {'app_raw': raw, 'body': raw}))
                    except Exception as ex:
                        print('  !! 卡池 %s 生成失败: %r' % (key, ex))
                ok += 1
            print('  抽卡应答 %d 条（%d 池 x 单抽/十连），%.0f KB，%.0fs'
                  % (len(out), ok,
                     sum(len(v) for v in out.values()) / 1024.0,
                     time.time() - t))
            return out


        battles, hero_tpl, spots, attrs, tcb, terrain, default_ids, \
            hero_combat = gen_battles()
        campaign_progress = gen_campaign_progress()
        campaign_cd = gen_campaign_cd(campaign_progress)
        campaign_order = gen_campaign_order()
        # 10001 在**任何情况下**都必须下发一个对象形式的 CampaignData。
        # 没有落盘时哨兵会原样发出去（客户端拿到的是字符串不是表），
        # 所以这里给一份"全新玩家"的初值快照，和 Python 侧冷启动的语义一致。
        campaign_cd_default = ''
        for stage, sq in sorted(campaign_order.items(), key=lambda kv: kv[1]):
            if sq == 1 and stage in campaign_cd:
                campaign_cd_default = stage
                break
        print('  CampaignData 初值快照 = %s' % (campaign_cd_default or '(缺失!)'))
        gacha = gen_gacha()
        hero_ids = sorted((srv.table.get('10001', {}).get('data', {})
                          .get('player', {}).get('datas', {})
                          .get('HeroesData', {}).get('heroes') or {}).keys())
        print('  英雄 id %d 个（Lua 侧靠它从请求体里认人名）' % len(hero_ids))

        payload = {
            '_note': 'materialized by build_lua_table.py; bodies are PRE-ENCODED json strings',
            'battles': battles,
            'heroTpl': hero_tpl,
            'spots': spots,
            'attrs': attrs,
            'tcb': tcb,
            'terrain': terrain,
            'defaultTeam': default_ids,
            # 14002 请求体里要剔掉的"自动补的默认英雄"（apply_team_config
            # 用 sorted(heroes)[:2] 塞进去的那对）。规则必须与
            # rrcp_server.Server.parse_battle_teams 一致。
            'defaultHeroIds': sorted(
                getattr(rrcp_server.Server, 'DEFAULT_TEAM_HERO_IDS', ()) or ()),
            'teamCap': getattr(rrcp_server.Server, 'TEAM_MAX_NUM_DEFAULT', 5),
            'teamNotHero': sorted(
                getattr(rrcp_server.Server, 'TEAM_NOT_HERO', ()) or ()),
            'heroCombat': hero_combat,
            'teamPh': TEAM_PH,
            'xPh': X_PH,
            'yPh': Y_PH,
            'uidPh': UID_PH,
            'attrPh': ATTR_PH,
            'campaignProgress': campaign_progress,
            'campaignCD': campaign_cd,
            'campaignOrder': campaign_order,
            'campaignCDDefault': campaign_cd_default,
            'gacha': gacha,
            'heroIds': hero_ids,
            'opcodes': encoded,
            'guideDataJson': guide_json,
            'serverTimeTarget': rrcp_server.Server.SERVER_TIME_TARGET,
            'guidePlaceholder': GUIDE_PLACEHOLDER,
            'codeVersion': rrcp_server.CODE_VERSION,
            'mainHeroPlaceholder': MAIN_HERO_PLACEHOLDER,
            'mainTypePlaceholder': MAIN_TYPE_PLACEHOLDER,
            'campaignCDPh': CAMPAIGN_PLACEHOLDER,
            'mainScreenDefault': main_screen_default,
            'debugActivityId': rrcp_server.Server.DEBUG_ACTIVITY_ID,
            'debugToggles': sorted(rrcp_server.Server.DEBUG_TOGGLES),
            # 21001/21005 在 battles 表里查不到时的兜底关卡号
            'ladderTemplateId': ladder_id,
        }

        dst = os.path.join(HERE, 'lua', 'opcode_table.lua')
        with io.open(dst, 'w', encoding='ascii', newline='\n') as f:
            f.write(emit_lua(payload))

        size = os.path.getsize(dst)
        print('=' * 68)
        print('opcodes 已物化 -> %s  (%.1f KB, 纯 ASCII Lua)' % (dst, size / 1024.0))
        print('  可用 opcode : %s' % sorted(encoded))
        print('  guideData   : %s' % guide_json)
        print('  serverTime  : %s' % rrcp_server.Server.SERVER_TIME_TARGET)
        print('  占位符      : %s (10001 里出现 %d 次)'
              % (GUIDE_PLACEHOLDER, encoded['10001'].count(GUIDE_PLACEHOLDER)))
        for k in sorted(dropped):
            print('  %-6s 剥掉说明字段 %s' % (k, dropped[k]))
        for k in sorted(encoded):
            print('  %-6s %6d B' % (k, len(encoded[k])))
    finally:
        rrcp_server.Server.TEAM_STATE_PATH = saved_team_state
        rrcp_server.Server.CAMPAIGN_STATE_PATH = saved_camp_state
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    main()