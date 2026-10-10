#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rrcp_server.py -- 跃迁旅人 rrcp 协议的通用 mock 游戏服

目标：让客户端走完登录流程，同时把**所有**请求录下来，便于逐个补响应。

== 已确认的协议（依据见 MEMORY.md，全部有反汇编地址）==

transport 帧  MessageProtocol::packupMessage @0x827e78
    [0]=(len>>8)&0xff  [1]=len&0xff  [2]=(len>>16)&0xff  [3]=type  [4:]=payload

握手
  C->S type 1 : payload = [u16 BE spki_len][SPKI DER][2B]
  S->C type 3 : RSA-PKCS1v15(client_pub, [u16 keylen][key][u8 algo])
                algo=0 -> 明文会话（客户端跳过 newCrypto，state=4）
                客户端此时只接受 type 3，回别的类型会被静默忽略

数据帧 type 0
    payload = [u32 BE crc32][u32 BE plainlen][data]
    crc32 是标准 zlib crc32 覆盖 data，且 plainlen == len(data)（已实测 MATCH）

RPC 请求 (data)
    [0] kind=1  [1] comp  [2:6] req_id  [6:10] opcode  [10:14] body_len  [14:18] ?  [18:] body

RPC 响应  RPCTransport::writeResponse @0x8205d8
    kind=2 | comp | i32 req_id | i64 timestamp | i32 b | i16 c | u32 len | body

应用体 (Service:newRequest)
    string.char(version, #rid) .. rid .. cjson(params)
    -> [u8 ver][u8 ridlen][rid][cjson]

响应 JSON 约定 (Service:newRequest 的 requestCallback)
    {"resCode":0, "data":{...}}
    resCode==0 成功；resCode!=0 且 !=16001 会弹 Error_<resCode>；
    data 是字符串会被当提示语弹窗（所以成功时别放字符串）。

== 用法 ==
    python rrcp_server.py --port 8888 --table opcodes_table.json --out <dir>
改响应只需改 opcodes_table.json，重启进程即可（不用重打包 APK）。
"""
import argparse
import json
import os
import random
import re
import socket
import struct
import threading
import time
import zlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
import csv
import io
import re

T_HS_OUT = 1        # C->S 我的公钥
T_DATA = 0          # 数据帧（algo=0 时载荷是明文）
T_HS_IN = 3         # S->C 用客户端公钥加密的会话材料
T_TICK = 0xBB       # 心跳
T_ERR = 0xFF

R_KIND_REQUEST = 1
R_KIND_RESPONSE = 2


# ------------------------------------------------------------------ 工具
def frame(payload, mtype):
    n = len(payload)
    return bytes([(n >> 8) & 0xFF, n & 0xFF, (n >> 16) & 0xFF, mtype & 0xFF]) + payload


def rd_hdr(buf, off=0):
    """(payload_len, type)"""
    return buf[off + 1] | (buf[off] << 8) | (buf[off + 2] << 16), buf[off + 3]


def hexdump(b, limit=200):
    out = []
    for i in range(0, min(len(b), limit), 16):
        row = b[i:i + 16]
        out.append('  %04x  %-47s  %s'
                   % (i, ' '.join('%02x' % c for c in row),
                      ''.join(chr(c) if 32 <= c < 127 else '.' for c in row)))
    if len(b) > limit:
        out.append('  ... (+%d)' % (len(b) - limit))
    return '\n'.join(out)


GACHA_OPCODES = (15001,)


def opcode_is_gacha(opcode):
    return opcode in GACHA_OPCODES


def _try_envelope(body, skip):
    """假设前 skip 字节是 native 前缀，返回 (ver, rid, rest) 或 None。

    标准布局是 [i32 native][u8 ver][u8 ridlen][rid][cjson]，
    但实测同一个 opcode 在不同请求下前缀长度并不一致（10001 是 4，
    15001 被读成 ver=116/rid='ster_11...'），所以这里不写死偏移。
    """
    if skip + 2 > len(body):
        return None
    ver = body[skip]
    n = body[skip + 1]
    if n == 0 or skip + 2 + n > len(body):
        return None
    rid = body[skip + 2:skip + 2 + n]
    rest = body[skip + 2 + n:]
    # rid 必须是可打印 ASCII；这是最强的判据
    for c in rid:
        if c < 32 or c > 126:
            return None
    if rest[:1] not in (b'{', b'[', b''):
        return None
    return ver, rid, rest


def parse_app_body(body):
    """body -> (ver, rid, rest, tail)

    不写死 native 前缀长度。实测：10001 是 4 字节，15001 是 **2 字节**
    （gacha_body.bin 落盘核对：38 90 | 00 | 09 | "tester_11" | {...}），
    所以依次试探 0..12，取第一个能给出可打印 rid 且 rest 以 { / [ 开头的切法。

    注意：这里**不要求 rest 能被 json.loads 解析**。客户端发来的 gachaId
    实测就是坏的（"Gacha_DoubleUp_S01" 变成了 "G\\x01\\x0A8_DoubleUp_S01"），
    整个 JSON 因此不可解析，但 isTen 是好的 —— 参数要单独按字节抽（见 gacha_params）。
    """
    if len(body) < 6:
        return None, None, None, body
    for skip in range(0, 13):
        r = _try_envelope(body, skip)
        if r is None:
            continue
        ver, rid, rest = r
        return ver, rid.decode('utf-8', 'replace'), rest, b''
    # 一个都对不上：保持老行为，至少把 rid 解出来便于看日志
    ver = body[4]
    n = body[5]
    rid = body[6:6 + n]
    return ver, rid.decode('utf-8', 'replace'), body[6 + n:], b''


GACHA_ID_RE = re.compile(rb'"gachaId"\s*:\s*"([^"]*)"')
IS_TEN_RE = re.compile(rb'"isTen"\s*:\s*(true|false|\d+)')
HERO_ID_RE = re.compile(rb'"heroId"\s*:\s*"([^"]*)"')
RESOURCE_TYPE_RE = re.compile(rb'"resourceType"\s*:\s*"([^"]*)"')

# 主屏助理三个 tab 对应的 screenType，取值来自 SelectPanelWidget.lua:10-12
SCREEN_TYPES = ('L2D', 'Por_Spine', 'Illustration')


def change_hero_params(*blobs):
    """从原始字节里抽 10038 的 heroId / resourceType。

    和 gacha_params 同一个理由：客户端发来的 JSON 未必整体可解析，
    这里按字节正则抽，抽不到就返回空串让调用方走兜底。
    """
    for raw in blobs:
        if not raw:
            continue
        m = HERO_ID_RE.search(raw)
        if not m:
            continue
        mt = RESOURCE_TYPE_RE.search(raw)
        rt = mt.group(1).decode('utf-8', 'replace') if mt else ''
        return m.group(1).decode('utf-8', 'replace'), rt
    return '', ''


def gacha_params(rest):
    """从原始字节里单独抽 gachaId / isTen，绕开整体 JSON 解析。

    之所以要这么做：客户端发来的 gachaId 实测带坏字节（0x01 0x0A），
    json.loads 整个对象会失败，连本来没坏的 isTen 一起丢掉 ——
    结果客户端明明点的十连，服务端按单抽出货，奖励动画必崩。
    """
    if not rest:
        return '', False
    out = {'gachaId': '', 'isTen': False}
    m = GACHA_ID_RE.search(rest)
    if m:
        out['gachaId'] = m.group(1).decode('utf-8', 'replace')
    m = IS_TEN_RE.search(rest)
    if m:
        v = m.group(1)
        out['isTen'] = (v == b'true' or v == b'1')
    return out['gachaId'], out['isTen']


# ------------------------------------------------------------------ 抽卡引擎
#
# 全部逻辑由游戏自己的三张表驱动，不编造任何掉率或保底：
#   Gacha.tsv      卡池 -> StartGachaRoute -> Coupon/CostSingle/CostTen/FirstCostTen
#   GachaRoute.tsv -> RewardSingle / RewardTen（这个游戏的 91 条 route 全都是
#                   RewardSingle == RewardTen、Count=-1、Weight=1、NextId=[]，
#                   也就是"一次十连的固定 10 个槽位"，单抽就是从这 10 个里抽 1 个）
#   Reward.tsv     每个槽位是一个 RandomType，可以继续引用别的 Reward 行，
#                   要一路展开到叶子（{amount, code, type}）为止。
#
# Reward.tsv 的 Content 统一是 [{ "<key>": [items] }, ...]，key 的含义由 RandomType 决定：
#   FIXED                 items 直接就是奖励
#   ARRAYS / GROUPARRAYS  key = 权重，按权重抽一个槽
#   ONCE / ONCE2          key = 权重，**不重复**池，抽完重置
#   NOREPEAT              同上（保留名，实际未在可达集里出现）
#   TIMES                 key = 累计抽数阈值，取最大的 <= 当前抽数的档
#   TIMESRESETBYMAXVALUE  同 TIMES，但可以出现 "Reset" 值表示计数归零
#   REPEATONCE            {mode: noRepeat|repeat, reward: [槽], missReward: items}
#                         noRepeat = 池内不重复，池空时给 missReward
#   WEIGHT / PROB / ONCE2 等未在卡池可达集里出现的类型统一按"按权重抽"处理
#
# 实测从当前开放的三个卡池出发，可达的 RandomType 只有 7 种：
#   ARRAYS / TIMES / FIXED / REPEATONCE / ONCE2 / GROUPARRAYS / TIMESRESETBYMAXVALUE
# 且没有任何悬空引用（引用了但未定义的 code 数为 0）。
REWARD_ID_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_]*$')


class GachaEngine:
    MAX_DEPTH = 32

    def __init__(self, tables_dir):
        self.dir = tables_dir
        self.gacha = self._tsv('Gacha.tsv')
        self.routes = self._tsv('GachaRoute.tsv')
        self.rewards = {}
        p = os.path.join(tables_dir, 'Reward.tsv')
        if os.path.exists(p):
            for line in io.open(p, encoding='utf-8').read().split('\n'):
                c = line.split('\t')
                if len(c) >= 4 and c[0].strip():
                    self.rewards[c[0].strip()] = (c[1].strip(), c[2].strip(), c[3].strip())
        self.ok = bool(self.gacha and self.routes and self.rewards)

    def _tsv(self, name):
        p = os.path.join(self.dir, name)
        if not os.path.exists(p):
            return {}
        rows = [l.split('\t') for l in io.open(p, encoding='utf-8').read().split('\n')]
        rows = [r for r in rows if any(x.strip() for x in r)]
        hdr = [h.strip() for h in rows[0]]
        return dict((r[0].strip(), dict(zip(hdr, [x.strip() for x in r])))
                    for r in rows[1:] if r and r[0].strip())

    # -------------------------------------------------- 基础工具
    @staticmethod
    def _first_key(group):
        for k in group:
            return k
        return None

    @staticmethod
    def _code_key(group):
        """用于"不重复"判重的稳定标识：取槽里所有 code 拼起来。"""
        k = GachaEngine._first_key(group)
        vals = group.get(k) if k is not None else None
        if not isinstance(vals, list):
            return json.dumps(group, sort_keys=True, ensure_ascii=False)
        return '|'.join(sorted('%s:%s' % (v.get('type'), v.get('code')) for v in vals
                               if isinstance(v, dict)))

    def _weighted_pick(self, groups):
        total = 0
        weights = []
        for g in groups:
            try:
                w = int(self._first_key(g))
            except (TypeError, ValueError):
                w = 1
            w = max(1, w)
            weights.append(w)
            total += w
        if total <= 0:
            return groups[0]
        r = random.randint(1, total)
        acc = 0
        for g, w in zip(groups, weights):
            acc += w
            if r <= acc:
                return g
        return groups[-1]

    def _expand(self, items, ctx, depth):
        """items 是一组 {amount, code, type}；code 若仍是 Reward 行则继续展开。"""
        out = []
        if not isinstance(items, list):
            return out
        for it in items:
            if not isinstance(it, dict) or 'code' not in it:
                continue
            code = it['code']
            if code in self.rewards:
                out.extend(self.resolve(code, ctx, depth + 1))
            else:
                out.append({'amount': it.get('amount', 1),
                            'code': code,
                            'type': it.get('type', 'ITEM')})
        return out

    # -------------------------------------------------- 单个 Reward 行求值
    def resolve(self, rid, ctx, depth=0):
        if depth > self.MAX_DEPTH or rid not in self.rewards:
            return []
        rtype, _reset, content = self.rewards[rid]
        try:
            c = json.loads(content)
        except Exception:
            return []
        if not isinstance(c, list) or not c:
            return []

        if rtype == 'FIXED':
            return self._expand(c, ctx, depth)

        if rtype in ('TIMES', 'TIMESRESETBYMAXVALUE'):
            node = ctx['times'].get(rid, 0) + 1
            ctx['times'][rid] = node
            pick = None
            for grp in c:
                k = self._first_key(grp)
                try:
                    threshold = int(k)
                except (TypeError, ValueError):
                    continue
                if node >= threshold:
                    if grp[k] == 'Reset':
                        ctx['times'][rid] = 0
                        pick = []
                    else:
                        pick = grp[k]
            if pick is None:
                pick = c[0].get(self._first_key(c[0]), [])
            return self._expand(pick, ctx, depth)

        if rtype == 'REPEATONCE':
            spec = c[0] if isinstance(c[0], dict) else {}
            rewards = spec.get('reward') or []
            mode = spec.get('mode', 'repeat')
            if mode == 'noRepeat' and rewards:
                used = ctx['used'].setdefault(rid, [])
                avail = [g for g in rewards if self._code_key(g) not in used]
                if not avail:
                    return self._expand(spec.get('missReward') or [], ctx, depth)
                g = self._weighted_pick(avail)
                used.append(self._code_key(g))
                return self._expand(g.get(self._first_key(g), []), ctx, depth)
            if not rewards:
                return self._expand(spec.get('missReward') or [], ctx, depth)
            g = self._weighted_pick(rewards)
            return self._expand(g.get(self._first_key(g), []), ctx, depth)

        if rtype in ('ONCE', 'ONCE2', 'NOREPEAT'):
            used = ctx['used'].setdefault(rid, [])
            avail = [g for g in c if self._code_key(g) not in used]
            if not avail:
                ctx['used'][rid] = []
                avail = list(c)
            g = self._weighted_pick(avail)
            ctx['used'][rid].append(self._code_key(g))
            return self._expand(g.get(self._first_key(g), []), ctx, depth)

        # ARRAYS / GROUPARRAYS / WEIGHT / PROB / 其余：按权重抽一个槽
        g = self._weighted_pick(c)
        return self._expand(g.get(self._first_key(g), []), ctx, depth)

    # -------------------------------------------------- 对外接口
    def pool(self, gacha_id):
        return self.gacha.get(gacha_id)

    def cost_of(self, gacha_id, is_ten, first_draw=False):
        p = self.pool(gacha_id)
        if not p:
            return None, 0
        if is_ten:
            if first_draw and p.get('FirstCostTen'):
                try:
                    return p['Coupon'], int(p['FirstCostTen'])
                except ValueError:
                    pass
            try:
                return p['Coupon'], int(p.get('CostTen') or 0)
            except ValueError:
                return p['Coupon'], 0
        try:
            return p['Coupon'], int(p.get('CostSingle') or 0)
        except ValueError:
            return p['Coupon'], 0

    def new_state(self):
        return {'times': {}, 'used': {}}

    def draw(self, gacha_id, is_ten, st):
        """返回 (result, err)。result 是 N 个元素，每个元素是一组奖励。

        result 的形状来自 CardPoolModel:formatCardPoolData：
            for k, v in ipairs(data.result) do
                for in_k, in_v in ipairs(v) do ... in_v.type / in_v.code / in_v.amount ...
        """
        p = self.pool(gacha_id)
        if not p:
            return None, 'unknown gachaId %r' % gacha_id

        route_id = None
        try:
            arr = json.loads(p.get('StartGachaRoute') or '[]')
            if arr:
                route_id = arr[0]
        except Exception:
            route_id = None
        route = self.routes.get(route_id) if route_id else None
        if not route:
            return None, 'no route for %r' % gacha_id

        bag = route.get('RewardTen') or route.get('RewardSingle')
        if bag not in self.rewards:
            return None, 'bag %r not defined' % bag
        rtype, _reset, content = self.rewards[bag]
        try:
            slots = json.loads(content)
        except Exception:
            return None, 'bag %r content is not json' % bag
        if not isinstance(slots, list) or not slots:
            return None, 'bag %r is empty' % bag

        ctx = {'times': st.setdefault('times', {}), 'used': st.setdefault('used', {})}

        # 十连 = 把 bag 里全部槽位取出来；单抽 = 按权重取一个槽。
        if is_ten:
            chosen = list(slots)
        else:
            chosen = [self._weighted_pick(slots)]

        result = []
        for grp in chosen:
            items = grp.get(self._first_key(grp), []) if isinstance(grp, dict) else []
            result.append(self._expand(items, ctx, 0))

        # 只保留非空组，避免客户端遍历到空列表
        result = [r for r in result if r] or [[]]
        return result, None


# ------------------------------------------------------------------ 服务器
CODE_VERSION = 'r59-ladderwin-20261010'
class Server:
    def __init__(self, cfg):
        self.cfg = cfg
        os.makedirs(cfg.out, exist_ok=True)
        # own logfile so the process can be spawned detached without shell redirection
        self.logf = open(cfg.logfile or os.path.join(cfg.out, 'server.log'),
                         'a', encoding='utf-8')
        self.nreq = 0
        self.session_key = os.urandom(cfg.keylen)
        self.table = {}
        self.gacha = GachaEngine(Server.TABLES_DIR)
        self.gacha_state = {}
        self.main_screen = {}
        # 最近一次 14002 的 campaignId；14003 结算时用它推进 CampaignData
        # （14003 请求体只有 15 B，里面没有 campaignId）
        self.last_campaign = ''
        # 已通关的主线关卡（Campaign.tsv 的 rowId），落盘在 campaign_state.json
        self.campaign_passed = set()
        self.load_table()
        # 必须在所有 apply_*() 之前：它们按 Server.X 类属性读开关，
        # 载入晚了这一轮就白生成一遍。
        self.load_debug_config()
        self.apply_hero_config()
        # 编队依赖 HeroesData，必须排在 apply_hero_config 之后
        self.apply_team_config()
        self.apply_ladder_config()
        self.apply_explore_config()
        self.apply_prismcore_config()
        self.apply_equip_config()
        self.apply_resource_config()
        self.apply_gacha_config()
        self.apply_site_config()
        self.apply_debug_activity()
        self.apply_banner_activity()
        self.load_main_screen()
        # 主线进度：覆盖 apply_*() 之后的 lastPassed（那些不改它，
        # 但必须排在 load_table() + 全部 apply_* 之后才有 datas 可写）
        self.load_campaign_state()
        self.w('==== 启动 port=%d algo=%d 代码版本=%s ====' % (cfg.port, cfg.algo, CODE_VERSION))
        self.w('会话密钥 %s' % self.session_key.hex())
        self.w('opcode 表 %d 条：%s' % (len(self.table), sorted(self.table)[:20]))

    def load_table(self):
        try:
            with open(self.cfg.table, encoding='utf-8') as f:
                self.table = json.load(f)
        except Exception as ex:
            self.w('!! 读表失败 %r，用空表' % ex)
            self.table = {}

    # ------------------------------------------------------------ 配置表
    # 14002 原来是把 C00S01 的战斗数据写死在 opcodes_table.json 里的，
    # 打第二关就会把第一关的敌方原样发回去。
    # 现在改成从 GridBattle 配置按 campaignId 生成。
    #
    # 配置来源（全部已核对过字段）：
    #   GridBattle.EnemyPositonArea  每关的敌方与友方单位，含 x/y 站位
    #       Campaign_C00S01 [{"x":4,"y":3,"enemy":"C00S01_DEF"}, ..., {"x":3,"friend":"C00S01_ShiZ","y":3}]
    #       Campaign_C00S02 [{"x":4,"y":3,"enemy":"C00S02_DEF"}, ..., {"x":2,"friend":"C00S02_HuL","y":2}]
    #   Enemy.tsv.Resource / Element / Class / Skill  -> modelId / element / profession / skills
    #   Character.tsv.Resource / Element              -> 友方与玩家角色的 modelId / element
    #   GridBattle.Level / Star / AttrCoef / CombatEffectiveness
    TABLES_DIR = r'E:\Test\Temp\yqlr\_out_text\tables'
    _cfg_cache = None

    # 合法职业来自 ConfigValue.tsv 的 ClassAniTime。客户端
    # BattleDataParser:fillHeroSpeed（BattleDataParser.lua:465-494）按
    #     heroData.profession 去 ClassAniTime 里找 {front, jump, back}
    # 找不到就直接 assert：
    #     assert(moveDur and #moveDur == 3, "Hero speed init failed!!!!")
    # 曾在这里硬编码 profession="WARRIOR"，不在合法集合内，导致第二关一点开始战斗
    # 就报 BattleDataParser.lua:451: Hero speed init failed!!!!
    # 第一关没事是因为它走表里那份静态响应，profession 是 "MAGE"。
    DEFAULT_PROFESSION = 'MAGE'
    _prof_cache = None

    def valid_professions(self):
        if Server._prof_cache is not None:
            return Server._prof_cache
        try:
            import csv as _csv
            with io.open(os.path.join(Server.TABLES_DIR, 'ConfigValue.tsv'),
                         encoding='utf-8') as f:
                for row in _csv.DictReader(f, delimiter='\t'):
                    if row.get('rowId') == 'ClassAniTime':
                        Server._prof_cache = {x['Class']
                                              for x in json.loads(row['content'])}
                        break
        except Exception as ex:
            self.w('!! 读 ClassAniTime 失败 %r，用兜底集合' % ex)
        if not Server._prof_cache:
            Server._prof_cache = {'ASSASIN', 'DEFENDER', 'FIGHTER', 'MAGE',
                                  'MARKSMAN', 'SUPPORTER'}
        self.w('合法职业 %s，玩家侧默认用 %s'
               % (sorted(Server._prof_cache), Server.DEFAULT_PROFESSION))
        return Server._prof_cache

    # ------------------------------------------------------------------
    # 角色养成配置：全解锁 / 满星 / 满级 / 满突破
    #
    # 上限一律从配置表推导，**不写死**，改配置表不用动这里：
    #   角色全集  Character.tsv  的 60 个 rowId
    #   等级上限  CharLevel.tsv   rowId 1..150
    #   突破上限  CharUpRank.tsv rowId = <heroId>_<rank>，每角色 1..10
    #             （客户端 HeroBase:getMaxRank() 在 HeroBase.lua:1430-1432
    #               也是写死 return 10，两边一致）
    #   星级上限  CharUpgrade.tsv rowId = <heroId>_<star>，
    #             **NextId == "-1" 的那一档就是满星**
    #             （HeroBase:_getStar() 走 ConfigReader:getRecordById("CharUpgrade", starId)，
    #               HeroBase:getIsMaxStar() 判 NextId == "-1"）
    #
    # 字段与客户端的对应关系（HeroBase.lua:synchronize:120-166）：
    #   starId -> self.star = _getStar()      星级
    #   adv    -> getRank()                   突破
    #   level / exp                          等级 / 经验
    #   heroFavor.favorLv -> favorLv         好感
    # ------------------------------------------------------------------
    HERO_UNLOCK_ALL = True      # True = 全部角色都放进 HeroesData.heroes
    HERO_MAX_STAR = True        # starId 指向该角色满星档
    HERO_MAX_RANK = True        # adv 拉满
    HERO_MAX_LEVEL = True       # level 拉满
    HERO_MAX_FAVOR = False      # 好感拉满（默认关，需要时开）
    HERO_PERSONALITY_MAP = True    # 是否下发 personalityMap —— **必须 True**（见下）
    HERO_PERSONALITY_VALUE = 0     # 6 个性格维度的默认取值
    # 6 个性格维度的键，来自客户端 GameTypesCfg.lua:592-617：
    #   HeroFavorType = { ALL="ALL", HEDONIC="Hedonic", DOMINATE="Dominate",
    #                     CALM="Calm", RIGOROUS="Rigorous", LIVELY="Lively",
    #                     AMIABLE="Amiable" }
    #   HeroFavorContList = { Calm, Hedonic, Amiable, Rigorous, Dominate, Lively }
    # 注意 ALL 是伪类型，不在 ContList 里，不应作为 map 的键。
    HERO_PERSONALITY_KEYS = ('Calm', 'Hedonic', 'Amiable',
                             'Rigorous', 'Dominate', 'Lively')
    # 跃升（BeyondUp / 临界）：把 beyondUp.id 指到该角色最大档
    #   HeroBase:389-391  getBeyondUpIsUnlock() = self._beyondUpId and ~= ""
    #   HeroBase:397-401  getBeyondUpLevel()   = CharBeyondUp(id).StarAmount  <- 就是"临界N"
    #   HeroBase:403-409  getBeyondUpNum()
    #   HeroBase:44      self._upChecks = {}   -> upChecks 不用下发
    #   HeroBase:217-220 getBeyondCheck() 未解锁时返回 {}，有守卫
    # 上限来自 CharBeyondUp.tsv（240 行 = 60 角色 x 4 档 0..3，
    # 实测每角色最大 StarAmount 均为 3，即"临界3"）。
    # 该行同时带 PortraitPlusResource（跃升立绘标记），如
    #   CharBeyondUp_AnWZ_3  StarAmount=3  PortraitPlusResource={"1":1,"2":0,"3":0}
    HERO_MAX_BEYOND_UP = True   # 是否把跃升拉满
    HERO_BEYOND_UP_CAP = None   # 覆盖档位；None = 取 CharBeyondUp.tsv 里该角色最大档
    # 形态资源解锁（立绘 / 骨骼 / Live2D）—— 这是"跃升立绘未解锁"的真正开关
    #   HeroBase:43-50（initialize 默认值）
    #       self.charUnlockResource = {}
    #       self.charUnlockResource.Por_Spine   = 1
    #       self.charUnlockResource.L2D        = 0     <- 默认锁着
    #       self.charUnlockResource.Illustration = 0
    #   HeroBase:305-321（服务端字段，逐键覆盖）
    #       if data.charUnlockResource then
    #           for k, v in pairs(data.charUnlockResource) do
    #               if k == "Por_Spine" and v == 1 then self._newUnlockSpine = v end
    #               if k == "Illustration" and v == 1 then self._newIllustration = v end
    #               self.charUnlockResource[k] = v
    #           end
    #       end
    # 三个判定：
    #   HeroBase:1354-1360  isUnlockSpine()       = charUnlockResource.Por_Spine == 1
    #   HeroBase:1362-1368  isUnlockL2D()         = charUnlockResource.L2D == 1
    #   HeroBase:1370-1372  isUnlockIllustration() = getBeyondUpNum() > 0   （不看这个字段）
    # 消费点：ArchivesHeroDetailsMediator:747-781 openRoleView
    #   isUnlockIllustration -> checkHeroResourceReady(heroId,"Illustration")
    #   isUnlockL2D         -> checkHeroResourceReady(heroId,"L2d")
    HERO_UNLOCK_RESOURCES = True   # 是否下发 charUnlockResource
    HERO_RESOURCE_VALUE = 1        # 三个键统一取值（1 = 已解锁）
    HERO_RESOURCE_KEYS = ('Por_Spine', 'L2D', 'Illustration')
    HERO_KEEP_EXISTING = True   # True = 保留 opcodes_table.json 里已有角色的字段
    HERO_LEVEL_CAP = None       # 覆盖等级上限；None = 取 CharLevel.tsv 最大值
    HERO_RANK_CAP = None        # 覆盖突破上限；None = 取 CharUpRank.tsv 每角色最大值
    HERO_STAR_CAP = None        # 覆盖星级；None = 取 CharUpgrade.tsv 的满星档
    HERO_SET_EXP = 0            # exp 字段值

    _hero_caps_cache = None
    _camp_order = None
    _camp_unlock = None

    def read_tsv(self, name):
        import csv as _csv
        with io.open(os.path.join(Server.TABLES_DIR, name), encoding='utf-8') as f:
            return list(_csv.DictReader(f, delimiter='\t'))

    def hero_ids(self):
        return [r['rowId'] for r in self.read_tsv('Character.tsv') if r.get('rowId')]

    def hero_caps(self):
        """等级/突破/星级上限，全部由配置表推导并缓存。"""
        if Server._hero_caps_cache is not None:
            return Server._hero_caps_cache
        import re as _re
        lv = [int(r['rowId']) for r in self.read_tsv('CharLevel.tsv')
              if str(r.get('rowId', '')).strip().isdigit()]
        ranks = {}
        for r in self.read_tsv('CharUpRank.tsv'):
            m = _re.match(r'^(.*)_(\d+)$', r['rowId'])
            if m:
                hid, rk = m.group(1), int(m.group(2))
                ranks[hid] = max(ranks.get(hid, 0), rk)
        stars = {}                      # heroId -> (starId, StarAmount)
        for r in self.read_tsv('CharUpgrade.tsv'):
            if str(r.get('NextId', '')).strip() == '-1':
                m = _re.match(r'^(.*)_(\d+)$', r['rowId'])
                if m:
                    stars[m.group(1)] = (r['rowId'], int(r['StarAmount']))
        Server._hero_caps_cache = {
            'level': max(lv) if lv else 1,
            'rank': max(ranks.values()) if ranks else 1,
            'ranks': ranks,
            'stars': stars,
            'favor': self.favor_caps(),
            'beyond': self.beyond_caps(),
        }
        return Server._hero_caps_cache

    def beyond_caps(self):
        """跃升（临界）档位，取自 CharBeyondUp.tsv。

        rowId 形如 `CharBeyondUp_<heroId>_<N>`，其 `StarAmount` 就是"临界N"。
        客户端 HeroBase:getBeyondUpLevel():397-401 直接取该字段。
        `PortraitPlusResource` 是跃升立绘的标记（客户端另走 DLC 校验）。
        """
        import re as _re
        rows = self.read_tsv('CharBeyondUp.tsv')
        best = {}          # heroId -> (rowId, StarAmount)
        for r in rows:
            m = _re.match(r'^CharBeyondUp_(.*)_(\d+)$', r.get('rowId', ''))
            if not m:
                continue
            hid = m.group(1)
            try:
                amt = int(r['StarAmount'])
            except (KeyError, TypeError, ValueError):
                continue
            if hid not in best or amt > best[hid][1]:
                best[hid] = (r['rowId'], amt)
        return best

    def favor_caps(self):
        """好感度上限，取自 Favorability.tsv。

        客户端 HeroSystem:getFavoraData():600-609
            local data = ConfigReader:getDataTable("Favorability")
            local len  = 条目数
            return data, len
        HeroInfoMediator:1381   self.favorDatalen = len - 1     -- 满级 = len-1
        HeroInfoMediator:1382   favorData[heroFavorLevel].FavorabilityValue
        HeroInfoMediator:1385   if heroFavorMax == -1 then  -> 走"已满级"分支

        实测 Favorability.tsv 11 行(rowId 0..10)，FavorabilityValue
        60/90/150/210/270/365/450/565/700/745/**-1**，
        即最大 favorLv = 10，且满级那一档是 -1（无上限）。
        curFavor 取最后一个**有限**值，满级分支下 progress 走硬编码 100，
        该字段实际不参与显示，但保持合法数值以免其他读取点拿到 nil。
        """
        rows = self.read_tsv('Favorability.tsv')
        vals = []
        for r in rows:
            try:
                vals.append(int(r['FavorabilityValue']))
            except (KeyError, TypeError, ValueError):
                pass
        finite = [v for v in vals if v > 0]
        return {
            'max_lv': max(len(rows) - 1, 0),
            'cur_max': max(finite) if finite else 0,
        }

    def apply_hero_config(self):
        """按上面的 HERO_* 配置项生成 HeroesData.heroes。

        在 load_table() 之后调用；战斗生成（14002）也会读同一份 heroes。
        """
        player = self.table.get('10001', {}).get('data', {}).get('player')
        if not player:
            self.w('!! apply_hero_config: 10001.data.player 缺失，跳过')
            return
        hd = player.setdefault('datas', {}).setdefault('HeroesData', {})
        heroes = hd.setdefault('heroes', {})

        if not Server.HERO_UNLOCK_ALL:
            self.w('[角色] HERO_UNLOCK_ALL=False，保留原有 %d 个' % len(heroes))
            return

        caps = self.hero_caps()
        ids = self.hero_ids()
        lv_cap = Server.HERO_LEVEL_CAP or caps['level']
        rk_cap = Server.HERO_RANK_CAP or caps['rank']
        st_cap = Server.HERO_STAR_CAP

        added = updated = 0
        for hid in ids:
            h = heroes.get(hid)
            if h is None:
                h = heroes[hid] = {}
                added += 1
            elif not Server.HERO_KEEP_EXISTING:
                h.clear()
                updated += 1

            if Server.HERO_MAX_LEVEL:
                h['level'] = lv_cap
                h['exp'] = Server.HERO_SET_EXP
            if Server.HERO_MAX_RANK:
                h['adv'] = caps['ranks'].get(hid) or rk_cap
            if Server.HERO_MAX_STAR:
                sid = caps['stars'].get(hid)
                if sid:
                    h['starId'] = sid[0] if st_cap is None else '%s_%d' % (hid, st_cap)
            # heroFavor **必须无条件下发**，否则两个界面直接崩：
            #   HeroInfoMediator:1377-1378
            #       self.heroFavorLevel = self._heroConfig.heroFavor.favorLv
            #       self.heroFavorCur   = self._heroConfig.heroFavor.curFavor
            #   HeroInfoMediator:1317
            #       return self._heroConfig.heroFavor.favorLv == len - 1
            #   ArchivesHeroDetailsMediator:593
            #       if self._heroConfig.heroFavor.favorLv < paramData.level then
            # 三处都没有 nil 判断。HeroBase:synchronize:145-147 虽带
            # `if data.heroFavor then` 保护，但那是**写入端**的保护，
            # 读取端照样会崩 —— 所以「可选字段」的判断在这里是错的。
            # 上限来源：Favorability.tsv 行数 - 1（HeroSystem:getFavoraData:600-609
            #   返回 data, len，HeroInfoMediator:1381 用 len-1 作满级），
            #   该表 11 行 -> 最大 favorLv=10，其 FavorabilityValue=-1（满级无上限）。
            fav = caps['favor']
            if Server.HERO_MAX_FAVOR:
                h['heroFavor'] = {'favorLv': fav['max_lv'],
                                  'curFavor': fav['cur_max']}
            else:
                h['heroFavor'] = {'favorLv': 0, 'curFavor': 0}
            # personalityMap 同样**必须无条件下发**，全工程 6 处无保护读取：
            #   HeroInfoMediator:1478          local curPerData = self._heroConfig.personalityMap
            #   DailyScheduleChooseHeroMediator:322   同上
            #   DailyScheduleClinicViewMediator:531   同上
            #   DailyScheduleHeroInfoViewMediator:119  local curPerData = heroConfig.personalityMap
            #   HomeWorldSystem:654 / :666 / :817      local curPerData = heroConfig.personalityMap
            #   HomeWorldHeroSelectMediator:128
            #       hero.personalityMap[newFavor] > 0     -- 缺 key 直接崩
            # 取值 0 是安全的：
            #   HeroInfoMediator:1488  cur = cur and cur or data.init
            #       Lua 里 0 为真 -> cur=0，随后 :1490-1496 会按配置 min/max 钳位
            #   HomeWorldHeroSelectMediator:128  0 > 0 为假，不崩
            if Server.HERO_PERSONALITY_MAP:
                h['personalityMap'] = {k: Server.HERO_PERSONALITY_VALUE
                                       for k in Server.HERO_PERSONALITY_KEYS}
            # 跃升（临界）：必须下发 beyondUp.id，否则 getBeyondUpIsUnlock() 为假，
            # 面板永远锁着（HeroInfoMediator:1721 / HeroBase:389-391）。
            if Server.HERO_MAX_BEYOND_UP:
                b = caps['beyond'].get(hid)
                if b is None:
                    self.w('[角色] !! %s 在 CharBeyondUp.tsv 里没有跃升档' % hid)
                else:
                    if Server.HERO_BEYOND_UP_CAP is None:
                        h['beyondUp'] = {'id': b[0]}
                    else:
                        h['beyondUp'] = {'id': 'CharBeyondUp_%s_%d'
                                         % (hid, Server.HERO_BEYOND_UP_CAP)}
            # 形态资源解锁：L2D 默认是锁的，必须服务端下发才会开
            if Server.HERO_UNLOCK_RESOURCES:
                h['charUnlockResource'] = {k: Server.HERO_RESOURCE_VALUE
                                           for k in Server.HERO_RESOURCE_KEYS}

        n_star = sum(1 for h in heroes.values() if 'starId' in h)
        n_fav = sum(1 for h in heroes.values() if 'heroFavor' in h)
        self.w('[角色] HERO_UNLOCK_ALL=%s MAX_STAR=%s MAX_RANK=%s MAX_LEVEL=%s'
               % (Server.HERO_UNLOCK_ALL, Server.HERO_MAX_STAR,
                  Server.HERO_MAX_RANK, Server.HERO_MAX_LEVEL))
        self.w('[角色] 共 %d 个角色（新增 %d / 改写 %d），上限 level=%s adv=%s 满星=%d'
               % (len(heroes), added, updated, lv_cap, rk_cap, n_star))
        self.w('[角色] heroFavor 下发 %d 个，favorLv 上限=%s curFavor=%s（MAX_FAVOR=%s）'
               % (n_fav, caps['favor']['max_lv'], caps['favor']['cur_max'],
                  Server.HERO_MAX_FAVOR))
        miss = [h for h in ids if 'starId' not in heroes.get(h, {})]
        if miss:
            self.w('[角色] !! 缺满星 starId: %s' % miss[:10])
        missf = [h for h in ids if 'heroFavor' not in heroes.get(h, {})]
        if missf:
            self.w('[角色] !! 缺 heroFavor（会崩）: %s' % missf[:10])
        misp = [h for h in ids if 'personalityMap' not in heroes.get(h, {})]
        if misp:
            self.w('[角色] !! 缺 personalityMap（会崩）: %s' % misp[:10])
        self.w('[角色] personalityMap %s（键 %s 值 %s）'
               % ('已下发' if Server.HERO_PERSONALITY_MAP else '关闭',
                  list(Server.HERO_PERSONALITY_KEYS),
                  Server.HERO_PERSONALITY_VALUE))
        n_be = sum(1 for h in heroes.values() if 'beyondUp' in h)
        lvls = sorted({caps['beyond'][h][1] for h in ids
                       if h in caps['beyond']})
        self.w('[角色] beyondUp 下发 %d 个，档位(临界)=%s（MAX_BEYOND_UP=%s CAP=%s）'
               % (n_be, lvls, Server.HERO_MAX_BEYOND_UP,
                  Server.HERO_BEYOND_UP_CAP))
        misb = [h for h in ids if 'beyondUp' not in heroes.get(h, {})]
        if misb:
            self.w('[角色] !! 缺 beyondUp（跃升会锁）: %s' % misb[:10])
        n_res = sum(1 for h in heroes.values() if 'charUnlockResource' in h)
        self.w('[角色] charUnlockResource 下发 %d 个（%s=%s，UNLOCK_RESOURCES=%s）'
               % (n_res, list(Server.HERO_RESOURCE_KEYS),
                  Server.HERO_RESOURCE_VALUE, Server.HERO_UNLOCK_RESOURCES))

    # ------------------------------------------------------------------
    # 天梯（Ladder/StairsBattle）：StairsBattleData.typeData[*].order 必须有值
    #
    # 现象：道具详情弹窗打开时崩
    #   LadderSystem.lua:658 attempt to perform arithmetic on local 'order'
    #   链：ItemInfoDetailMediator:184 addPopupView -> :55 enterWithData
    #       -> LadderSystem:658 getAutoBattleSpeedData
    #       -> :578 getAutoBattleSpeed
    #
    # 根因：
    #   LadderSystem:735-743 getAutoBattleSpeed(offset)
    #       local info = self:getLadderInfoForType(LadderType.COMMON)  -- :293-297
    #           return ladderInfo[type]                                  -- _ladderList[type]
    #       local order = info.order            <-- 我们从没下发过这个字段 -> nil
    #       local battleInfo = self:getBattleInfo(LadderType.COMMON, order + 1 + offset)
    #                                                                ^^^^^^^^^^^^^^^ 崩
    #   LadderSystem:745-753 getCur2TargetAutoBattleSpeed 同样用 info.order
    #   LadderSystem:767-771 getCurStairId 也用 ladderInfoData.order
    #
    # 数据入口：DevelopSystem:206  self:getLadder():synchronize(otherDatas.StairsBattleData)
    #   LadderModel:85-116 synchronize
    #       if ladderData.typeData then GameStyle:valueReplace(ladderData.typeData, self._ladderList) end
    #       if ladderData.checkMaps then ... end
    #       if ladderData.todayReward ~= nil then ... end
    #
    # order 的语义：LadderSystem:581-591 getBattleInfo(type, order)
    #   对 self._ladderConfigs[type] 按 config.Order 排序后取第 order 个，
    #   即**名次下标**（1 起）。取不到只会返回 {}，不会崩；
    #   但 nil 会在调用方做 `order + 1` 时崩，所以**必须存在**。
    #
    # 【为什么给一个很大的数】MainBattleViewSystem:getCurLadderInfo:86-107
    #     local progress = ""                       -- 字符串初值
    #     if data.Order <= order then
    #         progress = #stairsData                -- 数字
    #     else
    #         for k, v in pairs(stairsData) do
    #             if order + 1 == v.Order then
    #                 progress = k - 1; break       -- 数字
    #             end
    #         end
    #         -- 循环一次没匹配上，progress 就还是 ""
    #     end
    #     ...
    #     elseif progress < #stairsData then       -- :107 "" < 数字 → 崩
    #
    # 实测报的就是 "attempt to compare string with number"（r54）。
    # order=1 时 data.Order（章节最后一层，比如 70）> 1，走 else 分支，
    # 要在整章里找 Order==2 的行；找不到 progress 就漏成 ""。
    # 把 order 抬到大于任何章节层数，第一分支恒成立，progress 必是数字。
    LADDER_ORDER = 9999
    LADDER_TYPES = ('COMMON', 'WIND', 'FIRE', 'LIGHT', 'WATER', 'DARK', 'EARTH')

    def apply_ladder_config(self):
        """给 StairsBattleData.typeData[*] 补 order 字段。"""
        player = self.table.get('10001', {}).get('data', {}).get('player')
        if not player:
            return
        sb = player.setdefault('datas', {}).setdefault('StairsBattleData', {})
        td = sb.setdefault('typeData', {})

        # 以源表里已有的条目做模板。源表只有 COMMON 是完整的，
        # 以前对缺的类型直接 setdefault(t, {}) 建了个空字典，只补了 order，
        # 结果客户端 LadderSystem:getAllAdditionPercent 里
        #     for heroId, heroData in pairs(data.keepingHeroes)   -- 非 COMMON 分支
        # 拿到 nil -> "bad argument #1 to 'pairs' (table expected, got nil)"。
        # 所以每个类型都要有完整的 keepingHeroes / rank / score 等字段。
        template = None
        for v in td.values():
            if isinstance(v, dict) and 'keepingHeroes' in v:
                template = v
                break

        filled = []
        for t in Server.LADDER_TYPES:
            d = td.get(t)
            if not isinstance(d, dict):
                d = {}
                td[t] = d
                filled.append(t)
            if template:
                for k, v in template.items():
                    d.setdefault(k, json.loads(json.dumps(v))
                                 if isinstance(v, (dict, list)) else v)
            d.setdefault('keepingHeroes', {})
            if d.get('order') is None:
                # 必须是 number。证据：LadderModel:initConfigData:52-55 在
                # **初始化**时就比较 `self._T04LastOrder < v`，v 来自
                # config.Order（StairsBattle 表）。若那是字符串，
                # `0 < "1"` 在启动阶段就会抛 "compare number with string"，
                # 但游戏能正常启动 -> config.Order 是数字。
                # LadderSystem:190 checkStairsIsFinish 同样是
                #     return order <= orderCur      -- order 取自配置表
                # 所以这里的 order 也发数字。
                d['order'] = Server.LADDER_ORDER
                filled.append(t)
            # keepingNum = 该类型已解锁的挂机位数量（客户端只读、从不赋值，
            # 必须服务端下发）。来源 StairsBattleIdleUnlock.tsv 的 Num 列
            # （EARTH/WATER/WIND/FIRE = 8、LIGHT = 6）。
            #
            # 缺它会报 "LadderSystem.lua:352: attempt to compare two nil values"：
            # getOtherElemetOnHookHeroes:404-406 排序时直接
            #   table.sort(..., function (a, b) return b.keepingNum < a.keepingNum end)
            # 每一项都缺 keepingNum -> 比较 nil -> 崩。
            # **报错行号 352 是 luac 行表，跟反编译源码对不上**（真实位置 ~405），
            # 排查时别被行号带偏。
            #
            # 顺序很关键：必须在**模板拷贝之后**赋值，否则 COMMON 先算出的
            # keepingNum 会被 setdefault 复制给其余 6 个类型，
            # 结果所有类型都变成 COMMON 的值（实测全变成 1）。
            d['keepingNum'] = self.ladder_slot_count(t)
        self.w('[天梯] StairsBattleData.typeData order=%s，补齐/新建 %d 个类型: %s'
               % (Server.LADDER_ORDER, len(set(filled)), sorted(set(filled))))

        self.fill_ladder_reward_buff(td)

    LADDER_UNLOCK_TSV = 'StairsBattleIdleUnlock.tsv'

    # 表里没有该类型时的兜底位数。COMMON / DARK 在 StairsBattleIdleUnlock.tsv
    # 里没有行（那张表只覆盖 EARTH/WATER/WIND/FIRE/LIGHT 五个属性），
    # 但客户端 LadderSystem 的 LADDERType / openElement 仍然会遍历到它们，
    # 所以必须给个值，否则同样会 nil 比较。
    LADDER_DEFAULT_SLOTS = 1

    def ladder_slot_count(self, type_name):
        """该类型在 StairsBattleIdleUnlock.tsv 里的最大 Num（= 挂机位数）。"""
        if not hasattr(self, '_ladder_slots'):
            self._ladder_slots = {}
            try:
                for r in self.read_tsv(Server.LADDER_UNLOCK_TSV):
                    t, num = r.get('Type'), r.get('Num')
                    if not t or not num:
                        continue
                    try:
                        n = int(num)
                    except ValueError:
                        continue
                    if n > self._ladder_slots.get(t, 0):
                        self._ladder_slots[t] = n
            except Exception as ex:
                self.w('!! 读 %s 失败: %r' % (Server.LADDER_UNLOCK_TSV, ex))
        return self._ladder_slots.get(type_name, Server.LADDER_DEFAULT_SLOTS)

    LADDER_REWARD_TSV = 'StairsBattleIdleReward.tsv'

    def fill_ladder_reward_buff(self, td):
        """给每个 keepingHeroes 条目补 rewardBuff。

        客户端有两处会遍历它，缺了就直接崩：
            LadderSystem:337  for k, v in pairs(heroData.rewardBuff)
            LadderSystem:517  for k, v in pairs(heroData.rewardBuff)
        而源表给的 keepingHeroes 只有 {"LaJ": {"uid":1}}，没有 rewardBuff。

        rewardBuff 的形状 = StairsBattleIdleReward.tsv 的 RewardAdd
        （形如 {"CharExpPM":100}）。真实服务器是按角色当前 level/rank/star
        取满足条件的档位求和；离线服的角色一律满级满星（见 apply_hero_config），
        所以直接取该 Type 全部档位的和 —— 这与客户端自己在满级时的算法一致，
        不是编的数。
        """
        p = os.path.join(Server.TABLES_DIR, Server.LADDER_REWARD_TSV)
        if not os.path.exists(p):
            self.w('[天梯] 缺 %s，rewardBuff 置空' % Server.LADDER_REWARD_TSV)
            by_type = {}
        else:
            rows = [l.split('\t') for l in io.open(p, encoding='utf-8').read().split('\n')]
            rows = [r for r in rows if any(x.strip() for x in r)]
            hdr = [h.strip() for h in rows[0]]
            by_type = {}
            for r in rows[1:]:
                d = dict(zip(hdr, [x.strip() for x in r]))
                try:
                    add = json.loads(d.get('RewardAdd') or '{}')
                except Exception:
                    continue
                acc = by_type.setdefault(d.get('Type') or 'COMMON', {})
                for k, v in add.items():
                    try:
                        acc[k] = acc.get(k, 0) + float(v)
                    except (TypeError, ValueError):
                        acc[k] = acc.get(k, 0)

        touched = 0
        for t, data in td.items():
            kh = data.get('keepingHeroes')
            if not isinstance(kh, dict):
                continue
            add = by_type.get(t, {})
            for heroId, heroData in kh.items():
                if not isinstance(heroData, dict):
                    heroData = {}
                    kh[heroId] = heroData
                heroData.setdefault('uid', 1)
                heroData['rewardBuff'] = dict(add)
                touched += 1
        self.w('[天梯] rewardBuff 已补 %d 个英雄；按类型 %s'
               % (touched, {k: sorted(v) for k, v in sorted(by_type.items())}))
        self.fill_ladder_check_maps()

    # ------------------------------------------------------------------
    # 天梯 checkMaps（「资源勘探」入口的开关）
    # ------------------------------------------------------------------
    #
    # 现象：主界面第二个入口「资源勘探」灰色、点不动，点了会弹"未开放"。
    #
    # 门控在 ChapterMapMediator:338-346（New_planet_UI3 = 资源勘探 ->
    # openStaris）：
    #     function ChapterMapMediator:openStaris()
    #         if #self._ladderSystem:getCheckMaps() == 0 then
    #             ... ShowTipEvent(Strings:get("Function_Not_Open"))
    #             return              -- 直接 return，不进界面
    #         end
    #         self._ladderSystem:enterLadderInfo("tower")
    #     end
    #
    # 取值链：LadderSystem:231-233 -> LadderModel:136-138 getCheckMaps()
    #     return self._checkDataMaps
    # 而 _checkDataMaps 只在 LadderModel:synchronize:90-91 填：
    #     if ladderData.checkMaps then
    #         GameStyle:valueReplace(ladderData.checkMaps, self._checkMaps)
    #     end
    # 也就是 StairsBattleData.checkMaps。我们一直在发空表 {}，
    # 于是 #==0 恒成立，入口永远灰着。
    #
    # 填法（LadderModel:synchronize:90-111，形状必须严格对上）：
    #     for k, v in pairs(self._checkMaps) do
    #         local cond = v.openCondition
    #         if cond.currentValue == cond.targetValue then
    #             local cfg = ConfigReader:getRecordById("CampaignChapter", v.id)
    #             if cfg.Type == "Stairs" then
    #                 data[cfg.Order] = {data = v, cfg = cfg}
    #     self._checkDataMaps = data
    #
    # 两个硬要求：
    #   1) 每项必须有 openCondition.currentValue / .targetValue，
    #      两者相等才算解锁 —— 缺字段就是 cond 为 nil 直接崩
    #      （实测报 LadderModel.lua:92 attempt to index local 'cond'）
    #   2) v.id 必须是 **CampaignChapter.tsv 里 Type=="Stairs"** 的 rowId，
    #      否则 cfg.Type 不是 "Stairs"，这一项会被跳过（入口还是锁）
    # 键用章节 Order，最终 data 也按 cfg.Order 建索引，正好对上。
    LADDER_CHECK_TYPES = ('COMMON', 'DARK', 'EARTH', 'FIRE',
                          'LIGHT', 'WATER', 'WIND')
    CAMPAIGN_CHAPTER_TSV = 'CampaignChapter.tsv'

    def fill_ladder_check_maps(self):
        pl = self.table.get('10001', {}).get('data', {}).get('player')
        if not isinstance(pl, dict):
            return
        sb = pl.setdefault('datas', {}).setdefault('StairsBattleData', {})
        stairs = []
        for r in self.read_tsv(Server.CAMPAIGN_CHAPTER_TSV):
            if r.get('Type') != 'Stairs' or not r.get('rowId'):
                continue
            try:
                order = int(float(r.get('Order') or 0))
            except Exception:
                continue
            stairs.append((order, r['rowId']))
        stairs.sort()
        if not stairs:
            self.w('[天梯] checkMaps 没跳过：CampaignChapter 里没有 Type=Stairs')
            return

        cm = {}
        for order, cid in stairs:
            # 全部标成"已达成"（currentValue == targetValue），
            # 离线服没有进度概念，解锁判定直接过。
            cm[str(order)] = {
                'id': cid,
                'openCondition': {'currentValue': 1, 'targetValue': 1},
                'order': order,
                'checkOrder': 1,
                'totalCost': 0,
            }
        sb['checkMaps'] = cm
        self.w('[天梯] checkMaps 补 %d 项（Stairs 章节，空表会让「资源勘探」锁死）: %s'
               % (len(cm), ', '.join(c for _o, c in stairs[:6]) + ' ...'))

    # ------------------------------------------------------------------
    # 资源勘探（ExploreData）
    # ------------------------------------------------------------------
    #
    # 现象：主界面第二个入口「资源勘探」点不开。
    # 原因：我们从来没下发过 ExploreData，ExploreModel._sceneMap 是空表。
    # 客户端一进图就解引用（ExploreModel:60-70）：
    #     function getFinishObjects(exploreId) return self._sceneMap[exploreId].finishObjects end
    #     function getChainMap(exploreId)      return self._sceneMap[exploreId].chainMap end
    #     function getCheckMap(exploreId)      return self._sceneMap[exploreId].checkMap end
    # 三个都是 `self._sceneMap[exploreId].X`，exploreId 不存在就是 nil 索引。
    # 消费点见 ExploreSystem:57/223/236/259/282/308/896/910。
    #
    # 形状取自 ExploreModel:synchronize(:12-36)：
    #     if data.currentData and data.currentData.chainMap then ... end
    #     if data.currentData and data.currentData.finishChainMap then ... end
    #     if data.currentData and data.currentData.sceneId then self._currentExploreId = ... end
    #     if data.sceneMap then GameStyle:valueReplace(data.sceneMap, self._sceneMap) end
    # 数据键名是 **ExploreData**（DevelopSystem:197-198）。
    #
    # exploreId 取 Explore.tsv 的 rowId（实测只有 F1/F2/F3 三个），
    # 其中 F1 的解锁条件是 C01S06，所以打过 C01S06 就该能进。
    EXPLORE_ALL = True

    def apply_explore_config(self):
        """生成 ExploreData，让「资源勘探」入口能打开。"""
        pl = self.table.get('10001', {}).get('data', {}).get('player')
        if not isinstance(pl, dict):
            return
        datas = pl.setdefault('datas', {})
        if not Server.EXPLORE_ALL:
            datas.pop('ExploreData', None)
            return

        ids = [r.get('rowId') for r in self.read_tsv('Explore.tsv')
               if r.get('rowId')]
        if not ids:
            return

        scene_map = {}
        for eid in ids:
            scene_map[eid] = {
                # 已完成的场景物件 / 任务链 / 条件表，空表 = 全都没做
                'finishObjects': {},
                'chainMap': {},
                'checkMap': {},
            }
        datas['ExploreData'] = {
            'sceneMap': scene_map,
            'currentData': {
                # 停在第一个，客户端 getCurrentExploreId() 要它
                'sceneId': ids[0],
                'chainMap': {},
                'finishChainMap': {},
            },
        }
        self.w('[勘探] ExploreData 下发 %d 个场景：%s（当前 %s）'
               % (len(scene_map), ', '.join(ids), ids[0]))

    # ------------------------------------------------------------------
    # 共鸣（PrismCoreData）
    # ------------------------------------------------------------------
    #
    # 现象：点共鸣报错
    #   PrismCoreModel.lua:440 getSkillInfoByType
    #     attempt to index local 'config' (a nil value)
    # 对应源码（:527-539）：
    #     local serverInfo = self:getBranchDataByType(ptype)
    #     local curId = serverInfo.skillId
    #     local config = ConfigReader:getRecordById("PrismCore", curId)
    #     return { mainId = config.SkillNode1[#config.SkillNode1], ... }
    #
    # 两个原因叠加：
    #   1) skillId 是 nil —— 我们下发的 categories[type].branch 里只有
    #      order/subOrder/totalCost/activeSkill，从来没有 skillId。
    #      getRecordById("PrismCore", nil) 返回 nil -> config.SkillNode1 崩。
    #      注意 skillId 要放在 **branch 里面**，因为
    #      getBranchDataByType(:186-190) 返回的是 `data.branch`：
    #          return data and data.branch or {}
    #   2) 就算填了，也只能填 SkillNode1 **非空**的记录。
    #      PrismCore.tsv 96 条里有 78 条 SkillNode1 是空数组，
    #      `config.SkillNode1[#config.SkillNode1]` 会取 nil 再索引，照样崩。
    #      实测每个 Type 只有 <TYPE>_F01S01 这一条安全。
    PRISMCORE_TYPES = ('FIRE', 'WIND', 'WATER', 'LIGHT', 'DARK', 'EARTH')

    def apply_prismcore_config(self):
        """给共鸣分支补 skillId / resetTimes，修掉 config 为 nil 的崩溃。"""
        pl = self.table.get('10001', {}).get('data', {}).get('player')
        if not isinstance(pl, dict):
            return
        pc = pl.setdefault('datas', {}).get('PrismCoreData')
        if not isinstance(pc, dict):
            pc = {'level': 0, 'star': 0, 'totalStar': 0,
                  'heroBeyond': {}, 'categories': {}}
            pl['datas']['PrismCoreData'] = pc
        cats = pc.setdefault('categories', {})

        # 每种 Type 挑一条 SkillNode1 非空的记录当 skillId
        safe = {}
        for r in self.read_tsv('PrismCore.tsv'):
            rid = r.get('rowId')
            if not rid or not (r.get('SkillNode1') or '').strip():
                continue
            t = r.get('Type') or ''
            try:
                o = int(float(r.get('Order') or 0))
            except Exception:
                o = 0
            if t not in safe or o < safe[t][0]:
                safe[t] = (o, rid)

        fixed, missing = [], []
        for t in Server.PRISMCORE_TYPES:
            c = cats.setdefault(t, {})
            # skillId 必须在 branch 里（getBranchDataByType 返回 data.branch）
            br = c.setdefault('branch', {})
            br.setdefault('order', 1)
            br.setdefault('subOrder', 0)
            br.setdefault('totalCost', 0)
            br.setdefault('activeSkill', 0)
            # getResetTimeByType(:50-58) 读的是 category 顶层的 resetTimes
            c.setdefault('resetTimes', 0)
            if t in safe:
                br['skillId'] = safe[t][1]
                # order 必须和 skillId 指向的那条节点对齐：原来填的 99
                # 远超 PrismCore 的节点数（每 Type 只有 16 个，Order 1..16），
                # checkActiveSkill(:221-224) 的 typeConfig[serverInfo.order]
                # 会取到 nil。它有 `info and ...` 兜底不崩，但状态是错的。
                br['order'] = safe[t][0]
                fixed.append('%s->%s(order=%d)' % (t, safe[t][1], safe[t][0]))
            else:
                missing.append(t)
        self.w('[共鸣] categories %d 类，skillId 补齐 %s%s'
               % (len(cats), ', '.join(fixed),
                  ('；无安全记录: %s' % missing) if missing else ''))

    # ------------------------------------------------------------------
    # 装备（EquipData）
    # ------------------------------------------------------------------
    #
    # 现象：打开装备详情界面直接报
    #   EquipAttributePanelWidget.lua:54: attempt to index field '_equip' (a nil value)
    #   :52  self._equip = self._equipSystem:getEquipById(data.uniqId)  -- 返回 nil
    #   :53  self._config = self._equip._config                         -- 崩
    #
    # 原因：**服务端从来没下发过 EquipData**。player.datas 里没有任何装备键，
    # 于是 EquipModel._equipList 恒为空表，getEquipById 必然返回 nil。
    # 报错链上 EquipInfoBaseWidget:29 也是同样的写法。
    #
    # 形状（取自反编译源码，不是猜的）：
    #   EquipModel:synchronize(:57-79)
    #       if data.equips then for id, v in pairs(data.equips) do
    #           self._equipList[id] = EquipModelBase:new(v) end end
    #       if data.limit and data.limit.limitLevel then ... end
    #   EquipModel:getEquipById(:109-113)   self._equipList[tostring(id)]
    #   EquipModelBase:initialize(:16-30)
    #       self._id = data.uniqId
    #       assert(data.equipId ~= nil, "equipId必须存在")
    #       self._config = ConfigReader:requireRecordById("Equipment", data.equipId)
    # 所以 equips = { uniqId: {uniqId, equipId, ...} }，
    # equipId 必须是 Equipment.tsv 的 rowId（客户端要能查到配置，否则 assert 崩）。
    #
    # 常用字段来自 EquipModelBase 的 self.xxx 读取统计：
    #   uniqId / equipId  必需
    #   star              getCurlLevel() 读它
    #   secondProp        getSecondProp():112
    #   fixProps          getFixProps():120
    #   heroId            装在谁身上；**留空 = 未装备**（:138 判 nil/""）
    # 这里一律留空 heroId：全部进背包但不穿戴，避免属性联动/战力重算的坑，
    # 也不会污染英雄面板数值（战斗数值由 PLAYER_ATTR 单独定）。
    EQUIP_ALL = True               # True = 按 EQUIP_PER_RARITY 下发
    EQUIP_PER_RARITY = 3           # 每种稀有度发几件（Equipment.tsv 共 441 件 / 11 档）
    EQUIP_MAX_STAR = 20            # star（强化等级）
    EQUIP_LIMIT_LEVEL = 20         # limit.limitLevel，突破上限

    def apply_equip_config(self):
        """生成 EquipData，修掉 getEquipById 返回 nil 导致的界面崩溃。"""
        pl = self.table.get('10001', {}).get('data', {}).get('player')
        if not isinstance(pl, dict):
            return
        datas = pl.setdefault('datas', {})

        all_rows = [r for r in self.read_tsv('Equipment.tsv') if r.get('rowId')]
        if not Server.EQUIP_ALL:
            datas.pop('EquipData', None)
            return

        rows = all_rows
        if Server.EQUIP_PER_RARITY:
            by_rar, sel = {}, []
            for r in all_rows:
                by_rar.setdefault(r.get('Rareity') or '', []).append(r)
            for rar in sorted(by_rar):
                sel.extend(by_rar[rar][:Server.EQUIP_PER_RARITY])
            rows = sel

        equips = {}
        for i, r in enumerate(rows, 1):
            uid = 'EQ%05d' % i
            equips[uid] = {
                'uniqId': uid,
                'equipId': r['rowId'],
                'star': Server.EQUIP_MAX_STAR,
                'secondProp': {},
                'fixProps': {},
            }
        datas['EquipData'] = {
            'equips': equips,
            'limit': {'limitLevel': Server.EQUIP_LIMIT_LEVEL},
        }
        self.w('[装备] EquipData 下发 %d/%d 件，limitLevel=%d'
               % (len(equips), len(all_rows), Server.EQUIP_LIMIT_LEVEL))

    # ------------------------------------------------------------------
    # 无限资源（独立配置项，与角色养成那套无关）
    # ------------------------------------------------------------------
    #
    # 【顺带修一个一直存在的结构错误】
    # 我们原先下发的 player.bag 是**扁平 map**：
    #     {"IR_Gold":{"count":999999,"uniqId":""}, ...}
    # 但客户端只认这个形状：
    #     DevelopSystem:137-138  if data.bag then self:getBag():synchronize(data.bag, isDiff) end
    #     Bag:synchronize:30-40
    #         if bagData.items then
    #             for k, v in pairs(bagData.items) do
    #                 self:syncBagPageItems(v.itemId or k, v)
    #             end
    #         end
    #     Bag:syncBagPageItems:42-71
    #         local configData = GameStyle:getItemConfig(itemId)
    #         if configData == nil or configData.Page == nil then return end   -- Page 为空直接跳过
    #         item.config = configData
    #         self._entryList[itemId] = item
    #         再按 configData.Page 分桶到 _resourceList / _charPieceList
    #                                / _otherList / _equipList
    # 即正确形状是 `bag.items`，而且 **Page 为空的物品会被丢弃**。
    # 因为缺 `items` 这一层，客户端的背包一直是空的（getCountById 恒为 0）。
    #
    # 物品清单来源 Item.tsv（451 行，全部有 Page）：
    #     RESOURCE 141 / OTHER 243 / CHAR_PIECE 61 / EQUIP 6
    #     CHAR_PIECE 就是 CharUpgrade.Cost 里用的 ICP_<heroId> 碎片（60 个）
    #     MaxPile = -1 的是货币（本就无上限）；活动材料多为 9999
    # ------------------------------------------------------------------
    RESOURCE_INFINITE = True       # 总开关
    RESOURCE_COUNT = 99999999      # 统一数量
    RESOURCE_PAGES = ('RESOURCE', 'CHAR_PIECE')   # 只对这些 Item.Page 生效；None = 全部
    RESOURCE_EXCLUDE_TYPES = ('RANDOM_CHEST', 'CHOICE_CHEST', 'HOURGLASS')  # 排除
    RESOURCE_SKIP_EXISTING = False  # True = 保留 JSON 里已有条目的 count
    RESOURCE_PLAYER_CURRENCY = True  # 同时拉满 player.coin / diamond / exp
    RESOURCE_CURRENCY_COUNT = 99999999

    def apply_resource_config(self):
        """按 RESOURCE_* 配置项生成 player.bag.items（无限资源）。"""
        player = self.table.get('10001', {}).get('data', {}).get('player')
        if not player:
            self.w('!! apply_resource_config: 10001.data.player 缺失')
            return
        if not Server.RESOURCE_INFINITE:
            self.w('[资源] RESOURCE_INFINITE=False，跳过')
            return

        # 兼容旧的扁平 bag：把已有条目搬进 items 层
        bag = player.setdefault('bag', {})
        if not isinstance(bag.get('items'), dict):
            bag['items'] = {}
        items = bag['items']
        legacy = 0
        for k in [k for k in bag if k != 'items']:
            v = bag.pop(k)
            if isinstance(v, dict):
                v.setdefault('itemId', k)
                items.setdefault(k, v)
                legacy += 1

        pages = Server.RESOURCE_PAGES
        excl = set(Server.RESOURCE_EXCLUDE_TYPES or ())
        added = kept = 0
        for r in self.read_tsv('Item.tsv'):
            iid = r.get('rowId')
            page = (r.get('Page') or '').strip()
            if not iid or not page:
                continue
            if pages is not None and page not in pages:
                continue
            if (r.get('Type') or '').strip() in excl:
                continue
            cur = items.get(iid)
            if cur is not None and Server.RESOURCE_SKIP_EXISTING:
                kept += 1
                continue
            items[iid] = {'itemId': iid, 'count': Server.RESOURCE_COUNT}
            # 刻意**不写** uniqId。客户端用 `if data.uniqId then` 区分
            # 「装备/芯片实例」和「普通道具」（BagMediator:208、
            # EquipInfoBaseWidget:28、BaseItemWidget:224），实例要能通过
            # getEquipById / getChipByUid 查到。而 Lua 里空字符串是真值，
            # 曾经写成 'uniqId': '' 导致普通道具被当成实例 ->
            # EquipAttributePanelWidget:53 的 self._equip._config 报
            # "attempt to index field '_equip' (a nil value)"。
            added += 1

        if Server.RESOURCE_PLAYER_CURRENCY:
            for k in ('coin', 'diamond', 'exp'):
                player[k] = Server.RESOURCE_CURRENCY_COUNT

        self.w('[资源] 无限资源=True count=%s pages=%s 排除类型=%s'
               % (Server.RESOURCE_COUNT, pages,
                  list(Server.RESOURCE_EXCLUDE_TYPES or ())))
        self.w('[资源] 旧扁平条目迁移 %d 个；新增/覆盖 %d 个，保留 %d 个，共 %d 项'
               % (legacy, added, kept, len(items)))
        if Server.RESOURCE_PLAYER_CURRENCY:
            self.w('[资源] player.coin/diamond/exp = %s'
                   % Server.RESOURCE_CURRENCY_COUNT)

    # ------------------------------------------------------------------
    # 主页/个人空间 SettingInfo
    #
    # 现象：点主页入口崩
    #   SiteModel.lua:115 bad argument #1 to 'pairs' (table expected, got nil)
    #   链：HomeCenterWidget:114 handleClick -> SiteSystem:114 -> SiteModel:344 getUserSite
    #       -> SiteModel:53 initData -> SitePlayerPageWidget:36 initialize
    #       -> SiteMainMediator:68 enterWithData
    #
    # 根因：
    #   SiteModel:114-122 getAllBackGround()
    #       for k, v in pairs(self._setverSettingInfo.allBackGround) do   -- nil -> 崩
    #   而 SiteModel:38 initialize 里 `self._setverSettingInfo = {}`，
    #   只有收到服务端数据才会有内容：
    #       DevelopSystem:242-243
    #           if otherDatas and otherDatas.SettingInfo then
    #               self:getSiteModel():synchronizeSettingInfo(otherDatas.SettingInfo)
    #           end
    #       SiteModel:60-65 synchronizeSettingInfo -> GameStyle:valueReplace(...)
    #
    # SettingInfo 各字段的必需性（全工程 grep 结果）：
    #   allBackGround  SiteModel:117  pairs(...)          **无保护，必须给表**
    #   backGround     SiteModel:125  == ""                nil 安全（走 ConfigValue 默认）
    #   position       SiteModel:135  type(...) ~= "table" 有保护
    #   achieveMedals  SiteSystem:556 消费方 SuccessWallMedalWidget:16/126 有 `or {}` 兜底
    #
    # allBackGround 的键来自 ShowBackGround.tsv（实测只有 1 行 BackGround1），
    # 默认背景取 ConfigValue.tsv 的 Common_ShowBackGround = "BackGround1"。
    # 注意 SiteSystem:359 会把 getAllBackGround() 的**全部键**上报服务器，
    # 所以这里只填配置表里真实存在的 id，不编造。
    # ------------------------------------------------------------------
    SITE_SETTING_INFO = True        # 是否下发 datas.SettingInfo
    SITE_BACKGROUND_KEYS = None     # allBackGround 的键；None = 取 ShowBackGround.tsv 全部
    SITE_BACKGROUND_VALUE = True    # allBackGround 每个键的值
    SITE_BACKGROUND = ""            # backGround；"" = 用 ConfigValue 的 Common_ShowBackGround
    # achieveMedals：**必须是表**。
    #   SiteSystem:555-559  getMedals() = getSetverSettingInfo().achieveMedals
    #   SuccessWallMedalWidget:125-138  updateView(medals)
    #       self._medals = medals or self._siteSystem:getMedals()   -- :126 没有 `or {}`
    #       for k2, v2 in pairs(self._medals) do                     -- :138 pairs(nil) 崩
    # 注意 :16（initialize）**有** `or {}`，但 :126（updateView）没有，
    # 所以不能因为 initialize 兜底过就认为可以不传。
    # 形状：medals[medalId] = index，index 是墙上的槽位号
    #   SuccessWallMedalWidget:10   local WallMaxNum = 13
    #   SuccessWallMedalWidget:202  newMedals[targetIndex.medalId] = self._moveMedalData.index
    # 奖章 id 来自 AchievementMedal.tsv（17 个）。
    SITE_MEDALS = None              # None = 只发空表 {}（最小改动，仅防崩）
    SITE_MEDALS_FILL_ALL = False    # True = 按 AchievementMedal.tsv 的 order 填满前 N 个
    SITE_MEDALS_MAX = 13            # 墙上槽位数（WallMaxNum）

    # ------------------------------------------------------------ 抽卡池开关
    GACHA_OPEN_TYPES = ('UP',)      # 要打开哪些 Type 的卡池；UP=95 个（DoubleUp 56 + SingleUp 39）
    GACHA_ALWAYS_OPEN = ('Gacha_Base',)   # 不在这个 Type 里、但也要常开
    GACHA_TICKET_COUNT = 999999    # 抽卡令牌的堆叠数量
    #   两种券（IM_GachaTicket / IM_GachaTicket_Limited）在 Item.tsv 里都是
    #   Page=OTHER，而无限资源只覆盖 RESOURCE / CHAR_PIECE 两个 Page，
    #   所以限定券压根不在背包里 —— 客户端 CardPoolSystem:checkCostItemEnough
    #   会直接拦下请求，池子开了也点不动。这里按 Gacha.tsv 的 Coupon 列补齐。

    GACHA_DISPLAY_KEYS = ('promImage', 'Bg', 'normal', 'normal2', 'normal3',
                          'hero_a', 'hero_b', 'arrow', 'tab', 'banner')

    # 客户端 assets.db 里**不存在**的抽卡图（由 GACHA_APK_SCAN 扫出来固化在此，
    # 见 MEMORY 47 节）。引用了它们的卡池一打开，HomeCardPoolWidget:148 的
    # ccui.Scale9Sprite:create(path) 就返回 nil -> "attempt to index local 'backImg'"。
    # 引用数：arrow_3 = 29 个池、arrow_18 = 8 个、18 = 3 个、arrow_1 = 3 个、
    #         arrow_2 = 3 个、20 = 1 个、19 = 1 个
    GACHA_MISSING_IMG = (
        'recuit_show_icon_arrow_1', 'recuit_show_icon_arrow_2',
        'recuit_show_icon_arrow_3', 'recuit_show_icon_arrow_18',
        'recuit_show_18', 'recuit_show_19', 'recuit_show_20',
    )

    GACHA_APK_SCAN = True       # 若能找到原版 APK，再现扫一次补全缺图名单
    GACHA_APK_PATHS = (
        r'D:\Temp\yqlr\yqlr_2.2.2_9game.apk',
        r'D:\Temp\yqlr\_out_repack\yqlr_v5_dev.apk',
    )
    GACHA_ASSET_DBS = ('assets/32/assets.db', 'assets/64/assets.db')

    def gacha_scan_missing_img(self):
        """扫原版 APK 的 assets.db，列出 Gacha.tsv 引用但客户端缺失的抽卡图。

        GACHA_MISSING_IMG 是这份名单的固化副本；这里现扫是为了 APK 换版本时
        名单能自动跟上。扫不到（没装 APK / 没开 GACHA_APK_SCAN）就只用固化名单。
        """
        if not self.GACHA_APK_SCAN:
            return set(self.GACHA_MISSING_IMG)
        import zipfile
        have = set()
        for apk in self.GACHA_APK_PATHS:
            if not os.path.exists(apk):
                continue
            try:
                z = zipfile.ZipFile(apk)
                for db in self.GACHA_ASSET_DBS:
                    if db in z.namelist():
                        have |= set(re.findall(
                            rb'recuit_show_[a-zA-Z0-9_]+', z.read(db)))
                z.close()
            except Exception as ex:
                self.w('[抽卡] 扫 %s 失败: %r' % (os.path.basename(apk), ex))
        if not have:
            return set(self.GACHA_MISSING_IMG)
        have = set(h.decode() for h in have)
        miss = set()
        for cfg in self.gacha.gacha.values():
            for k in self.GACHA_DISPLAY_KEYS:
                v = cfg.get(k)
                if v and v.startswith('recuit') and v not in have:
                    miss.add(v)
        if miss != set(self.GACHA_MISSING_IMG):
            self.w('[抽卡] 现扫缺图名单与固化名单不同：多 %s / 少 %s'
                   % (sorted(miss - set(self.GACHA_MISSING_IMG)),
                      sorted(set(self.GACHA_MISSING_IMG) - miss)))
        return miss

    def apply_gacha_config(self):
        """把 Gacha.tsv 里符合条件的的卡池全部置 open，并补齐抽卡令牌。

        必须排在 apply_resource_config 之后：那时 bag.items 才刚建好。
        """
        if not self.gacha.ok:
            self.w('[抽卡] 表没加载，跳过卡池开关')
            return
        p = self.table.get('10001')
        if not isinstance(p, dict):
            self.w('[抽卡] 10001 不存在，跳过')
            return
        datas = p.get('data', {}).get('player', {}).get('datas')
        if not isinstance(datas, dict):
            self.w('[抽卡] 10001.data.player.datas 不存在，跳过')
            return
        gd = datas.setdefault('GachaponData', {})
        infos = gd.setdefault('gachaponInfos', {})

        want = []
        missing_img = self.gacha_scan_missing_img()
        skipped = []
        for gid, cfg in self.gacha.gacha.items():
            if not (cfg.get('Type') in self.GACHA_OPEN_TYPES
                    or gid in self.GACHA_ALWAYS_OPEN):
                continue
            bad = [cfg.get(k) for k in self.GACHA_DISPLAY_KEYS
                   if cfg.get(k) and cfg.get(k).startswith('recuit')
                   and cfg.get(k) in missing_img]
            if bad:
                skipped.append((gid, bad))
                continue
            want.append(gid)

        for gid in want:
            cur = infos.get(gid)
            if not isinstance(cur, dict):
                cur = {}
                infos[gid] = cur
            cur['open'] = True
            cur.setdefault('today', 0)
            cur.setdefault('ten', 0)
            cur.setdefault('total', 0)

        # 没打开的池子必须显式置 open=false，否则会沿用表里的旧值
        for gid in self.gacha.gacha:
            if gid not in want and isinstance(infos.get(gid), dict):
                infos[gid]['open'] = False

        # 补齐这些池子要用的券，否则客户端点不动
        coupons = sorted(set(self.gacha.gacha[g]['Coupon']
                             for g in want
                             if g in self.gacha.gacha and self.gacha.gacha[g].get('Coupon')))
        items = p['data']['player'].get('bag', {}).get('items')
        added = []
        if isinstance(items, dict):
            for c in coupons:
                if c not in items:
                    items[c] = {'count': self.GACHA_TICKET_COUNT,
                                'itemId': c}
                    # 同 apply_resource_config：不写 uniqId，空串是 Lua 真值，
                    # 会被客户端误判成装备/芯片实例。
                    added.append(c)
                elif items[c].get('count', 0) < self.GACHA_TICKET_COUNT:
                    items[c]['count'] = self.GACHA_TICKET_COUNT
                    added.append(c)

        self.w('[抽卡] 打开 %d 个卡池，跳过 %d 个（引用了客户端缺失的图 %s）'
               % (len(want), len(skipped), sorted(missing_img)))
        for gid, bad in skipped[:6]:
            self.w('        跳过 %-30s 缺 %s' % (gid, ','.join(bad)))
        if len(skipped) > 6:
            self.w('        ... 另有 %d 个同类' % (len(skipped) - 6))
        self.w('[抽卡] 券 %s 补齐 %d 个 -> %s'
               % (coupons, len(added), added or '无'))

    def apply_site_config(self):
        """下发 datas.SettingInfo，避免 SiteModel:getAllBackGround 的 pairs(nil)。"""
        player = self.table.get('10001', {}).get('data', {}).get('player')
        if not player:
            return
        if not Server.SITE_SETTING_INFO:
            self.w('[空间] SITE_SETTING_INFO=False，跳过')
            return
        keys = Server.SITE_BACKGROUND_KEYS
        if keys is None:
            keys = [r['rowId'] for r in self.read_tsv('ShowBackGround.tsv')
                    if r.get('rowId')]
        info = {'allBackGround': {k: Server.SITE_BACKGROUND_VALUE for k in keys},
                'backGround': Server.SITE_BACKGROUND}
        if Server.SITE_MEDALS is not None:
            info['achieveMedals'] = Server.SITE_MEDALS
        elif Server.SITE_MEDALS_FILL_ALL:
            rows = [r for r in self.read_tsv('AchievementMedal.tsv')
                    if r.get('rowId')]
            rows.sort(key=lambda r: int(r.get('order') or 0))
            info['achieveMedals'] = {
                r['rowId']: i + 1
                for i, r in enumerate(rows[:Server.SITE_MEDALS_MAX])
            }
        else:
            # 最小改动：发空表。nil 会让 SuccessWallMedalWidget:138 的 pairs 崩。
            info['achieveMedals'] = {}
        player.setdefault('datas', {})['SettingInfo'] = info
        self.w('[空间] SettingInfo 已下发：allBackGround 键 %s，backGround=%r'
               % (keys, Server.SITE_BACKGROUND))
        self.w('[空间] achieveMedals %s（%d 项）'
               % ('已预填' if Server.SITE_MEDALS_FILL_ALL else '空表',
                  len(info['achieveMedals'])))

    # ------------------------------------------------------------------
    # 引导进度：必须由服务端下发，否则第二关引导会死循环。
    #
    # 客户端判定（yq/gameplay/guide/view/GuideWidget.lua:436-448）：
    #     local last    = self._guideSystem:getFinishLastGuideId(GroupId)
    #     local server  = self._guideSystem:getFinishServerLastGuideId(GroupId)
    #     local serverConfigOrder = server and GameStyle:getGuideById(server).Order or 0
    #     if saveConfig.Order <= serverConfigOrder then
    #         self._guideSystem:setFinishLastGuideId(curGuideData.Id)  -- 本地直接推进
    #         callbackfinsh()
    #     else
    #         self._guideSystem:finshGuide({ curGuideData.Id }, callbackfinsh)  -- 去问服务端
    #     end
    #
    # 而 GuideSystem:requestGuideToServer（GuideSystem.lua:576-586）只判 resCode
    # 就回调，**不读 guideData**。guideData 只有一个消费点：
    #     DevelopSystem.lua:95-97   if data.guideData then ... synchronize(data.guideData) end
    # 也就是必须放在玩家同步里（10001.data.player.guideData），形状是
    #     { [GroupId] = { guideId = "Guide1_StepXX" } }
    #
    # 我们以前从不下发 -> serverConfigOrder 恒为 0 -> 每一步都走 finshGuide ->
    # 服务端仍不回 -> 进度永远记不上 -> 引导回到组内起点（Guide1_Step16）无限重播。
    # 实测日志：Step19→…→Step35_1，然后 Step16→17→…→Step35_1，循环。
    #
    # 这里记录 10027（上报引导步）里出现过的最大 Order，并在 10001 里回下发。
    # ------------------------------------------------------------------
    # ------------------------------------------------------------ 调试活动
    #
    # 往 ActivityData 里塞一个调试活动，作为「服务端配置」的入口。
    #
    # 光下发 ActivityData 不够：ActivityList:syncAloneActivity(:27-42) 会先拿 id
    # 去 ConfigReader:requireRecordById("Activity", id) 查配置行，
    # 查不到就走 `else` 分支里的 `if config then`，即**整条被静默丢弃**。
    # 所以客户端侧还得运行时往 ConfigReader 的 Activity 表里注入一行
    # （见 build_patched_luac.py 的 patch_debug_activity），两边配套才生效。
    #
    # 字段含义来自 BaseActivity:synchronize(:40-67)：status / showOpenTime /
    # showCloseTime / actualOpenTime。status 决定 _isTodayOpen。
    DEBUG_ACTIVITY_ID = 'Activity_Debug_Config'
    DEBUG_ACTIVITY_SEND = True

    def apply_debug_activity(self):
        if not self.DEBUG_ACTIVITY_SEND:
            return
        player = self.table.get('10001', {}).get('data', {}).get('player')
        if not player:
            return
        # 同样要嵌套在 activities 里（DevelopSystem:262-263），理由见
    # apply_banner_activity 的注释。
        ad = player.setdefault('datas', {}).setdefault(
            'ActivityData', {}).setdefault('activities', {})
        # 宽时间窗：DebugBox 是开发期工具，不该被活动周期卡住。
        now = Server.server_time_ms()
        ad[self.DEBUG_ACTIVITY_ID] = {
            'id': self.DEBUG_ACTIVITY_ID,
            'status': 1,
            'showOpenTime': now - 86400000,
            'showCloseTime': now + 365 * 86400000,
            'actualOpenTime': now - 86400000,
        }
        self.w('[活动] 已下发调试活动 %s' % self.DEBUG_ACTIVITY_ID)

    # ------------------------------------------------------------ 限时活动 banner
    #
    # 主页右上角第一个图标（秒表样式）对应 KRightListData[1]：
    #     btnType = "Banner", funcCallback = "bannerCallback"
    # 点它走 HomeCenterWidget:showActivityList() -> activityView /
    # ActivityMediator -> EVT_SHOW_POPUP。
    #
    # 弹窗内容由 ActivityMediator:145-156 决定：
    #     _bannerSystem:getBannerListData() 里 icon[1].ListRes 非空的项
    # 而 BannerSystem:41-59 的 bannerlist 来自：
    #     1. activity:getIsTodayOpen() == 1     <- BaseActivity:53 读 data.status
    #     2. activityCfg.Icon ~= ""           <- Activity.tsv 的 Icon 列
    #
    # 之前这个弹窗是**白板**，原因就是两个条件都不满足：
    #   - 表里原有的 3 个活动（Activity_MainLineFund / Activity_TowerFund /
    #     Activity_Deposit）都没带 status -> getIsTodayOpen() 恒为
    #     STATUS_INIT(0) != 1 -> 一个都进不了列表；
    #   - 调试活动带了 status=1，但配置行 Icon = "" -> BannerSystem:50 挡掉。
    #
    # 下面这几个都是 Activity.tsv 里**真实存在**的 Limit 类活动，
    # 它们的 Icon[1].ListRes 非空，且 Config 指向的 ActivityConfig 行都存在
    # （BaseActivity:_getActivityConfig:157 对缺失的 configId 是 assert，
    # 选之前逐个核对过）。LimitActivityMode 是 BaseActivity 的空壳
    # （LimitActivityMode.lua 全文 21 行，只覆写 synchronize/getViewName），
    # 不读额外的服务端子表，最不容易炸。
    BANNER_ACTIVITY_IDS = (
        'Activity_CharUpgrade',
        'Activity_PVP',
        'Activity_StarField1',
    )
    BANNER_SEND = True

    def apply_banner_activity(self):
        if not self.BANNER_SEND:
            return
        player = self.table.get('10001', {}).get('data', {}).get('player')
        if not player:
            return
        acts = self.read_tsv('Activity.tsv')
        by_id = {r.get('rowId'): r for r in acts if r.get('rowId')}
        # **必须是嵌套一层的 activities**（DevelopSystem:262-263）：
        #     if otherDatas and otherDatas.ActivityData
        #        and otherDatas.ActivityData.activities then
        #         self:getActivityList():synchronize(otherDatas.ActivityData.activities)
        # 扁平写成 ActivityData:{id:{...}} 的话，`and ....activities` 直接短路，
        # synchronize 一次都不会被调用 —— 于是 status 永远读不到，
        # getIsTodayOpen() 恒为 STATUS_INIT，banner 列表恒空。
        # （曾因此排查半天：服务端日志显示数据已下发，客户端却一条活动都没有。）
        ad = player.setdefault('datas', {}).setdefault(
            'ActivityData', {}).setdefault('activities', {})

        # 表里原有的 3 个占位活动原本是**扁平**写在 ActivityData 顶层的。
        # 客户端只读 activities（DevelopSystem:262-263），所以它们从来没被
        # synchronize 过 —— 一直是"存在但无效"的状态（历史上靠
        # ActivityList 的 nil 补丁容忍）。既然现在层级对了，就一并搬进来，
        # 免得顶层残留同 id 的旧副本造成两处数据不一致。
        for legacy in ('Activity_MainLineFund', 'Activity_TowerFund',
                       'Activity_Deposit'):
            if legacy in player['datas']['ActivityData']:
                moved = player['datas']['ActivityData'].pop(legacy)
                ad.setdefault(legacy, moved)
                self.w('[活动] 占位活动 %s 从顶层搬进 activities' % legacy)
        now = Server.server_time_ms()
        sent = []
        for aid in self.BANNER_ACTIVITY_IDS:
            cfg = by_id.get(aid)
            if not cfg:
                self.w('[活动] !! %s 不在 Activity.tsv 里，跳过' % aid)
                continue
            # 先自检 Icon[1].ListRes：没有它进了 banner 列表也渲染不出图标，
            # 等于白下发。
            try:
                icon = json.loads(cfg.get('Icon') or '')
            except Exception:
                icon = None
            if not (isinstance(icon, list) and icon
                    and isinstance(icon[0], dict) and icon[0].get('ListRes')):
                self.w('[活动] !! %s 的 Icon[1].ListRes 为空，跳过' % aid)
                continue
            ad[aid] = {
                'id': aid,
                'status': 1,
                'showOpenTime': now - 86400000,
                'showCloseTime': now + 365 * 86400000,
                'actualOpenTime': now - 86400000,
            }
            sent.append('%s(%s)' % (aid, icon[0]['ListRes']))
        self.w('[活动] banner 下发 %d 个: %s' % (len(sent), ', '.join(sent)))

    GUIDE_STEP_RE = re.compile(rb'Step[\w.]+')
    _guide_order = None
    _guide_suffix = None

    def guide_orders(self):
        if Server._guide_order is not None:
            return Server._guide_order
        import csv as _csv
        out = {}
        try:
            with io.open(os.path.join(Server.TABLES_DIR, 'Guide.tsv'),
                         encoding='utf-8') as f:
                for row in _csv.DictReader(f, delimiter='\t'):
                    try:
                        out[row['rowId']] = int(row['Order'])
                    except Exception:
                        pass
        except Exception as ex:
            self.w('!! 读 Guide.tsv 失败 %r' % ex)
        Server._guide_order = out
        # 后缀 -> rowId。ver=116 的请求里 guideId 是编码过的
        # （"G<01><15>X1_Step16" 实为 "Guide1_Step16"，u/i/d 被替换），
        # 但 `StepNN` 这段始终是明文，所以用后缀反查完整 rowId 最稳。
        suf = {}
        for gid in out:
            k = gid[gid.index('_') + 1:] if '_' in gid else gid
            suf.setdefault(k, gid)
        Server._guide_suffix = suf
        self.w('引导步配置载入 %d 条（后缀索引 %d 条）' % (len(out), len(suf)))
        return out

    def resolve_guide_id(self, raw):
        """从任意形态的 app 载荷里还原 guideId 列表。"""
        orders = self.guide_orders()
        suf = Server._guide_suffix or {}
        found = []
        for m in Server.GUIDE_STEP_RE.finditer(raw or b''):
            k = m.group(0).decode('ascii', 'replace')
            gid = suf.get(k)
            if gid:
                found.append(gid)
        return found

    def track_guide(self, raw):
        """从**app 信封**里抓 guideId，记下 Order 最大的一条。

        踩过的坑（两个）：
        1) 最初传 `req['body']`，但 10027 的 body 长度是 0，guideId 在 app 信封里：
               app: ver=116 rid='ster_11{"guides":[...,"guideId":"Guide1_Step35_1",...]}'
               params(raw 0 B):
           app 信封由 parse_app_body 拆出，返回 (ver, rid, rest, tail)，有用的是 rest。
        2) ver=116 时 guideId 是**编码过的**（"G<01><15>X1_Step16" 实为 "Guide1_Step16"），
           ver=9 时才是明文。所以不匹配完整 id，只匹配 `StepNN` 后缀再回查 Guide.tsv。
        """
        cur = getattr(self, '_guide_seen', None)
        if cur is None:
            cur = {}
            self._guide_seen = cur
        orders = self.guide_orders()
        if isinstance(raw, str):
            raw = raw.encode('utf-8', 'replace')
        changed = False
        for gid in self.resolve_guide_id(raw):
            o = orders.get(gid)
            if o is None:
                continue
            g = gid.split('_')[0]
            if cur.get(g, -1) < o:
                cur[g] = o
                changed = True
        if changed:
            self.w('   引导进度推进: %s' % ', '.join(
                '%s=%d' % (g, o) for g, o in sorted(cur.items())))
            self.save_guide_state(cur)
        return cur

    # 引导进度落盘：mock 重启不应该把进度清零。
    # 否则每次重启 mock，10001 就下发不了 guideData，
    # 客户端 getWorkingGuide() 返回 nil -> 引导从 GUIDE1_BEGINGUIDE 全量重放。
    GUIDE_STATE_PATH = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'guide_state.json')

    def load_guide_state(self):
        try:
            with io.open(Server.GUIDE_STATE_PATH, encoding='utf-8') as f:
                st = json.load(f)
            if isinstance(st, dict) and st:
                self._guide_seen = {str(k): int(v) for k, v in st.items()}
                self.w('   载入引导进度: %s' % json.dumps(self._guide_seen))
        except Exception:
            pass
        return getattr(self, '_guide_seen', None)

    @staticmethod
    def save_guide_state(state):
        try:
            tmp = Server.GUIDE_STATE_PATH + '.tmp'
            with io.open(tmp, 'w', encoding='utf-8') as f:
                json.dump({str(k): int(v) for k, v in state.items()}, f)
            if os.path.exists(Server.GUIDE_STATE_PATH):
                os.remove(Server.GUIDE_STATE_PATH)
            os.rename(tmp, Server.GUIDE_STATE_PATH)
        except Exception as ex:
            pass

    # 主屏助理落盘。10038 changeHero 改的是 Player 上的
    # _mainScreenHeroId / _mainScreenType，重启 mock 不该把它打回表里的初值。
    MAIN_SCREEN_STATE_PATH = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'main_screen_state.json')

    def load_main_screen(self):
        try:
            with io.open(Server.MAIN_SCREEN_STATE_PATH, encoding='utf-8') as f:
                st = json.load(f)
            if isinstance(st, dict) and st.get('heroId'):
                self.main_screen = {'heroId': st['heroId'],
                                    'type': st.get('type') or 'Por_Spine'}
                self.w('   载入主屏助理: %s' % json.dumps(
                    self.main_screen, ensure_ascii=False))
        except Exception:
            pass
        return self.main_screen

    @staticmethod
    def save_main_screen(state):
        try:
            tmp = Server.MAIN_SCREEN_STATE_PATH + '.tmp'
            with io.open(tmp, 'w', encoding='utf-8') as f:
                json.dump(state, f, ensure_ascii=False)
            if os.path.exists(Server.MAIN_SCREEN_STATE_PATH):
                os.remove(Server.MAIN_SCREEN_STATE_PATH)
            os.rename(tmp, Server.MAIN_SCREEN_STATE_PATH)
        except Exception as ex:
            pass

    # ------------------------------------------------------------ 主线进度落盘
    #
    # 14003 结算会把 CampaignData.lastPassed 写回 table['10001']（内存），
    # 重启 mock 就退回 opcodes_table.json 里的初值 C00S01 —— 玩家刚打通的关
    # 卡白打了。参照 main_screen_state.json 的做法单独落盘。
    #
    # 只存「已通关关卡」这一个事实，lastPassed/branchLastPassed 都是从它
    # 推出来的，避免存四份互相打架的字段。
    CAMPAIGN_STATE_PATH = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'campaign_state.json')

    def load_campaign_state(self):
        """读回已通关进度并写进 10001 表。"""
        try:
            with io.open(Server.CAMPAIGN_STATE_PATH, encoding='utf-8') as f:
                st = json.load(f)
        except Exception:
            return
        if not isinstance(st, dict):
            return
        passed = st.get('passed')
        if not passed:
            return
        if isinstance(passed, str):
            passed = [passed]
        passed = [p for p in passed if isinstance(p, str)]
        if not passed:
            return
        # 先灌进集合，后续 14003 追加时才能带上历史关卡
        self.campaign_passed.update(passed)
        # 取 Order 最靠后的那一关作为 lastPassed
        best = max(passed, key=lambda s: self.campaign_order_rank(s))
        pl = self.table.get('10001', {}).get('data', {}).get('player')
        if not isinstance(pl, dict):
            return
        cd = pl.setdefault('datas', {}).setdefault('CampaignData', {})
        cd.update(self.build_campaign_progress(best))
        # branchLastPassed 按章节各自取最靠后的
        blp = {}
        for p in passed:
            ch = self.campaign_chapter(p)
            if ch and blp.get(ch, '') and \
                    self.campaign_order_rank(blp[ch]) > self.campaign_order_rank(p):
                continue
            if ch:
                blp[ch] = p
        if blp:
            cd['branchLastPassed'] = blp
        self.w('[进度] 载入已通关 %d 关，lastPassed=%s' % (len(passed), best))

    @staticmethod
    def save_campaign_state(passed):
        try:
            tmp = Server.CAMPAIGN_STATE_PATH + '.tmp'
            with io.open(tmp, 'w', encoding='utf-8') as f:
                json.dump({'passed': sorted(set(passed))}, f, ensure_ascii=False)
            if os.path.exists(Server.CAMPAIGN_STATE_PATH):
                os.remove(Server.CAMPAIGN_STATE_PATH)
            os.rename(tmp, Server.CAMPAIGN_STATE_PATH)
        except Exception as ex:
            pass

    def campaign_chapter(self, stage_id):
        for _o1, _o2, rid, ch in self.campaign_order():
            if rid == stage_id:
                return ch
        return ''

    def campaign_order_rank(self, stage_id):
        """Order 序号；越大越靠后。未知关卡返回 -1。"""
        for o1, o2, rid, _ch in self.campaign_order():
            if rid == stage_id:
                return o1 * 10000 + o2
        return -1

    # ------------------------------------------------------------ 调试面板可调配置
    #
    # 客户端自带的 DebugBox 面板（yq/debug/debugBox/）用 opcode 10032 发
    # {cmd = {FuncName, 参数...}}，应答里的 d.player 会走
    # Service.lua:71-77 -> syncPlayer 自动同步回客户端，所以改完直接回
    # 一份新的 player 就能看到效果。
    #
    # 这些开关本来就都是 Server 的**类属性**，apply_*() 里按 Server.X 读，
    # 所以运行时 setattr 就够了 —— 不用改 apply_*() 里的任何一行，
    # 改完重跑对应的 apply_*() 重新生成 table['10001'] 即可。
    #
    # 白名单是刻意的：下面这些**不开放**，改了会直接把客户端打崩，
    # 源码里的理由写在各自 apply_*() 的注释里：
    #   HERO_PERSONALITY_MAP  必须 True（HeroInfoMediator:1478 等 7 处无保护读取）
    #   HERO_PERSONALITY_KEYS / HERO_RESOURCE_KEYS  结构键，不是开关
    #   HERO_KEEP_EXISTING    内部实现细节，改了会和增量逻辑打架
    #   RESOURCE_PAGES / RESOURCE_EXCLUDE_TYPES      结构范围
    #   LADDER_TYPES / LADDER_REWARD_TSV            结构来源
    DEBUG_TOGGLES = {
        # ---- 角色 ----
        'HERO_UNLOCK_ALL': bool,
        'HERO_MAX_LEVEL': bool,
        'HERO_MAX_RANK': bool,
        'HERO_MAX_STAR': bool,
        'HERO_MAX_FAVOR': bool,
        'HERO_MAX_BEYOND_UP': bool,
        'HERO_UNLOCK_RESOURCES': bool,
        'HERO_LEVEL_CAP': int,
        'HERO_RANK_CAP': int,
        'HERO_STAR_CAP': int,
        'HERO_BEYOND_UP_CAP': int,
        'HERO_SET_EXP': int,
        'HERO_RESOURCE_VALUE': int,
        # ---- 资源 ----
        'RESOURCE_INFINITE': bool,
        'RESOURCE_COUNT': int,
        'RESOURCE_PLAYER_CURRENCY': bool,
        'RESOURCE_CURRENCY_COUNT': int,
        'RESOURCE_SKIP_EXISTING': bool,
        # ---- 天梯 ----
        'LADDER_ORDER': int,
    }

    # 改了这些键需要重跑哪个 apply_*()
    DEBUG_TOGGLE_APPLY = (
        ('HERO_', 'apply_hero_config'),
        ('RESOURCE_', 'apply_resource_config'),
        ('LADDER_', 'apply_ladder_config'),
    )

    DEBUG_CONFIG_PATH = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'debug_config.json')

    def apply_for_key(self, key):
        for prefix, fn in self.DEBUG_TOGGLE_APPLY:
            if key.startswith(prefix):
                return fn
        return None

    def cast_toggle(self, key, raw):
        """按白名单声明的类型转换面板传来的字符串。"""
        caster = self.DEBUG_TOGGLES[key]
        if caster is bool:
            if isinstance(raw, bool):
                return raw
            s = str(raw).strip().lower()
            if s in ('true', '1', 'yes', 'on'):
                return True
            if s in ('false', '0', 'no', 'off', ''):
                return False
            raise ValueError('%r 不是布尔值' % (raw,))
        if isinstance(raw, bool):
            raise ValueError('%r 不是整数' % (raw,))
        # 这四个键的 None 含义是"不覆盖，取配置表推导出的上限"。
        # debug_config.json 里 None 落盘成 JSON null，读回来就是 Python None，
        # 不能拿它去 int()。
        if raw is None and key in ('HERO_LEVEL_CAP', 'HERO_RANK_CAP',
                                   'HERO_STAR_CAP', 'HERO_BEYOND_UP_CAP'):
            return None
        n = int(str(raw).strip())
        # 空串/0 同样表达"不覆盖"
        if n <= 0 and key in ('HERO_LEVEL_CAP', 'HERO_RANK_CAP',
                              'HERO_STAR_CAP', 'HERO_BEYOND_UP_CAP'):
            return None
        return n

    def load_debug_config(self):
        try:
            with io.open(Server.DEBUG_CONFIG_PATH, encoding='utf-8') as f:
                st = json.load(f)
        except Exception:
            st = None
        if not isinstance(st, dict):
            st = {}
        bad = [k for k in st if k not in self.DEBUG_TOGGLES]
        if bad:
            self.w('!! debug_config.json 里有不认识的键，忽略: %s' % bad)
        applied = {}
        for k, v in st.items():
            if k not in self.DEBUG_TOGGLES:
                continue
            try:
                val = self.cast_toggle(k, v)
            except Exception as ex:
                self.w('!! debug_config.json 里 %s=%r 无法解析，忽略: %r' % (k, v, ex))
                continue
            setattr(Server, k, val)
            applied[k] = val
        if applied:
            self.w('调试配置载入 %d 项: %s' % (len(applied), json.dumps(applied)))
        return applied

    def save_debug_config(self):
        st = {k: getattr(Server, k) for k in self.DEBUG_TOGGLES}
        try:
            tmp = Server.DEBUG_CONFIG_PATH + '.tmp'
            with io.open(tmp, 'w', encoding='utf-8') as f:
                json.dump(st, f, ensure_ascii=False, indent=1, sort_keys=True)
            if os.path.exists(Server.DEBUG_CONFIG_PATH):
                os.remove(Server.DEBUG_CONFIG_PATH)
            os.rename(tmp, Server.DEBUG_CONFIG_PATH)
        except Exception as ex:
            self.w('!! debug_config.json 落盘失败: %r' % (ex,))

    def rebuild_player(self):
        """按当前开关重新生成 10001 的 player 整块，并返回它。"""
        self.load_table()
        self.apply_hero_config()
        self.apply_team_config()
        self.apply_ladder_config()
        self.apply_explore_config()
        self.apply_prismcore_config()
        self.apply_equip_config()
        self.apply_resource_config()
        return self.table.get('10001', {}).get('data', {}).get('player') or {}

    # [调引导] 恢复点封顶。
    # 客户端只用服务端 guideData 里的 guideId 做**登录恢复**：
    #   MainSceneMediator.lua:307-314
    #       lastId = getWorkingGuide("Guide1")
    #       guideId = GameStyle:getGuideById(lastId).ForcedGuideId
    # 即"恢复点 = 上次完成步的 ForcedGuideId"，不是上次完成步本身。
    #
    # 之前报的是 Guide1_Step35_1(Order=33)，它的 ForcedGuideId=Guide1_Step35(点开始战斗)，
    # 于是重登直接跳到 Step35，**中间的 Step29(点 _guide_ChuanSJ 拖戈琳进编队) 被跳过**，
    # 编队里没人 -> "点开始战斗会缺人"。
    #
    # Guide1_Step27(Order=28) 的 ForcedGuideId=Guide1_Step29，
    # 所以把上报进度封顶到 28，恢复点就落在 Step29，引导会把 29/34 补跑一遍，
    # 队自然满，不需要服务端硬塞编队。
    GUIDE_REPORT_MAX_ORDER = 28

    # [跳过剧情] 开关：True = 直接上报教程终点标记，整段新手剧情不再触发。
    #
    # 客户端判定链：
    #   GuideModule:getIsEndGuide(82-92)
    #       local serverGroup = self._finishServerLastGuideId[groupId]
    #       if not serverGroup then return false end
    #       local config = GameStyle:getGuideById(serverGroup.guideId)
    #       return config.GuideLink == "-1"
    #   MainSceneMediator:306
    #       if not checkIsNotShowGuide() and not getIsEndGuide("Guide1") then <做引导恢复> end
    # 而 Guide.tsv 里 Guide1 组唯一 GuideLink=="-1" 的是
    #   Guide1_Step107  Order=88  Next=-1  Action=CLICK  Param1=successMainView
    # 也就是 GUIDE1_ENDGUIDE（GuideModule.lua:14）。
    # 上报它 -> getIsEndGuide=true -> MainSceneMediator 整段跳过 -> 引导彻底不出现。
    #
    # 用途：先把剧情让开，专注主线/战斗；剧情本身的问题（Step36 目标节点
    # _guide_ChuanSJ 找不到导致 windowFit 把引导挪到 -300）之后再单独修。
    GUIDE_SKIP_STORY = True
    GUIDE_END_MARKER = 'Guide1_Step107'

    # 需要一并标记为"已完成"的引导分组 -> 该组在 Guide.tsv 里
    # GuideLink=="-1" 的结束标记 rowId。
    #
    # 原理（全部来自客户端源码，不是猜的）：
    #   GuideModule:synchronize(data)            GuideModule.lua:24-33
    #       GameStyle:valueReplace(data, self._finishServerLastGuideId)   -- :30
    #       GameStyle:valueReplace(data, self._finishLastGuideId)         -- :31
    #   注意 :31 —— 服务端下发的引导数据会**同时**灌进本地完成集
    #   _finishLastGuideId（之前只看到 :30，漏了 :31）。
    #
    #   GuideModule:isFinshGuide(guideId)        GuideModule.lua:114-131
    #       local lastId = self:getFinishLastGuideId(groupId)   -- 来自服务端
    #       return config.Order <= lastConfig.Order
    #
    #   GuideSystem:checkStarFieldGuide()        GuideSystem.lua:690-702
    #       if not self._unlockSystem:getIsUnlock("StarField") then return end
    #       if self:checkGuideStatus() then return end
    #       if not self:isFinshGuide("Guide500_Step3")
    #          and self:saveCurGuideStepId("Guide500_Step1") then return true end
    #   注意它**不查** getIsEndGuide()，所以只发"结束标记"是没用的，
    #   必须让 isFinshGuide 返回 true —— 而这正好由 _finishLastGuideId 决定。
    #
    # 下发 Guide500_Step8(Order=9) 后：
    #   isFinshGuide("Guide500_Step3") -> 4 <= 9 -> true
    #   -> `not true` -> false -> checkStarFieldGuide 返回 nil -> 引导不触发
    #
    # Guide500 = StarField 星域探索活动引导（Guide.tsv 第 197-204 行，Order 2..9）。
    # 它是 full unlock 解锁 StarField 后由客户端自己触发的，与 Guide1 无关，
    # 所以之前只发 Guide1 压不住。
    GUIDE_SKIP_GROUPS = {
        'Guide1': 'Guide1_Step107',
        'Guide500': 'Guide500_Step8',
    }

    # Guide.tsv 里一共 54 个引导分组，以前只上报这 2 个"已完成"，
    # 其余 52 组客户端认为是 0 步，于是各种引导步骤会自己弹东西
    # （例如 HomeMediator:btnClickCall 里 checkGuideStatus -> EVT_CHECKGUIDE
    #   -> guide19991 -> 弹"战术芯片兑换卡-1h"的道具信息弹窗）。
    # 打开这个开关：按 Guide.tsv 的 Order 自动取每个分组的最后一步，全部上报为已完成。
    GUIDE_COMPLETE_ALL = True

    # ------------------------------------------------------------------
    # 服务器时间偏移
    #
    # 现象：ActivitySignMonthModel.lua:64
    #       "没有找到当月奖励月10年2026"
    #
    # 链路：HomeMediator:149 dispatch -> SignMonthMediator:184 updateViewUI
    #       -> :55 enterWithData -> :40 getMonthReward
    #       -> ActivitySignMonthModel:64 getRewardCfg
    #
    # 根因：getMonthReward(:34-38) 用**服务器时间**算当月
    #       local curTime = DmGame:...GameServerAgent():remoteTimestamp()
    #       local month = os.date("%m", curTime)
    #       local year  = os.date("%Y", curTime)
    #       然后 getRewardCfg(:56-71) 去 getSignMonthTable() 里找
    #       v.Month.year == year and v.Month.month == month
    #   而 getSignMonthTable(:158-163) 读的是**配置表** SignMonth.tsv，
    #   不是服务端数据 —— 服务端补字段没用。
    #   SignMonth.tsv 实测只覆盖 **2022-03 ~ 2024-12**（34 行），
    #   设备当前 2026-10 -> 永远匹配不上 -> assert 崩。
    #
    # 处理：把响应包头里的服务器时间(i64 timestamp)整体前移到 2024-10，
    #       让"当月"落回配置表覆盖范围。偏移量在进程启动时算一次，
    #       之后时间照常流逝（不是冻结）。
    #       设成 None 即关闭偏移、恢复真实时间。
    #
    # 注意：GameServerAgent:remoteTimeMillis() = client:remoteTimeMillis()
    #       + _timeOffset，其中 client 由 rrcp.createClient()（C++ 模块
    #       lua_rrcp.cpp）创建，_timeOffset 恒为 0，从未被服务端赋值。
    #       C++ 侧源码不在工作区，无法静态确认它取包头时间戳还是设备时间，
    #       所以这一改需要实测验证；若无效则改用「设置模拟器系统时间」。
    # ------------------------------------------------------------------
    SERVER_TIME_TARGET = '2024-10-15 12:00:00'

    _time_shift = 0.0
    _time_shift_ready = False

    @classmethod
    def server_time_ms(cls):
        """返回发给客户端的服务器时间戳（毫秒）。"""
        if not cls._time_shift_ready:
            cls._time_shift_ready = True
            if cls.SERVER_TIME_TARGET:
                tgt = time.mktime(time.strptime(cls.SERVER_TIME_TARGET,
                                               '%Y-%m-%d %H:%M:%S'))
                cls._time_shift = tgt - time.time()
                print('[时间偏移] 目标 %s  偏移 %+.1f 天'
                      % (cls.SERVER_TIME_TARGET, cls._time_shift / 86400.0))
            else:
                cls._time_shift = 0.0
        return int((time.time() + cls._time_shift) * 1000)

    def guide_data(self):
        cur = getattr(self, '_guide_seen', None)
        if cur is None:
            cur = self.load_guide_state()
        if Server.GUIDE_SKIP_STORY:
            groups = dict(Server.GUIDE_SKIP_GROUPS)
            if Server.GUIDE_COMPLETE_ALL:
                orders = self.guide_orders()
                best = {}
                for gid, o in orders.items():
                    g = gid.split('_')[0]
                    if g not in best or o > best[g][0]:
                        best[g] = (o, gid)
                added = 0
                for g, (_o, last) in best.items():
                    if g not in groups:
                        groups[g] = last
                        added += 1
                self.w('引导：%d 个分组全部标记为完成（新增 %d 个）'
                        % (len(groups), added))
            return dict((g, {'guideId': mid}) for g, mid in groups.items())
        if not cur:
            return None
        orders = self.guide_orders()
        cap = Server.GUIDE_REPORT_MAX_ORDER
        # 收集每个 group 的 order -> [rowId]，保持确定性（字典序最小优先）
        by_group = {}
        for gid, o in orders.items():
            g = gid.split('_')[0]
            by_group.setdefault(g, {}).setdefault(int(o), []).append(gid)
        out = {}
        for g, o_map in by_group.items():
            cur_o = cur.get(g)
            if cur_o is None:
                continue
            target = min(int(cur_o), cap)
            if target not in o_map:
                continue
            gid = sorted(o_map[target])[0]
            out[g] = {'guideId': gid}
            if int(cur_o) > cap:
                self.w('   [引导封顶] %s 实际 Order=%s > 封顶 %s -> 改报 %s'
                       % (g, cur_o, cap, gid))
        return out or None

    def pick_profession(self, cfg, is_enemy):
        """敌方用 Enemy.tsv 的 Class；玩家侧/友方没有配置来源，用合法默认值。

        Character.tsv 的 Position 字段是 Char_Pos_LaJ 这类**文本 key**
        （在 Text.tsv 里查），不是职业映射，所以不能拿来当 profession。
        """
        if is_enemy:
            p = cfg.get('Class')
            if p:
                return p
        prof = Server.DEFAULT_PROFESSION
        legal = self.valid_professions()
        assert prof in legal, '默认职业 %s 不在合法集合 %s 内！' % (prof, sorted(legal))
        return prof

    def config_tables(self):
        if Server._cfg_cache is not None:
            return Server._cfg_cache

        def load(fn):
            path = os.path.join(Server.TABLES_DIR, fn)
            try:
                with io.open(path, encoding='utf-8') as f:
                    return {r['rowId']: r for r in csv.DictReader(f, delimiter='\t')}
            except Exception as ex:
                self.w('!! 读配置表失败 %s %r' % (fn, ex))
                return {}

        Server._cfg_cache = (load('GridBattle.tsv'), load('Enemy.tsv'),
                             load('Character.tsv'), load('Skill.tsv'))
        self.w('配置表已载入 GridBattle=%d Enemy=%d Character=%d Skill=%d' % (
            len(Server._cfg_cache[0]), len(Server._cfg_cache[1]),
            len(Server._cfg_cache[2]), len(Server._cfg_cache[3])))
        return Server._cfg_cache

    @staticmethod
    def resolve_hero_id(unit):
        """友方单位在配置里带关卡前缀，实际角色 id 要去掉。

        GridBattle 里写的是 C00S02_HuL / C00S01_ShiZ，
        但 Character.tsv 里的 rowId 是 HuL / ShiZ。
        敌方 C00S02_DEF 则是 Enemy.tsv 的真实 rowId，不用剥。
        """
        parts = unit.split('_')
        return parts[-1] if len(parts) > 1 else unit

    @staticmethod
    def hero_skills(skill_t, cid):
        """按 Skill.tsv 的命名规律 <角色id>_*_B 取该角色的技能。

        已核对：LaJ -> LaJ_C_B / LaJ_S1_B / LaJ_S2_B / LaJ_U_B
                HuL -> HuL_C_B / HuL_S1_B / HuL_S2_B / HuL_U_B（还有 SP_01_* 系列）
                ShiZ -> ShiZ_C_B / ShiZ_S1_B / ShiZ_S2_B / ShiZ_U_B
        只取不含 SP_ 的常规三件套 + S2，与表里写死的 C00S01 响应保持同构。

        [重要] 技能等级必须用 1，不能用 5。
        原因：Skill.tsv 里 ChuanSJ_S2_B（FuncName=Skill_ChuanSJ_PassiveSkill）只有
            Parameter_1 = [{effParam2:30000, effParam1:3000, effParam:0.3}]
            Parameter_2..5 = [{effParam2:3000, effParam1:0.6}]   <- 缺 effParam
        而 Skill_ChuanSJ.lua:487 无条件读 _env.skillArgs.effParam：
            if global.CheckCD(_env) and _env.curHpRatio <= _env.skillArgs.effParam then
        发等级 5 就命中坏数据 -> "attempt to compare number with nil"，
        每帧报错（战斗被拉长后才暴露，之前 9 秒秒杀技能来不及触发）。
        真人新英雄是 1 级，所以线上正常。统一发 1 级。
        """
        SKILL_LEVEL = 1
        out = {}
        for k in skill_t:
            if not k.startswith(cid + '_') or not k.endswith('_B'):
                continue
            if '_SP_' in k:
                continue
            out[k] = SKILL_LEVEL
        return out

    STAGE_RE = re.compile(rb'C\d{2}S\d{2}')

    def extract_campaign(self, body):
        """从 14002 请求体里取出 campaignId。

        请求体是自定义二进制编码，但 key 和 value 都是明文 ASCII：
            7b 22 "campaignId" 22 3a 22 "C00S01" ...
            7b='{'  22=key 标记  3a=':'  22=字符串值 标记
        所以直接找 'campaignId' 后面第一个形如 C00S01 的 token 即可，
        不必去完整解码这套编码。
        """
        i = body.find(b'campaignId')
        if i >= 0:
            m = Server.STAGE_RE.search(body, i)
            if m:
                return m.group(0).decode('ascii')
        m = Server.STAGE_RE.search(body)
        return m.group(0).decode('ascii') if m else None

    def _hero_base(self, cid, uid, camp, x, y, level, star, model_id, element, profession, skills,
                    body=None):
        h = {
            'uid': uid, 'cid': cid, 'modelId': model_id, 'camp': camp,
            'x': x, 'y': y, 'level': level, 'star': star,
            'element': element, 'profession': profession,
            'Weight': 1000,
            'skills': skills,
        }
        # 【变身体列表】客户端靠它预生成召唤/变身数据。
        #   BattleDataParser.lua:288  self:fillOtherHeroData(heroData.body, otherData)
        #   :292-320  拿每个 id 去 getBattleRecordById("Enemy", unitId) 查配置，
        #             组出 {attrs, cid, modelId, pos, type, skills, level, star,
        #                  element, profession, Weight} 存进 others
        # 之后 special_ops.Summon(:7-11) 走
        #   actor:getOwner():copySummonData(summonId)   -> BattlePlayer:72-76
        #       return self._others[id] and deepCopy(...)
        #   assert(summonData, "cannot summon id:" .. tostring(summonId))
        #
        # 我们不下发 body -> heroData.body 是 nil -> :293 的
        # `if type(unitIds) == "table"` 不成立 -> others 恒空 ->
        # 技能一召唤就 assert 崩（实测 cannot summon id:DuoLNN_Summoned1）。
        if body:
            h['body'] = body
        return h

    @staticmethod
    def _change_body(cfg):
        """从 Character/Enemy 配置里取 ChangeBody 列表（可能是 JSON 数组）。"""
        try:
            v = json.loads(cfg.get('ChangeBody') or '')
        except Exception:
            return None
        if isinstance(v, list) and v:
            return v
        return None

    # ------------------------------------------------------------------
    # 主线战斗：玩家编队
    # ------------------------------------------------------------------
    #
    # 编队数据在 player.datas.Teams.teams[id].team，形状由客户端
    # TeamsSystem:getTeamById(:123-131) 确认（`teams[id].team` 才是英雄表，
    # 同级的 name / leadSkills 是另外两件事）。
    # 玩家改队走 TeamsService:requestSetTeams -> **opcode 29001**（未实现），
    # 所以离线服里编队永远是空的 —— 必须服务端给一份默认编队，
    # 否则战斗取不到人。
    TEAM_MAX_NUM = 5
    # 【按星球/章节区分编队人数上限】
    # 章��名来自 Text.tsv 的 ChapName_*（实测）：
    #     ChapName_C00 = 星球：岩-233      <- 你现在走的这条线（C00/C01）
    #     ChapName_C01 = 星球：岩-233
    #     ChapName_C02 = 星球：炽-237
    #     ChapName_C10 = 星球：岩-233      <- 岩-233 还有一条后期线
    #     ...
    # 「岩-233 之后」= 不属于岩-233 的章节，从那里开始放宽到 5 人。
    # 岩-233 自己的章节保持 TEAM_MAX_NUM_PLANET 的人数（原来 2）。
    TEAM_MAX_NUM_DEFAULT = 5
    TEAM_MAX_NUM_PLANET = 2
    # 用 Text.tsv 的 ChapName_* 反查星球名（rowId 里没有 planet 字段，
    # 星球名只有中文文本 "星球：xxx"）。
    #
    # 原本按"岩-233 之后"理解，岩-233 自己保持 2 人；现在按要求
    # **岩-233 也放宽到 5**，所以列表清空 —— 所有星球一律 5 人。
    # 机制留着：以后要单独收紧某个星球，往里加名字即可。
    # 例：('\u5ca9-233',)  # 岩-233
    TEAM_SMALL_PLANETS = ()
    _team_num_cache = None

    def team_max_num(self, campaign_id=None):
        """该关卡允许的编队人数。campaign_id 形如 C01S08 / C01M02。"""
        if not campaign_id:
            return Server.TEAM_MAX_NUM_DEFAULT
        ch = campaign_id[:3] if len(campaign_id) >= 3 else ''
        if Server._team_num_cache is None:
            Server._team_num_cache = {}
            try:
                for r in self.read_tsv('Text.tsv'):
                    rid = r.get('rowId') or ''
                    if not rid.startswith('ChapName_'):
                        continue
                    key = rid[len('ChapName_'):]
                    zh = r.get('Zh_CN') or ''
                    # "星球：岩-233" -> 岩-233
                    planet = zh.split('\uff1a')[-1].strip() if '\uff1a' in zh else ''
                    Server._team_num_cache[key] = planet
            except Exception:
                Server._team_num_cache = {}
        planet = Server._team_num_cache.get(ch, '')
        if planet and planet in Server.TEAM_SMALL_PLANETS:
            return Server.TEAM_MAX_NUM_PLANET
        return Server.TEAM_MAX_NUM_DEFAULT

    def remember_team_from_request(self, campaign_id, req_slots):
        """把 14002 请求里解出的编队存下来，之后每关复用。"""
        cap = self.team_max_num(campaign_id)
        slots = [s for s in req_slots if s.get('heroId')][:cap]
        if not slots:
            return
        ids = [s['heroId'] for s in slots]
        cur = self.player_team_hero_ids()
        if ids == cur:
            return
        # 用玩家的队伍（顺序=请求里的顺序），坐标有就存、没有留空
        newteam = {}
        for i, s in enumerate(slots, 1):
            newteam[str(i)] = {'heroId': s['heroId'], 'id': s['heroId'],
                               'x': s.get('x'), 'y': s.get('y'), 'type': 1}
        pl = self.table.get('10001', {}).get('data', {}).get('player')
        if not isinstance(pl, dict):
            return
        teams = pl.setdefault('datas', {}).setdefault('Teams', {})
        tmap = teams.setdefault('teams', {})
        t = tmap.get('1')
        if not isinstance(t, dict):
            t = {'name': 'Team1', 'leadSkills': {}, 'team': {}}
            tmap['1'] = t
        t['team'] = newteam
        teams['maxNum'] = cap
        Server.save_team_state(teams)
        self.w('   [编队] 记住玩家选择 %s（%s，上限 %d）'
               % (ids, campaign_id, cap))
    # 自动补的默认编队英雄（parse_battle_teams 要靠它剔掉默认残留）
    DEFAULT_TEAM_HERO_IDS = ()

    def player_team_hero_ids(self):
        """当前出战编队的 heroId 列表（按编队槽位顺序）。"""
        teams = (self.table.get('10001', {}).get('data', {})
                 .get('player', {}).get('datas', {}).get('Teams') or {})
        tmap = teams.get('teams') or {}
        # 优先用 1 号编队（主线战斗固定用第 1 队）
        for key in ('1', 1):
            t = tmap.get(str(key)) or tmap.get(key)
            if isinstance(t, dict):
                ids = self._team_ids_from(t.get('team'))
                if ids:
                    return ids
        # 没有可用编队就看有没有任何一队是满的
        for k in sorted(tmap.keys(), key=lambda x: str(x)):
            t = tmap.get(k)
            if isinstance(t, dict):
                ids = self._team_ids_from(t.get('team'))
                if ids:
                    return ids
        return []

    @staticmethod
    def _team_ids_from(team):
        """把 teams[id].team 归一成 heroId 列表。

        客户端存编队时 `team` 是按槽位编号的 map（槽位 -> heroId），
        但历史数据/别的分支也可能直接给数组。两种都兼容。

        注意 TeamGroundWidget:getCurTeam(:5170-5176) 存的其实是
            curTeams[heroData.uid] = {heroId=, id=, x=, y=, type=}
        即键是**英雄 uid**，值里带 heroId/x/y。所以下面 dict 分支要
        按 heroId 排序取，并额外提供带坐标的 _team_slots_from。
        """
        if not team:
            return []
        out = []
        if isinstance(team, list):
            for v in team:
                if isinstance(v, str) and v:
                    out.append(v)
                elif isinstance(v, dict):
                    for k in ('heroId', 'id', 'cid'):
                        if v.get(k):
                            out.append(str(v[k]))
                            break
        elif isinstance(team, dict):
            # 槽位 -> heroId；槽位名可能是数字字符串
            def sk(k):
                try:
                    return (0, int(k))
                except Exception:
                    return (1, str(k))
            for k in sorted(team.keys(), key=sk):
                v = team[k]
                if isinstance(v, str) and v:
                    out.append(v)
                elif isinstance(v, dict):
                    for kk in ('heroId', 'id', 'cid'):
                        if v.get(kk):
                            out.append(str(v[kk]))
                            break
        return out

    @staticmethod
    def _team_slots_from(team):
        """把编队归一成 [{heroId, x, y}]，**保留玩家摆的坐标**。

        TeamGroundWidget:getCurTeam(:5168-5176) 存的是
            curTeams[heroData.uid] = {heroId, id, x = tx+1, y = ty+1, type}
        键是英雄 uid、值里带 x/y，所以要先按 x,y 排序（键是 uid 排不出阵型）。
        """
        out = []
        if isinstance(team, list):
            items = team
        elif isinstance(team, dict):
            items = [team[k] for k in team.keys()]
        else:
            return out
        for v in items:
            if isinstance(v, str) and v:
                out.append({'heroId': v, 'x': None, 'y': None})
            elif isinstance(v, dict):
                hid = None
                for k in ('heroId', 'id', 'cid'):
                    if v.get(k):
                        hid = str(v[k])
                        break
                if hid:
                    out.append({'heroId': hid,
                                'x': v.get('x'),
                                'y': v.get('y')})
        # 有坐标的按 (y, x) 排 —— 和客户端 tx/ty 的摆放顺序一致
        if any(s['x'] is not None for s in out):
            out.sort(key=lambda s: (s['y'] if s['y'] is not None else 0,
                                    s['x'] if s['x'] is not None else 0))
        return out

    def cur_team_slots(self):
        """当前出战编队（第 1 队）的槽位列表 [{heroId, x, y}]。"""
        teams = (self.table.get('10001', {}).get('data', {})
                 .get('player', {}).get('datas', {}).get('Teams') or {})
        tmap = teams.get('teams') or {}
        for key in ('1', 1):
            t = tmap.get(str(key)) or tmap.get(key)
            if isinstance(t, dict):
                slots = self._team_slots_from(t.get('team'))
                if slots:
                    return slots
        for k in sorted(tmap.keys(), key=lambda x: str(x)):
            t = tmap.get(k)
            if isinstance(t, dict):
                slots = self._team_slots_from(t.get('team'))
                if slots:
                    return slots
        return []

    # ------------------------------------------------------------------
    # 29001 改编队
    # ------------------------------------------------------------------
    #
    # 【为什么必须实现】玩家在游戏里换角色走
    #   TeamMediator:saveEditCallBack(:214-221) 组装
    #       para = {name=, id=, teams=getCurTeam(), leaderSkills=}
    #   -> TeamsSystem:requestSetTeams(:20-35)
    #   -> TeamsService:requestSetTeams -> newRequest(**29001**, params)
    # 服务端不回 29001 的话，客户端 TeamsModel:synchronize(:27-53) 收不到
    # 新编队，_teams 一直是旧值 —— 于是「上场角色不跟随玩家选择」。
    #
    # 请求体是自定义二进制编码，但 key/value 都是明文 ASCII（见 extract_campaign
    # 的注释），所以这里按 "heroId" 逐个抠出来，不做完整解码。
    # 形如： ... "heroId" ... "AnWZ" ... "x" ... 3 ... "y" ... 4 ...
    TEAM_KEY_RE = re.compile(rb'"heroId"[^\x00-\x20"]*"([^"]{1,64})"')

    # 14002 请求体里的 teams：不是纯 JSON，值里混了类型标记字节。
    # 先按"teams 字段起点"切开，再在那一段里逐个抠英雄 id / x / y。
    TEAMS_FIELD_RE = re.compile(rb'"teams"\s*:\s*\{')
    # 这个协议不是纯 JSON：引号内会混进类型标记字节。实测 C01S02 的 teams 段：
    #   b'"LaJ\x01"\x18y":2,"i\x01D<LaJ","x":1,"hero\x05Y\t\x15Xtype":"OWNED"'
    # 可见两种情况：
    #   1) 值里带标记 —— "LaJ\x01"，闭引号在 \x01 **之后**
    #   2) 键名带前缀 —— "\x18y"，闭引号在 y **之前**
    # 所以正则都要容忍引号内侧的 \x00-\x20。
    # 14002 请求体不是纯 JSON，而且**字段顺序不固定**（Lua 表遍历序）：
    #   实测 A：{"campaignId":"C01S03","battleData":{...,"teams":{"HuoL":{...
    #   实测 B：{"battleData":{"teams\x01\x09\x0c...,"campaignId":"C01S05"}
    # 键名后面也不一定有闭合引号（"teams 后面直接跟标记字节）。
    # 所以不能靠 '"teams":{' 定位 —— 实测 B 那样会整个匹配失败、
    # 悄悄退回默认编队（玩家看到的就是"又变回两个默认的了"）。
    # 改成：全 body 扫描"引号紧跟的 ASCII 串"，再用 owned 集合校验。
    HERO_TOK_RE = re.compile(rb'"([A-Za-z][A-Za-z0-9_]{0,30})')
    # 打包段里的英雄名**没有引号前缀**（实测 C01S06 尾部：
    # ...\x04La6\x7f...ChuanS6A...MoG2\xc5...），所以还要扫裸 token。
    # 注意名字后面常紧跟打包字节里的数字（MoG2 / ChuanS6A），正则不能要求
    # "后面是非字母"，否则整段被当成一个 token。改成扫出一段字母数字串后，
    # 再**逐个前缀**去 owned 里匹配（MoG2 -> MoG2 / MoG，命中 MoG）。
    HERO_BARE_RE = re.compile(rb'([A-Z][A-Za-z0-9_]{1,24})')

    XY_RE = {
        'x': re.compile(rb'(?<![A-Za-z0-9_])x[\x00-\x20]*"[\x00-\x20]*[:=][\x00-\x20]*(\d+)'),
        'y': re.compile(rb'(?<![A-Za-z0-9_])y[\x00-\x20]*"[\x00-\x20]*[:=][\x00-\x20]*(\d+)'),
    }
    # 这些是键名/枚举，不是英雄（先排掉，减少误判）
    TEAM_NOT_HERO = frozenset((
        'battleData', 'campaignId', 'leaderSkills', 'teams', 'heroId', 'id',
        'type', 'x', 'y', 'i', 'a', 'OWNED', 'team', 'name', 'skills', 'level',
        'star', 'profession', 'element', 'modelId', 'cid', 'uid', 'camp',
    ))

    def parse_battle_teams(self, body):
        """从 14002 请求体解出 [{heroId, x, y}]。解不出返回 []。"""
        if not body:
            return []
        owned = set((self.table.get('10001', {}).get('data', {})
                     .get('player', {}).get('datas', {})
                     .get('HeroesData', {}).get('heroes') or {}))
        if not owned:
            return []

        hits = []
        seen = set()
        # 先扫带引号的（结构完整、置信度高），再扫裸 token（打包段）。
        # 顺序按在 body 里出现的先后，这样 x/y 的归属才对得上。
        cands = []
        for rx, quoted in ((Server.HERO_TOK_RE, True),
                           (Server.HERO_BARE_RE, False)):
            for m in rx.finditer(body):
                tok = m.group(1).decode('ascii', 'replace')
                if tok in Server.TEAM_NOT_HERO:
                    continue
                if tok not in owned:
                    if quoted:
                        continue
                    # 裸 token 逐个前缀找真正的英雄 id（MoG2 -> MoG）
                    hit = None
                    for n in range(len(tok) - 1, 0, -1):
                        if tok[:n] in owned:
                            hit = tok[:n]
                            break
                    if not hit:
                        continue
                    tok = hit
                cands.append((m.start(), m.end(), tok))
        cands.sort()
        for st, end, tok in cands:
            if tok in seen:
                continue
            seen.add(tok)
            hits.append((end, tok))

        # 【剔掉自动补的默认英雄】apply_team_config 用 sorted(heroes)[:2]
        # 给 6 个队都塞了同一对默认角色（实测 AnWZ/BaiJ）。客户端编队界面
        # 是从这个初值开起来的，玩家换了人之后默认那对仍可能留在 body 里，
        # 于是战斗上场成"一个默认 + 一个我选的"。
        # 只要 body 里还有别的候选，就不要默认那对。
        defaults = set(Server.DEFAULT_TEAM_HERO_IDS or ())
        slots = []
        picked = [t for _e, t in hits]
        non_def = [t for t in picked if t not in defaults]
        if non_def and len(non_def) < len(picked):
            dropped = [t for t in picked if t in defaults]
            self.w('   14002 剔除默认残留 %s（body 里还有 %s）'
                   % (dropped, non_def))

        # 重新按 body 顺序取，且跳过被剔掉的默认
        use = non_def if non_def else picked
        use_set = set(use)
        for i, (end, tok) in enumerate(hits):
            if tok not in use_set:
                continue
            nxt = len(body)
            for e2, t2 in hits:
                if e2 > end:
                    nxt = e2
                    break
            seg = body[end:nxt]
            slot = {'heroId': tok, 'x': None, 'y': None}
            for axis, rx in Server.XY_RE.items():
                mm = rx.search(seg)
                if mm:
                    slot[axis] = int(mm.group(1))
            slots.append(slot)
            if len(slots) >= Server.TEAM_MAX_NUM_DEFAULT:
                break
        if slots:
            self.w('   14002 扫到英雄 %s'
                   % [(s['heroId'], s['x'], s['y']) for s in slots])
        return slots

    def parse_set_teams(self, body):
        """从 29001 请求体里解出 (team_id, slots)。解不出返回 (None, [])。"""
        if not body:
            return None, []
        slots = [(m.group(1).decode('ascii', 'replace'), m.end())
                 for m in Server.TEAM_KEY_RE.finditer(body)]
        if not slots:
            return None, []
        # 槽位坐标：每个 heroId 之后到下一个 heroId 之间的 "x"/"y" 数值
        res = []
        for i, (hid, end) in enumerate(slots):
            nxt = slots[i + 1][1] if i + 1 < len(slots) else len(body)
            seg = body[end:nxt]
            mx = re.search(rb'"x"[^\x00-\x20"]*(\d+)', seg)
            my = re.search(rb'"y"[^\x00-\x20"]*(\d+)', seg)
            res.append({'heroId': hid,
                        'x': int(mx.group(1)) if mx else None,
                        'y': int(my.group(1)) if my else None})
        # 队号：请求体里的 "id" 紧跟在 "teams" 之前
        mid = re.search(rb'"id"[^\x00-\x20"]*(\d+)', body)
        return (int(mid.group(1)) if mid else 1), res

    def apply_set_teams(self, team_id, slots):
        """把玩家选的编队写进 10001 的 Teams，并落盘。"""
        player = self.table.get('10001', {}).get('data', {}).get('player')
        if not isinstance(player, dict):
            return None
        teams = player.setdefault('datas', {}).setdefault('Teams', {})
        teams.setdefault('maxNum', Server.TEAM_MAX_NUM_DEFAULT)
        tmap = teams.setdefault('teams', {})
        key = str(team_id or 1)
        t = tmap.get(key)
        if not isinstance(t, dict):
            t = {'name': 'Team%s' % key, 'leadSkills': {}, 'team': {}}
            tmap[key] = t
        # 存成 {槽位: {heroId,id,x,y,type}}，和 getCurTeam 的形状对齐
        newteam = {}
        for i, s in enumerate(slots[:Server.TEAM_MAX_NUM_DEFAULT], 1):
            newteam[str(i)] = {'heroId': s['heroId'], 'id': s['heroId'],
                               'x': s['x'], 'y': s['y'], 'type': 1}
        t['team'] = newteam
        self.w('[编队] 29001 存 %s 号队 = %s'
               % (key, [s['heroId'] for s in slots[:Server.TEAM_MAX_NUM_DEFAULT]]))
        Server.save_team_state(teams)
        return teams

    def apply_team_config(self):
        """给 Teams 填一份可用的默认编队。

        只填**空队**（`if not Server._team_ids_from(...)`），所以玩家通过
        29001 选好的队不会被这里冲掉 —— 这正是「上场角色跟随玩家选择」的前提。
        """
        player = self.table.get('10001', {}).get('data', {}).get('player')
        if not player:
            return
        datas = player.setdefault('datas', {})

        # 先把玩家上次选的编队读回来（重启后不丢）
        saved = Server.load_team_state()
        if saved:
            datas['Teams'] = saved
            self.w('[编队] 载入玩家编队: %s'
                   % {k: Server._team_ids_from((v or {}).get('team'))
                      for k, v in (saved.get('teams') or {}).items()})

        teams = datas.setdefault('Teams', {})
        teams['maxNum'] = Server.TEAM_MAX_NUM_DEFAULT
        tmap = teams.setdefault('teams', {})

        heroes = (datas.get('HeroesData') or {}).get('heroes') or {}
        owned = sorted(heroes)[:Server.TEAM_MAX_NUM_DEFAULT]
        # 记下自动补的默认是谁，parse_battle_teams 要靠它剔掉默认残留
        Server.DEFAULT_TEAM_HERO_IDS = tuple(owned)

        # 每个队伍都按 TEAM_MAX_NUM 填满（之前写成 `min(i, len(owned))`，
        # 结果第 1 队只放 1 个、第 2 队才满，而 player_team_hero_ids()
        # 优先取 1 队 —— 主线战斗就只出 1 个人）。
        filled_teams = []
        for i in range(1, 7):
            key = str(i)
            t = tmap.get(key)
            if not isinstance(t, dict):
                t = {'name': 'Team%d' % i, 'leadSkills': {}, 'team': {}}
                tmap[key] = t
            t.setdefault('name', 'Team%d' % i)
            t.setdefault('leadSkills', {})
            t.setdefault('team', {})
            if not Server._team_ids_from(t.get('team')) and owned:
                n = min(Server.TEAM_MAX_NUM_DEFAULT, len(owned))
                t['team'] = {str(k + 1): owned[k] for k in range(n)}
                filled_teams.append('%s=%s' % (key, t['team']))
        self.w('[编队] 默认编队: %s' % (', '.join(filled_teams) or '无可用角色'))

    # ------------------------------------------------------------------
    # 编队落盘（29001）
    # ------------------------------------------------------------------
    TEAM_STATE_PATH = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'team_state.json')

    # 天梯关卡 id 形如 T24S40（StairsBattle.tsv 的 rowId）。
    #
    # 但**不止这一种形态**：StairsBattle.tsv 里还有 T_FIRE_S001 / T_LIGHT_S001 /
    # T_DARK_Sxxx 这种"元素分表"的 id。只用 T\d{2}[SMX]\d{2} 会让这几百关在
    # 21001/21005 上完全打不了（实测 1686 关里有 47 个 T_FIRE_/T_LIGHT_/... 开头的
    # 不被匹配），表现为"点某类天梯关卡进不去"。
    # 所以改成先按正则捞候选，再拿 StairsBattle 的 rowId 集合校验；
    # 正则捞不到就退回全 body 扫 token（与 parse_battle_teams 同思路）。
    STAIRS_ID_RE = re.compile(rb'T\d{2}[SMX]\d{2}')
    STAIRS_TOK_RE = re.compile(rb'[A-Za-z_][A-Za-z0-9_]{2,40}')

    def extract_stairs(self, body):
        """从请求体里解出天梯关卡 id，解不出返回 ''。"""
        if not body:
            return ''
        valid = self.stairs_ids()
        cands = []
        m = Server.STAIRS_ID_RE.search(body)
        if m:
            cands.append(m.group(0))
        if valid:
            for m in Server.STAIRS_TOK_RE.finditer(body):
                tok = m.group(0).decode('ascii', 'replace')
                if tok in valid:
                    cands.append(tok)
                    break
        for c in cands:
            if not valid or c in valid:
                return c
        return ''

    def stairs_ids(self):
        """StairsBattle 全部 rowId 的集合（只建一次）。"""
        got = getattr(self, '_stairs_id_set', None)
        if got is None:
            got = set()
            try:
                for r in self.read_tsv('StairsBattle.tsv'):
                    rid = r.get('rowId')
                    if rid:
                        got.add(rid)
            except Exception:
                pass
            self._stairs_id_set = got
        return got

    def stairs_row(self, bid):
        """按 rowId 取 StairsBattle 配置。"""
        if not bid:
            return None
        for r in self.read_tsv('StairsBattle.tsv'):
            if r.get('rowId') == bid:
                return r
        return None

    def stairs_grid_battle(self, bid):
        """StairsBattle.GridBattle —— 客户端 getGridBattleID 要的就是它。"""
        r = self.stairs_row(bid)
        return (r or {}).get('GridBattle') or ''

    def gen_stairs_battle_data(self, bid):
        """按天梯关卡配置生成战斗数据，形状同主线 14002。"""
        r = self.stairs_row(bid)
        if not r:
            self.w('!! 天梯 %s 不在 StairsBattle.tsv 里' % bid)
            return None
        grid_id = r.get('GridBattle') or ''
        if not grid_id:
            self.w('!! 天梯 %s 没有 GridBattle' % bid)
            return None
        try:
            rows = [x for x in self.read_tsv('GridBattle.tsv')
                    if x.get('rowId') == grid_id]
        except Exception:
            rows = []
        if not rows:
            self.w('!! GridBattle %s 不在表里' % grid_id)
            return None

        class _G(dict):
            pass
        grid = rows[0]
        gen = self.gen_battle_data(bid, grid_override=grid)
        if gen:
            gen['campaignId'] = bid
            gen['gridBattleId'] = grid_id
        return gen

    @staticmethod
    def load_team_state():
        try:
            with io.open(Server.TEAM_STATE_PATH, encoding='utf-8') as f:
                st = json.load(f)
            if isinstance(st, dict) and st.get('teams'):
                return st
        except Exception:
            pass
        return None

    @staticmethod
    def save_team_state(teams):
        try:
            tmp = Server.TEAM_STATE_PATH + '.tmp'
            with io.open(tmp, 'w', encoding='utf-8') as f:
                json.dump(teams, f, ensure_ascii=False)
            if os.path.exists(Server.TEAM_STATE_PATH):
                os.remove(Server.TEAM_STATE_PATH)
            os.rename(tmp, Server.TEAM_STATE_PATH)
        except Exception as ex:
            pass

    # ------------------------------------------------------------------
    # 主线关卡进度推进
    # ------------------------------------------------------------------
    #
    # 现象：第二关（C00S02）打完了、14003 也回了 pass:true，但**过不去** ——
    # 服务端日志里 14003 之后只剩心跳，没有任何推进请求。
    #
    # 原因：CampaignData.lastPassed 一直是 "C00S01"，没推进。客户端
    # CampaignModel:synchronize(:289-295) 靠它判定通关：
    #     if data.lastPassed then self._curFinishStage = data.lastPassed end
    #     if data.branchLastPassed then valueReplace(..., self._campaignBranches) end
    # 所以 14003（战斗结算）必须回一个 d.player.datas.CampaignData。
    #
    # 推进顺序由 Campaign.tsv 决定（不是猜的）：
    #     rowId / Order_1 / Order_2 / Chapter / UnlockId / BranchGroup
    # C00 主干实测：C00S01(1) -> C00S02(2, Unlock=C00S01) -> C00S03(3)
    #                 -> C00S04(4) -> C01S01(5, Unlock=C00S04) ...
    #
    # 注意：分支关卡 CxxMxx 的 **Order_1 是空的**（实测 29 条），
    # 只看 Order_1 会把它们全甩到末尾、链条错乱。所以：
    #   - 主干推进 = 按 (Order_1, Order_2) 排序
    #   - 解锁判定 = 按 UnlockId 建图（谁把 stage_id 当 UnlockId，谁就解锁）
    #   - branchLastPassed[chapter] 只记该章节**主干**的最后一关，
    #     不能用分支关卡覆盖（否则会把 C01 的进度写回 C01M01）
    CAMPAIGN_TSV = 'Campaign.tsv'

    def campaign_order(self):
        """(Order_1, Order_2, rowId, Chapter) 列表，主干按 Order 排序。

        分支关卡（Order_1 为空、rowId 形如 CxxMxx）排在所属章节之后。
        """
        if self._camp_order is not None:
            return self._camp_order
        self._camp_order = []
        for r in self.read_tsv(Server.CAMPAIGN_TSV):
            rid = r.get('rowId')
            if not rid:
                continue

            def num(x):
                try:
                    return int(float(x or 0))
                except Exception:
                    return 0
            self._camp_order.append((num(r.get('Order_1')), num(r.get('Order_2')),
                                     rid, r.get('Chapter') or ''))
        # 主干在前（Order>0），分支关卡 Order=0 排到末尾但保持章节相邻
        self._camp_order.sort(key=lambda t: (t[3], t[0], t[1], t[2]))
        return self._camp_order

    def campaign_next(self, stage_id):
        """通关 stage_id 之后的下一关 rowId；已经最后一关则返回 None。

        只沿主干 Order 推进 —— 分支关卡不是必须打的，不该挡着主线。
        """
        order = self.campaign_order()
        for i, (o1, o2, rid, ch) in enumerate(order):
            if rid != stage_id:
                continue
            for o1b, _o2b, rid_b, _chb in order[i + 1:]:
                # 跳过 Order 为空的分支关卡
                if o1b > 0:
                    return rid_b
            return None
        return None

    def campaign_unlocked_by(self, stage_id):
        """哪些关卡把 stage_id 当 UnlockId（即通关它之后解锁的关卡）。"""
        if self._camp_unlock is None:
            self._camp_unlock = {}
            for r in self.read_tsv(Server.CAMPAIGN_TSV):
                u = r.get('UnlockId')
                if u:
                    self._camp_unlock.setdefault(u, []).append(r['rowId'])
        return self._camp_unlock.get(stage_id, [])

    def build_campaign_progress(self, stage_id):
        """构造 d.player.datas.CampaignData 的增量（lastPassed 等）。"""
        chap = ''
        for _o1, _o2, rid, ch in self.campaign_order():
            if rid == stage_id:
                chap = ch
                break
        return {
            'lastPassed': stage_id,
            'lastCampaign': stage_id,
            'lastBattleCampaign': stage_id,
            'branchLastPassed': {chap: stage_id} if chap else {},
        }

    def gen_battle_data(self, campaign_id, req_slots=None,
                        grid_override=None):
        """按 GridBattle 配置生成一关的 enemyData / playerData。

        grid_override：天梯关卡不走 "Campaign_<id>" 命名，直接把
        StairsBattle.GridBattle 对应的那行 GridBattle 传进来复用。
        """
        grid_t, enemy_t, hero_t, skill_t = self.config_tables()
        grid = grid_override or grid_t.get('Campaign_%s' % campaign_id)

        if not grid:
            self.w('!! 没有 %s 的 GridBattle 配置' % campaign_id)
            return None

        try:
            area = json.loads(grid.get('EnemyPositonArea') or '[]')
        except Exception as ex:
            self.w('!! EnemyPositonArea 解析失败 %r' % ex)
            return None

        level = int(float(grid.get('Level') or 1))
        star = int(float(grid.get('Star') or 1))
        power = int(float(grid.get('CombatEffectiveness') or 1000))
        coef = {}
        try:
            coef = json.loads(grid.get('AttrCoef') or '{}')
        except Exception:
            pass

        base_attrs = {'MaxHP': 3000, 'Atk': 300, 'PDef': 200, 'MDef': 200, 'MaxMP': 1000}

        # [调数值] 玩家侧属性，集中在这里方便调。
        #
        # 历史：attrs(20) 全属性放大 -> Atk=6000 对敌方 HP=3000 一击秒杀，
        # 战斗 9 秒结束，战斗内引导 Step36 来不及执行 -> 引导重播。
        # 后来压到 Atk=300（等于敌方原始值），战斗够长但赢得太慢。
        # 现在取 900：约 3~4 下打死一只 3000 血的怪，战斗时长对引导仍然够用，
        # 但胜得快。改这一个数就能调战斗节奏。
        # 敌方基准见上面 attrs(1.0) = {MaxHP:3000, Atk:300, PDef:200, MDef:200}。
        PLAYER_ATTR = {'MaxHP': 60000, 'Atk': 900, 'PDef': 2000, 'MDef': 2000,
                       'MaxMP': 5000}

        def player_attrs(coef):
            out = {'CriDmg': 15000, 'BlkDmg': 9000}
            for k, v in PLAYER_ATTR.items():
                out[k] = int(v * (coef.get(k, 1) or 1))
            return out
        Server.player_attrs = staticmethod(player_attrs)

        def attrs(scale):
            out = {}
            for k, v in base_attrs.items():
                out[k] = int(v * scale * (coef.get(k, 1) or 1))
            out['CriDmg'] = 15000
            out['BlkDmg'] = 9000
            return out

        # 【避开特殊地形格】203 关里有 105 关的 landformSP 会盖住
        # PlayerPositonArea 的头两格。英雄/友军站上去就会触发地形技能，而
        # 地形脚本 SpecialTerrain_*_Effect 里是：
        #     local target = _env.params.unit
        #     global.PerformAngerValueOnTarget(_env, target, 350)   -- target 可能是 nil
        #     global.ApplyBuff(_env, target, {...})
        # 崩在 AngerSystem 里（PerformActionValueOnTarget -> target:getId()）。
        # 实测 C00S04 崩在 SpecialTerrain_XinShouHuiNeng0_4_2.lua:174/176。
        #
        # 对照已验证能跑通的 C00S01 写死响应：英雄在 (2,3)，而该关 landformSP
        # 只有 "1_2"/"2_2" 两格 —— 正好都不压地形。
        # 必须在下面拼友军之前算好，因为友军也用 area 里的配置坐标。
        terrain_xy = set()
        try:
            _map = json.loads(grid.get('MapDataId') or '{}')
            for _k in (_map.get('landformSP') or {}):
                _kx, _ky = _k.split('_')
                terrain_xy.add((int(_kx), int(_ky)))
        except Exception:
            pass

        enemies = []
        friends = []
        idx = 0
        skipped_friend = 0
        for slot in area:
            unit = slot.get('enemy') or slot.get('friend')
            if not unit:
                continue
            idx += 1
            is_enemy = 'enemy' in slot
            # 友军跟玩家同阵营（下面会被并进 player_heros），压地形一样会
            # 触发上面那个地形技能崩掉，所以直接不摆。敌方在 x>=4 一侧，
            # 地形基本都在左侧，但为了稳妥同样跳过。
            _sx, _sy = int(slot.get('x', 0)), int(slot.get('y', 0))
            if (_sx, _sy) in terrain_xy:
                skipped_friend += 1
                self.w('   %s 跳过压地形的%s %s @(%d,%d)'
                       % (campaign_id, '友军' if not is_enemy else '敌方',
                          unit, _sx, _sy))
                continue
            cfg = enemy_t.get(unit) if is_enemy else hero_t.get(unit)

            if not cfg and not is_enemy:
                real_id = Server.resolve_hero_id(unit)
                cfg = hero_t.get(real_id)
                if cfg:
                    unit = real_id

            if not cfg:
                self.w('!! 单位 %s 不在配置表里' % unit)
                continue
            try:
                skills = json.loads(cfg.get('Skill') or '{}')
            except Exception:
                skills = {}
            hero = self._hero_base(
                cid=unit,
                uid='%d_%d' % (200001 if is_enemy else 150001, idx),
                camp=2 if is_enemy else 1,
                x=int(slot.get('x', 0)), y=int(slot.get('y', 0)),
                level=level, star=star,
                model_id=cfg.get('Resource'),
                element=cfg.get('Element'),
                profession=self.pick_profession(cfg, is_enemy),
                skills=skills if skills else self.hero_skills(skill_t, unit),
                body=self._change_body(cfg),
            )
            hero['combat'] = max(1000, power // max(1, len(area)))
            hero['attrs'] = attrs(1.0)
            (enemies if is_enemy else friends).append(hero)

        # 玩家侧：**只放编队里的英雄**，不是全部已拥有的英雄。
        #
        # 之前这里遍历 `owned`（full unlock 下是 60 个），于是每场战斗我方
        # 派出 60+ 个单位 —— 战斗表现完全不对（而且 totalCombat 会被撑爆）。
        # 编队从 player.datas.Teams.teams[id].team 取，形状由客户端
        # TeamsSystem:getTeamById(:123-131) 确认：teams[id].team 才是英雄表。
        #
        # 取不到编队时（首次进入、玩家还没存过队）退回"第一个已拥有英雄"，
        # 至少保证战斗能跑起来，而不是摆 60 个单位。
        owned = {}
        try:
            owned = (self.table['10001']['data']['player']['datas']
                     ['HeroesData']['heroes']) or {}
        except Exception:
            owned = {}

        # 槽位（含玩家摆的 x/y），和 team_hero_ids 同序，用来定站位
        team_slots = self.cur_team_slots()
        team_hero_ids = self.player_team_hero_ids()

        # 【优先用请求自带的编队】14002 请求里就带着玩家选的上场角色，
        # 比服务端存的（29001）更贴近当下：玩家改完队直接开打、没点保存时，
        # 只有请求里这份是对的。实测 C01S02 的请求带的是 LaJ，
        # 而服务端存的是默认的 AnWZ/BaiJ —— 不读请求就上场错人。
        cap = self.team_max_num(campaign_id)
        if req_slots:
            req_ids = [s['heroId'] for s in req_slots][:cap]
            if req_ids:
                # 【不足要补齐】请求里第 2 个以后的队员是紧凑打包的
                # （实测 C01S04 第二成员键是 "La6\x3f..."，不是英雄 id，
                #  技能 blob 里还有 ShiZ/MoG 这类名字不能乱认），
                # 所以有时只能解出 1 个。绝不能因此只派一个人上场 ——
                # 用户实测就是"只会上一个角色"。缺的用服务端编队补。
                saved_ids = self.player_team_hero_ids()
                fill_from = [h for h in saved_ids if h not in req_ids]
                missing = cap - len(req_ids)
                # 补齐也不能拿默认那对来凑 —— 玩家看到的就是"一个默认一个我选的"。
                # 优先用玩家拥有的其它角色（排除自动补的默认），再退回服务端编队。
                defaults = set(Server.DEFAULT_TEAM_HERO_IDS or ())
                spare = [h for h in sorted(owned) if h not in req_ids
                         and h not in defaults]
                fill_from = spare or fill_from
                if missing > 0 and fill_from:
                    top = fill_from[:missing]
                    self.w('   %s 请求只解出 %d 个（%s），补 %s'
                           % (campaign_id, len(req_ids), req_ids, top))
                    req_ids = req_ids + top
                    team_slots = list(req_slots[:cap])
                    for h in top:
                        src = next((s for s in self.cur_team_slots()
                                    if s['heroId'] == h), None)
                        team_slots.append(src or {'heroId': h, 'x': None,
                                                  'y': None})
                self.w('   %s 用请求自带编队 %s（覆盖服务端存的 %s）'
                       % (campaign_id, req_ids, team_hero_ids))
                team_hero_ids = req_ids
                team_slots = team_slots[:cap]

        if team_hero_ids:
            # 只保留真正拥有的（配置表可能给出玩家没有的英雄）
            keep = [h for h in team_hero_ids if h in owned]
            for dropped in (h for h in team_hero_ids if h not in owned):
                self.w('   编队里的 %s 不在 HeroesData，剔掉（玩家会看到少人）'
                       % dropped)
            team_hero_ids = keep
        if not team_hero_ids and owned:
            team_hero_ids = [sorted(owned)[0]]
            self.w('   编队为空，暂用 %s 一个角色参战' % team_hero_ids[0])
        # 过滤后长度可能变了，槽位要跟着对齐
        if len(team_slots) != len(team_hero_ids):
            by_id = {s['heroId']: s for s in team_slots}
            team_slots = [by_id.get(h, {}) for h in team_hero_ids]
        self.w('   %s 出战编队 = %s' % (campaign_id, team_hero_ids))

        # 站位取 PlayerPositonArea 的格子（我方站位），并避开地形格。
        # terrain_xy 已在上面拼友军之前算好。
        spots = []
        skipped_terrain = 0
        try:
            for a in json.loads(grid.get('PlayerPositonArea') or '[]'):
                p = (int(a.get('x', 1)), int(a.get('y', 1)))
                if p in terrain_xy:
                    skipped_terrain += 1
                    continue
                spots.append(p)
        except Exception:
            spots = [(1, 1)]
        if skipped_terrain:
            self.w('   %s 跳过 %d 个压地形的我方站位，剩 %d 个'
                   % (campaign_id, skipped_terrain, len(spots)))
        if not spots:
            spots = [(1, 1)]

        player_heros = []
        for i, cid in enumerate(team_hero_ids):
            info = owned.get(cid) or {}
            cfg = hero_t.get(cid, {})
            # 优先用玩家在编队界面摆的坐标（29001 存的 slot.x/slot.y）。
            # 摆位会避开地形吗？不会 —— 玩家能摆哪就摆哪，所以这里仍要
            # 校验：压在 landformSP 上时回退到 spots 里的安全格。
            sx = sy = None
            if i < len(team_slots):
                sx, sy = team_slots[i].get('x'), team_slots[i].get('y')
            if sx is not None and sy is not None:
                if (int(sx), int(sy)) in terrain_xy:
                    self.w('   %s 编队位 (%s,%s) 压地形，改用默认站位'
                           % (campaign_id, sx, sy))
                    sx = sy = None
            if sx is not None and sy is not None:
                x, y = int(sx), int(sy)
            else:
                x, y = spots[i] if i < len(spots) else (1, 1 + i)
            h = self._hero_base(
                cid=cid, uid='100001_%d' % (i + 1), camp=1, x=x, y=y,
                level=int(info.get('level') or level), star=int(info.get('star') or 5),
                model_id=cfg.get('Resource') or ('C_' + cid),
                element=cfg.get('Element') or 'FIRE',
                profession=self.pick_profession(cfg, False),
                skills=self.hero_skills(skill_t, cid),
                body=self._change_body(cfg),
            )
            h['adv'] = int(info.get('adv') or 1)
            h['combat'] = int(info.get('combat') or 60000)
            # [调数值] 玩家侧只放大血量/防，攻击单独一档（PLAYER_ATTR.Atk=900）。
            # 原因：第二关的战斗内引导 Step36（点戈琳）/Step36_1（佩璐对话）必须
            # 在战斗中有时间执行，而之前玩家 Atk=6000 对敌方 HP=3000 是 2 倍溢出、
            # 一击秒杀，整场 9 秒就结束（14002 13:42:03 -> 14003 13:42:14），
            # Step36 根本没机会触发，引导就跳回结算剧情 Step16 重播整段。
            # Atk 调到 900（约 3~4 下打死一只怪），既能快速取胜又留足引导时间。
            h['attrs'] = Server.player_attrs(coef)
            player_heros.append(h)

        # 友方单位并进我方阵营（配置里 friend 是跟玩家一起的友军）
        for h in friends:
            h['camp'] = 1
            player_heros.append(h)

        return {
            'campaignId': campaign_id,
            'gridBattleId': 'Campaign_%s' % campaign_id,
            'logicSeed': 123456,
            'param': {'repeatedDefeats': 0},
            'playerData': {
                'rid': 100001, 'uid': 100001,
                'totalCombat': sum(h['combat'] for h in player_heros) or 60000,
                'heros': player_heros,
            },
            'enemyData': {
                'uid': 200001, 'rid': 200001,
                'totalCombat': sum(h['combat'] for h in enemies) or power,
                'heros': enemies,
            },
        }

    def w(self, s):
        line = '%s %s' % (time.strftime('%H:%M:%S'), s)
        self.logf.write(line + '\n')
        self.logf.flush()
        print(line, flush=True)

    # ---------------- 握手
    def handle_spki(self, conn, payload):
        spki_len = struct.unpack('>H', payload[0:2])[0]
        spki = payload[2:2 + spki_len]
        pk = serialization.load_der_public_key(spki)
        n = pk.public_numbers()
        self.w('  客户端 SPKI: len=%d RSA-%d e=%d' % (spki_len, n.n.bit_length(), n.e))
        self.w('  n = %x' % n.n)
        open(os.path.join(self.cfg.out, 'client_spki.der'), 'wb').write(spki)

        plain = (struct.pack('>H', len(self.session_key)) + self.session_key +
                 bytes([self.cfg.algo]))
        ct = pk.encrypt(plain, padding.PKCS1v15())
        self.w('  回 type=3: 明文 %d B = u16(%d)+key(%d)+algo(%d)，密文 %d B'
               % (len(plain), len(self.session_key), len(self.session_key),
                  self.cfg.algo, len(ct)))
        conn.sendall(frame(ct, T_HS_IN))

    # ---------------- RPC
    def parse_request(self, data):
        """data -> dict

        Layout pinned from a real capture (crc32/plainlen stripped):
            [0]     kind = 1
            [1]     compression
            [2:6]   i32 req_id
            [6:10]  i32 unknown (observed 0)
            [10:14] i32 opcode        <-- NOT [6:10]; getting this wrong makes
            [14:18] u32 body_len      <-- the server read opcode as 0 and
            [18:]   body                body_len as the opcode, silently falling
                                         back to the "default" response.
        """
        if len(data) < 18:
            return None
        kind = data[0]
        comp = data[1]
        req_id = struct.unpack_from('>i', data, 2)[0]
        opcode = struct.unpack_from('>i', data, 10)[0]
        blen = struct.unpack_from('>I', data, 14)[0]
        body = data[18:18 + blen]
        return dict(kind=kind, comp=comp, req_id=req_id, opcode=opcode,
                    blen=blen, body=body, tail=data[18 + blen:])

    RESP_KEYS = ('resCode', 'data', 'd', 'del')

    # ------------------------------------------------------------ 调试面板
    #
    # 指令体在 app 信封的 rest 里：{"cmd":["FuncName","参数1","参数2",...]}
    # 按字节抽，理由同抽卡（客户端 JSON 带坏字节）。
    CMD_RE = re.compile(rb'"cmd"\s*:\s*\[')
    CMD_ITEM_RE = re.compile(rb'"((?:[^"\\]|\\.)*)"')

    def parse_cmd(self, req):
        """-> (FuncName, [参数...]) 或 (None, [])。

        DebugBoxMediator 传的 params 是 Lua table 的 {名字, 值...}，
        值多数是字符串（面板输入框/下拉框给的都是文本）。
        """
        for raw in (req.get('body') or b'', req.get('app_raw') or b''):
            m = self.CMD_RE.search(raw)
            if not m:
                continue
            # 从 cmd 的 '[' 往后扫到配对的 ']'，逐个抽字符串字面量。
            i = m.end()
            depth = 1
            items = []
            cur = None
            while i < len(raw) and depth > 0:
                c = raw[i:i + 1]
                if c == b'[':
                    depth += 1
                elif c == b']':
                    depth -= 1
                    if depth == 0:
                        break
                elif c == b'"':
                    mi = self.CMD_ITEM_RE.match(raw, i)
                    if not mi:
                        break
                    items.append(mi.group(1).decode('utf-8', 'replace'))
                    i = mi.end()
                    continue
                i += 1
            if items:
                return items[0], items[1:]
        return None, []

    def build_debug_response(self, req):
        """10032 的应答。只认白名单里的开关名，不做任何 eval。"""
        name, args = self.parse_cmd(req)
        self.w('   10032 cmd=%r args=%r' % (name, args))
        if not name:
            return {'resCode': 1, 'data': '无法解析 cmd'}

        if name == 'debugConfigReset':
            for k in self.DEBUG_TOGGLES:
                setattr(Server, k, DEFAULTS[k])
            self.save_debug_config()
            player = self.rebuild_player()
            return {'resCode': 0, 'data': '已恢复默认配置',
                    'd': {'player': player}}

        if name != 'debugConfig':
            # 其余是游戏自己的调试指令（addHero / campaign / chapter ...），
            # 它们要真服务端，这里不实现。
            return {'resCode': 1,
                    'data': '未实现的指令: %s（当前只支持 debugConfig）' % name}

        if len(args) < 2:
            return {'resCode': 1, 'data': '用法: debugConfig <开关名> <值>'}
        key, raw_val = args[0], args[1]
        if key not in self.DEBUG_TOGGLES:
            return {'resCode': 1,
                    'data': '未知开关 %r（可用: %s）'
                            % (key, ', '.join(sorted(self.DEBUG_TOGGLES)))}
        try:
            val = self.cast_toggle(key, raw_val)
        except Exception as ex:
            return {'resCode': 1, 'data': '%s 取值非法: %s' % (key, ex)}

        old = getattr(Server, key)
        if val == old:
            return {'resCode': 0, 'data': '%s 已经是 %r' % (key, val)}

        setattr(Server, key, val)
        self.save_debug_config()
        apply_fn = self.apply_for_key(key)
        self.w('   调试配置 %s: %r -> %r，重跑 %s'
               % (key, old, val, apply_fn))
        player = self.rebuild_player()
        return {'resCode': 0,
                'data': '%s: %r -> %r' % (key, old, val),
                'd': {'player': player}}

    # ------------------------------------------------------------ 抽卡
    def build_gacha_response(self, req):
        """15001 的应答。抽卡结果完全由 Gacha/GachaRoute/Reward 三张表推出。"""
        raw = req.get('app_raw') or b''
        gacha_id, is_ten = gacha_params(raw)
        self.w('   15001 raw rest (%d B) = %s' % (len(raw), raw[:90]))
        self.w('   15001 解析出 gachaId=%r isTen=%s' % (gacha_id, is_ten))

        if not self.gacha.ok:
            self.w('   15001 抽卡表没加载成功，直接兜底')
            return {'resCode': 0, 'data': {'result': [[]], 'autoSave': False}}

        pool = self.gacha.pool(gacha_id)
        if not pool:
            # 兜底而不是报错：result 里出现空组会让客户端
            # CardPoolRewardMediator:215 的 maxStar < v.initStar 拿 nil 比较直接崩。
            fb = 'Gacha_Base' if self.gacha.pool('Gacha_Base') else None
            if not fb:
                self.w('   15001 未知卡池 %r 且无兜底池' % gacha_id)
                return {'resCode': 1, 'data': {}}
            self.w('   15001 卡池 %r 解析不出来，回退到 %s' % (gacha_id, fb))
            gacha_id = fb
            pool = self.gacha.pool(gacha_id)

        # 每个卡池一份抽卡状态：TIMES 计数、ONCE2/REPEATONCE 的已用池
        st = self.gacha_state.setdefault(gacha_id, self.gacha.new_state())

        is_first = self.gacha_is_first(gacha_id, st)

        result, err = self.gacha.draw(gacha_id, is_ten, st)
        if err or not result or not any(result):
            self.w('   15001 %s: %s' % (gacha_id, err))
            return {'resCode': 1, 'data': {}}

        coupon, cost = self.gacha.cost_of(gacha_id, is_ten, is_first)
        self.w('   15001 卡池=%s 十连=%s 消耗=%s x%s 首抽=%s'
               % (gacha_id, is_ten, coupon, cost, is_first))
        for i, grp in enumerate(result):
            self.w('      #%d %s' % (i, ', '.join(
                '%s %s x%s' % (r['type'], r['code'], r['amount']) for r in grp)))

        st['total'] = st.get('total', 0) + len(result)
        st['today'] = st.get('today', 0) + len(result)
        if is_ten:
            st['ten'] = st.get('ten', 0) + 1
        st['gachaTimes'] = st.get('gachaTimes', 0) + 1

        return {
            'resCode': 0,
            'data': {
                'result': result,
                'autoSave': False,
                # 顺带回一份池子状态，客户端不读，但方便抓包核对
                'gachaponInfos': self.gacha_infos(),
            },
        }

    def gacha_is_first(self, gacha_id, st):
        """CardPoolSystem:getCardIsFirst —— gacha10Times.GACHA_ID_ALL >= 1 就不算首抽。"""
        return (st.get('ten', 0)) < 1

    def gacha_infos(self):
        """把服务端抽卡状态整成客户端 10001 里同形状的 gachaponInfos。"""
        base = {}
        p = self.table.get('10001')
        if isinstance(p, dict):
            datas = (p.get('data') or {}).get('player', {}).get('datas', {})
            gi = (datas.get('GachaponData') or {}).get('gachaponInfos')
            if isinstance(gi, dict):
                base = gi
        out = {}
        for gid, v in base.items():
            out[gid] = dict(v) if isinstance(v, dict) else v
        for gid, st in self.gacha_state.items():
            cur = out.setdefault(gid, {})
            cur['total'] = st.get('total', 0)
            cur['today'] = st.get('today', 0)
            cur['ten'] = st.get('ten', 0)
            cur['gachaTimes'] = st.get('gachaTimes', 0)
            cur['gacha10Times'] = {'GACHA_ID_ALL': st.get('ten', 0)}
            cur.setdefault('open', True)
            cur.setdefault('resetNum', 0)
            cur.setdefault('receivedId', '')
            cur.setdefault('rewards', {})
        return out

    def build_response(self, req, ts):
        opcode = req['opcode']
        spec = self.table.get(str(opcode))
        if spec is None:
            spec = self.table.get('default')
        if spec is None:
            resp = {'resCode': 0, 'data': {}}
        elif isinstance(spec, dict) and 'raw' in spec:
            resp = json.loads(spec['raw'])
        else:
            resp = spec

        # Strip documentation keys. opcodes_table.json uses `_note` / `_comment`
        # / `_bug` etc. as inline explanations, and they sit at the same level as
        # resCode/data -- so the whole spec used to be sent to the client verbatim,
        # dumping our notes into the game. Only these four keys are real protocol.
        if isinstance(resp, dict):
            junk = [k for k in resp
                    if k not in self.RESP_KEYS and
                    (k.startswith('_') or k in ('note', 'comment', 'desc', 'fields',
                                               'required', 'schema', 'bug', 'chain',
                                               'chain2', 'resIds', 'gridConfig',
                                               'taskTypes', 'heroIds', 'bug2'))]
            if junk:
                self.w('   (丢弃说明字段 %s)' % junk)
            resp = {k: v for k, v in resp.items() if k in self.RESP_KEYS}

        # 15001 = 抽卡。请求参数在 app 信封的 rest 里：{"gachaId":"...","isTen":true}
        # 响应被客户端这样消费（CardPoolModel:formatCardPoolData + CardPoolSystem:148-150）：
        #     data.result   -> N 组奖励的数组（N = isTen ? 10 : 1）
        #     data.autoSave -> 是否自动存档这抽记录
        if opcode == 15001:
            resp = self.build_gacha_response(req)

        # 14002：按 campaignId 从 GridBattle 配置生成战斗数据。
        # 表里那份写死的 C00S01 响应保持原样不动（第一关已实测能跑通），
        # 只有打到别的关卡才走生成逻辑，避免动到已验证的路径。
        if opcode == 14002:
            body = req.get('body') or b''
            camp = self.extract_campaign(body)
            self.w('   14002 campaignId=%s' % camp)
            # 记下来给 14003 用：结算请求体里没有 campaignId（blen=15）
            if camp:
                self.last_campaign = camp

            # 【关键】请求体里**带着玩家当前编队**，形状
            #   {"campaignId":...,"battleData":{"leaderSkills":{},"teams":{...}},...}
            # 日志实测（C01S02）：
            #   ...,"teams":{"LaJ\x01"\x18y":2,"i"\x01D<LaJ","x":1,"hero...
            # 也就是说玩家选谁上场，是随每次战斗请求一起发过来的 ——
            # 比等服务端存的 29001 编队更直接，也不依赖玩家有没有点保存。
            req_slots = self.parse_battle_teams(body)
            if req_slots:
                self.w('   14002 请求自带编队 = %r' % (req_slots,))
            else:
                self.w('   14002 请求里没解出编队，用服务端存的')

            if camp and camp != 'C00S01':
                # 【持久化玩家选择】客户端从来不发 29001（实测多关日志里一次都
                # 没有），玩家选好的队只出现在 14002 请求体里。所以解出来之后
                # 立刻存回 team_state.json，之后每关直接复用，不用重新选。
                if req_slots:
                    self.remember_team_from_request(camp, req_slots)
                gen = self.gen_battle_data(camp, req_slots=req_slots)
                if gen:
                    self.w('   14002 按配置生成 %s：敌方 %d 个，友方 %d 个' % (
                        camp, len(gen['enemyData']['heros']),
                        len(gen['playerData']['heros'])))
                    resp = {'resCode': 0, 'data': gen}

        # 29001 = 改编队。TeamsService:requestSetTeams(:11-15) newRequest(29001, params)
        # params 由 TeamMediator:saveEditCallBack(:214-221) 组装：
        #     {name=, id=, teams=getCurTeam(), leaderSkills=}
        # getCurTeam()（TeamGroundWidget:5170-5176）返回
        #     curTeams[heroData.uid] = {heroId=, id=, x=, y=, type=}
        # 不实现它，玩家换的角色就存不下来 -> 上场角色不跟随玩家选择。
        # TeamsSystem:requestSetTeams(:22) 只判 resCode == GS_SUCCESS，
        # 所以必须回 0；再带一份 d.player 让 TeamsModel:synchronize 生效。
        if opcode == 29001:
            tid, slots = self.parse_set_teams(req.get('body') or b'')
            if not slots:
                self.w('   29001 没解出英雄，回原编队（不吞）')
            else:
                teams = self.apply_set_teams(tid, slots)
                if teams is not None:
                    resp = {'resCode': 0, 'data': {},
                            'd': {'player': self.table['10001']['data']['player']}}

        # 14003 = 主线战斗结算。第二关过不去的根因在这里：
        # CampaignData.lastPassed 不推进，客户端 CampaignModel:synchronize(:289)
        #   if data.lastPassed then self._curFinishStage = data.lastPassed end
        # 停在 C00S01，于是 C00S02 打赢了也不算通关。
        # 14003 的请求体只有 15 B（日志里 blen=15），campaignId 不在里面，
        # 所以用 14002 记下的最近一场关卡。
        if opcode == 14003:
            camp = self.extract_campaign(req.get('body') or b'') or self.last_campaign
            if camp:
                nxt = self.campaign_next(camp)
                # 1) 先写回 10001 的表里，这样重登 / 下一包 10001 也不会退回旧进度
                pdata = self.table.get('10001', {}).get('data', {})
                pl = pdata.get('player')
                if isinstance(pl, dict):
                    cd = pl.setdefault('datas', {}).setdefault('CampaignData', {})
                    cd.update(self.build_campaign_progress(camp))
                    # 1a) 记进 passed 并落盘 —— 否则重启 mock 就退回初值 C00S01
                    self.campaign_passed.add(camp)
                    Server.save_campaign_state(self.campaign_passed)
                    self.w('   14003 结算 %s -> 下一关 %s（已写回表 + 落盘 %d 关）'
                           % (camp, nxt, len(self.campaign_passed)))
                    # 1b) branchLastPassed 按章节取最靠后的已通关关
                    #     （分支关卡 CxxMxx 的 Order 是空的，不能拿它当章节进度）
                    blp = {}
                    for p in self.campaign_passed:
                        ch = self.campaign_chapter(p)
                        if not ch:
                            continue
                        cur = blp.get(ch)
                        if not cur or self.campaign_order_rank(p) > \
                                self.campaign_order_rank(cur):
                            blp[ch] = p
                    if blp:
                        cd['branchLastPassed'] = blp
                    # 2) 回整份 player，形状同 build_debug_response（:2523-2525）。
                    #    不用增量是因为客户端 syncPlayer 是整块覆盖还是逐字段合并
                    #    在解出来的 lua 里查不到（Service.lua 没被反编译出来），
                    #    而整份 player 是 10032 已实测生效的形状。
                    resp['d'] = {'player': pl}
                    self.w('   14003 CampaignData=%r'
                           % json.dumps(cd, ensure_ascii=False))

        # 21001 = LADDER_FIGHT_STAR（天梯挑战一关）。
        # 请求体 {"id":"T24S40","battleData":{teams...}}，id 是 StairsBattle 的 rowId。
        #
        # 应答的 data 必须是一份完整战斗数据，因为客户端直接拿它开战：
        #   LadderSystem:requestEnterBattle(:920-937)
        #       requestLadderFightStar(params, ...) ->
        #           self:enterStageBattle(response.data, leaveTeamView)
        #   LadderSystem:enterStageBattle(:1096-1097)
        #       local campaignId = data.campaignId or data.id
        #       local gridBattleId = data.gridBattleId or self:getGridBattleID(campaignId)
        # 之前我们只回 {"resCode":0,"data":{}}，于是 data.id / data.gridBattleId
        # 都是 nil -> getGridBattleID(nil) ->
        #     assert(battleData, "battleData:" .. tostring(id))   -- :1073
        # 直接崩（实测报错就是 battleData:nil）。
        #
        # 复用主线的 gen_battle_data：GridBattle 里同样有 StairsBattle 指向的
        # 地图（StairsBattle.tsv 的 GridBattle 列），形状一致。
        if opcode in (21001, 21005):
            bid = self.extract_stairs(req.get('body') or b'')
            self.w('   %d 天梯 id=%s' % (opcode, bid))
            gen = self.gen_stairs_battle_data(bid) if bid else None
            if gen:
                resp = {'resCode': 0, 'data': gen}
            else:
                # 兜底：至少把 id/gridBattleId 回上，客户端能用配置表自己开
                grid = self.stairs_grid_battle(bid) if bid else None
                resp = {'resCode': 0,
                        'data': {'id': bid, 'gridBattleId': grid,
                                 'campaignId': bid, 'logicSeed': 123456}}

        # 21002 = LADDER_FIGHT_END（天梯战斗结算）。
        # 请求体是空的（blen=15），胜负完全由我们回什么决定。
        #
        # 现象：打赢被判失败。客户端判定链（LadderSystem:948-989）：
        #     local responseData = response.data
        #     if not responseData or responseData.withdraw then return end
        #     if responseData and responseData.reviewFailed then ... end
        #     if responseData and responseData.pass then
        #         view = battleSuccessView
        #     else
        #         view = battleFailedView        -- ← 之前落到这里
        #     end
        #     ...
        #     rewards = responseData.passReward
        #
        # 我们原来回通用 {"resCode":0,"data":{}}，pass 是 nil -> 走失败分支。
        # 离线服没有校验，直接判通关。
        if opcode == 21002:
            rewards = self.table.get('14003', {}).get('data', {}).get(
                'passReward') or []
            resp = {'resCode': 0, 'data': {
                'pass': True,
                'firstPass': True,
                'withdraw': False,
                'reviewFailed': False,
                'passReward': rewards,
            }}
            self.w('   21002 结算：判通关，奖励 %d 项' % len(rewards))

        # 10027 = 引导步上报。guideId 在 **app 信封**（rest）里，不在 req['body']
        # （10027 的 body 长度是 0），所以用 handle_data 传进来的 app_raw。
        if opcode == 10027:
            self.w('   [哨兵] 进入 10027 钩子 len(body)=%d len(app_raw)=%d'
                   % (len(req.get('body') or b''), len(req.get('app_raw') or b'')))
            # 重要：guideId 在 **req['body']** 里。
            # parse_app_body 把这段拆成 (ver, rid, rest, tail)，但 guideId
            # 被并进了 **rid**，所以 rest 是空的：
            #     app: ver=9 rid='ester_11{"guides":[{"guideId":"Guide1_Step27"}]}'
            #     params(raw 0 B)          <-- 这个 0 是 rest，不是 body
            #     blen=65                    <-- body 其实有 65 字节
            # 当初看到 params(raw 0 B) 就认为 body 为空，改用 app_raw
            # 反而更坏（app_raw = rest = 空）。直接扫 body 最稳。
            self.track_guide(req.get('body') or b'')

        # 10032 = 调试面板指令通道（DebugBoxService:OPCODE_DATA_MODIFICATION）。
        # 请求体 {cmd = [FuncName, 参数...]}，DebugBoxMediator:180-220 组装。
        # 应答里的 d.player 走 Service.lua:71-77 -> syncPlayer 自动同步回客户端，
        # 所以这里改完开关直接回一整份新 player，客户端立刻可见。
        if opcode == 10032:
            resp = self.build_debug_response(req)

        # 10038 changeHero = 设置主屏助理。
        # 调用链：HomeCenterWidget:759 的确认回调 ->
        #   CustomDataSystem:ChangeHero({heroId, resourceType}) ->
        #   CustomDataService:requestChangeHero -> opType.changeHero = 10038
        # resourceType 就是 SelectPanelWidget 的 tab pageName
        # (HomeCenterWidget:718 self._selectHeroType = pageName)，
        # 取值 L2D / Por_Spine / Illustration，与 Player:getScreenHero()
        # 返回的 screenType 是同一套字符串。
        #
        # 为什么必须回这个 diff：客户端自己只检查 resCode
        # (CustomDataSystem:119)，真正的状态更新靠通用应答分发
        #   Service.lua:71-77  response.d -> EVT_SYNCHRONIZE_DIFF
        #   -> DevelopSystem:syncPlayer -> BasePlayer:synchronizeInfoDiff
        #      (:224-230 写 _mainScreenType / _mainScreenHeroId)
        # 画面之所以会变，是 SelectPanelWidget 的三个 callback 直接调了
        # changeLive2d / changeSpine / changeIllustration 换模型；
        # 但 Player 上的 heroId 还是旧的，于是
        # getCurScreenHeroInfo() -> getScreenHero() 给**旧角色**播语音
        # (HomeCenterWidget:591 / :611 / :830)。
        # 这就是"换了助理但语音还是上一个"。
        if opcode == 10038:
            hero_id, res_type = change_hero_params(req.get('body') or b'',
                                                   req.get('app_raw') or b'')
            self.w('   10038 changeHero heroId=%r resourceType=%r'
                   % (hero_id, res_type))
            known = set(self.hero_ids())
            if hero_id and hero_id not in known:
                self.w('   10038 heroId %r 不在 Character.tsv 里，忽略' % hero_id)
                hero_id = ''
            if hero_id:
                if res_type not in SCREEN_TYPES:
                    # 只切了角色没带形态（或带了非法值）时沿用当前形态
                    res_type = self.main_screen.get('type') or 'Por_Spine'
                    self.w('   10038 resourceType 非法/缺失，沿用 %r' % res_type)
                self.main_screen = {'heroId': hero_id, 'type': res_type}
                self.save_main_screen(self.main_screen)
                self.w('   10038 主屏助理 = %s / %s' % (hero_id, res_type))
            cur = self.main_screen
            resp = {
                'resCode': 0,
                'data': {},
                'd': {'player': {
                    'mainScreenHeroId': cur.get('heroId', ''),
                    'mainScreenType': cur.get('type', ''),
                }},
            }

        # 10001 玩家同步里下发引导进度（否则客户端判定服务端进度为 0）
        if opcode == 10001:
            self.w('   [哨兵] 进入 10001 钩子')
            gd = self.guide_data()
            if gd and isinstance(resp, dict) and isinstance(resp.get('data'), dict):
                player = resp['data'].get('player')
                if isinstance(player, dict):
                    player['guideData'] = gd
                    self.w('   10001 下发 guideData=%s' % json.dumps(gd, ensure_ascii=False))
            # 重连后要把玩家上次选的主屏助理带回来，否则 10001 的表内初值
            # (LaJ / Por_Spine) 会盖掉 10038 的选择。
            if (isinstance(resp, dict) and isinstance(resp.get('data'), dict)
                    and self.main_screen.get('heroId')):
                player = resp['data'].get('player')
                if isinstance(player, dict):
                    player['mainScreenHeroId'] = self.main_screen['heroId']
                    player['mainScreenType'] = self.main_screen.get('type') or \
                        player.get('mainScreenType')
                    self.w('   10001 下发主屏助理 %s / %s'
                           % (player['mainScreenHeroId'], player['mainScreenType']))

        body = json.dumps(resp, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        return (bytes([R_KIND_RESPONSE, 0]) +
                struct.pack('>i', req['req_id']) +
                struct.pack('>q', ts) +
                struct.pack('>i', 0) +
                struct.pack('>h', 0) +
                struct.pack('>I', len(body)) + body)

    def handle_data(self, conn, payload):
        crc, plainlen = struct.unpack('>II', payload[:8])
        data = payload[8:8 + plainlen]
        got = zlib.crc32(data) & 0xFFFFFFFF
        self.w('  data: crc32=%08x(%s) plainlen=%d 实收=%d'
               % (crc, 'OK' if got == crc else 'BAD', plainlen, len(data)))
        req = self.parse_request(data)
        if not req:
            self.w('   !! 载荷太短，无法当 RPC 解析')
            return
        self.nreq += 1
        ver, rid, rest, _ = parse_app_body(req['body'])
        # 引导上报(10027)的 guideId 在 app 信封里而不在 req['body']（body 长度为 0），
        # 把它挂到 req 上给 build_response 用。只记引导相关的 opcode，代价可忽略。
        req['app_raw'] = rest
        if opcode_is_gacha(req.get('opcode')):
            # 抽卡的 app 信封前缀长度与其他 opcode 不一致，字面量日志不可信。
            # 落一份原始二进制文件，确认字节序只能靠这东西。
            try:
                gp = os.path.join(self.cfg.out, 'gacha_body.bin')
                with open(gp, 'wb') as fh:
                    fh.write(req.get('body') or b'')
                self.w('   15001 raw body -> %s (%d B)'
                       % (gp, len(req.get('body') or b'')))
            except Exception as ex:
                self.w('   15001 raw body 落盘失败: %r' % (ex,))
        self.w('   #%d REQ opcode=%d req_id=%d kind=%d comp=%d blen=%d tail=%d'
               % (self.nreq, req['opcode'], req['req_id'], req['kind'],
                  req['comp'], req['blen'], len(req['tail'])))
        self.w('     app: ver=%s rid=%r' % (ver, rid))
        try:
            j = json.loads(rest.decode('utf-8', 'replace'))
            self.w('     params: %s' % json.dumps(j, ensure_ascii=False)[:600])
        except Exception:
            # 这个协议不是纯 JSON：值里会混进二进制（类型标记），
            # 例如 14002 的 teams 实测长这样：
            #   ...,"teams":{"LaJ\x01"\x18y":2,"i"\x01D<LaJ","x":1,...},"Ch...
            # 所以 json.loads 会失败，而控制字节的规律一时看不出来
            # （0x18/0x05/0x09/0x15 和 D< / Y / X 混用）。
            # 这种情况下必须打**完整** body —— 之前只打 120 字节，
            # 尾部结构（heroId 那些字段）正好被截掉，没法解。
            self.w('     params(raw %d B) 非 JSON，完整 hex:'
                   % len(rest))
            self.w('     %s' % rest.hex(' '))
        if req['tail']:
            self.w('     tail(%d B): %s' % (len(req['tail']), hexdump(req['tail'], 80)))
        if not self.cfg.quiet:
            self.w(hexdump(data))

        ts = Server.server_time_ms()
        rsp = self.build_response(req, ts)
        wire = struct.pack('>II', zlib.crc32(rsp) & 0xFFFFFFFF, len(rsp)) + rsp
        conn.sendall(frame(wire, T_DATA))
        self.w('     -> RESP %d B: %s' % (len(rsp), rsp[24:][:200].decode('utf-8', 'replace')))

    # ---------------- 连接
    def handle(self, conn, addr):
        self.w('\n== 连接 %s:%d ==' % (addr[0], addr[1]))
        conn.settimeout(self.cfg.timeout)
        buf = b''
        hs_done = False
        try:
            while True:
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    self.w('-- 空闲超时'); break
                if not chunk:
                    self.w('== 对端关闭 =='); break
                buf += chunk
                while len(buf) >= 4:
                    plen, mtype = rd_hdr(buf)
                    # plen == 0 is legal (tick / crypto-ack frames carry no payload)
                    if plen < 0 or plen > (1 << 23):
                        self.w('  !! length out of range %d, dropping buffer' % plen)
                        buf = b''
                        break
                    if len(buf) < 4 + plen:
                        break
                    payload, buf = buf[4:4 + plen], buf[4 + plen:]
                    if not hs_done and mtype == T_HS_OUT:
                        self.handle_spki(conn, payload)
                        hs_done = True
                    elif mtype == T_DATA:
                        self.handle_data(conn, payload)
                    elif mtype == T_TICK:
                        self.w('  心跳 tick（不回）')
                    elif mtype == 2:
                        self.w('  type=2 %d B（未解读）: %s' % (plen, payload[:64].hex(' ')))
                    else:
                        self.w('  type=0x%02x %d B: %s' % (mtype, plen, payload[:64].hex(' ')))
        except Exception as ex:
            self.w('!! %r' % ex)
        finally:
            try:
                conn.close()
            except Exception:
                pass
            self.w('== 连接结束（本连接 %d 个请求）==' % self.nreq)

    def serve(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.cfg.host, self.cfg.port))
        s.listen(8)
        self.w('监听 %s:%d' % (self.cfg.host, self.cfg.port))
        while True:
            c, a = s.accept()
            threading.Thread(target=self.handle, args=(c, a), daemon=True).start()


# 白名单开关的默认值快照。类定义跑完之后立刻取一次，供 debugConfigReset 用 ——
# 不能再往后取，因为启动时 load_debug_config() 就会把它们覆盖掉。
DEFAULTS = {k: getattr(Server, k) for k in Server.DEBUG_TOGGLES}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, default=8888)
    ap.add_argument('--host', default='0.0.0.0')
    ap.add_argument('--out', default=r'E:\Test\Temp\yqlr\_out_rrcp\capture\srv')
    ap.add_argument('--table', default=r'E:\Test\Temp\yqlr\_out_rrcp\opcodes_table.json')
    ap.add_argument('--algo', type=int, default=0)
    ap.add_argument('--keylen', type=int, default=16)
    ap.add_argument('--timeout', type=float, default=90.0)
    ap.add_argument('--logfile', default='')
    ap.add_argument('--quiet', action='store_true')
    Server(ap.parse_args()).serve()


if __name__ == '__main__':
    main()