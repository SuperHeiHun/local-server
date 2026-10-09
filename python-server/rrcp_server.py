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


def parse_app_body(body):
        """body = [i32 ?][u8 ver][u8 ridlen][rid][cjson][TLV...]
        The 4-byte prefix comes from the native RPC layer; Service:newRequest only
        builds the part from `string.char(version, #rid) .. rid .. cjson`."""
        if len(body) < 6:
            return None, None, None, body
        ver = body[4]
        n = body[5]
        rid = body[6:6 + n]
        rest = body[6 + n:]
        return ver, rid.decode('utf-8', 'replace'), rest, b''


# ------------------------------------------------------------------ 服务器
CODE_VERSION = 'r34-achievements-20261008'
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
        self.load_table()
        self.apply_hero_config()
        self.apply_ladder_config()
        self.apply_resource_config()
        self.apply_site_config()
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
    # ------------------------------------------------------------------
    LADDER_ORDER = 1
    LADDER_TYPES = ('COMMON', 'WIND', 'FIRE', 'LIGHT', 'WATER', 'DARK', 'EARTH')

    def apply_ladder_config(self):
        """给 StairsBattleData.typeData[*] 补 order 字段。"""
        player = self.table.get('10001', {}).get('data', {}).get('player')
        if not player:
            return
        sb = player.setdefault('datas', {}).setdefault('StairsBattleData', {})
        td = sb.setdefault('typeData', {})
        filled = []
        for t in Server.LADDER_TYPES:
            d = td.setdefault(t, {})
            if d.get('order') is None:
                d['order'] = Server.LADDER_ORDER
                filled.append(t)
        self.w('[天梯] StairsBattleData.typeData order=%s，补齐 %d 个类型: %s'
               % (Server.LADDER_ORDER, len(filled), filled))

    # ------------------------------------------------------------------
    # 无限资源（独立配置项，与角色养成那套无关）
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
            items[iid] = {'itemId': iid, 'count': Server.RESOURCE_COUNT,
                          'uniqId': ''}
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
            return {g: {'guideId': mid}
                    for g, mid in Server.GUIDE_SKIP_GROUPS.items()}
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

    def _hero_base(self, cid, uid, camp, x, y, level, star, model_id, element, profession, skills):
        return {
            'uid': uid, 'cid': cid, 'modelId': model_id, 'camp': camp,
            'x': x, 'y': y, 'level': level, 'star': star,
            'element': element, 'profession': profession,
            'Weight': 1000,
            'skills': skills,
        }

    def gen_battle_data(self, campaign_id):
        """按 GridBattle 配置生成一关的 enemyData / playerData。"""
        grid_t, enemy_t, hero_t, skill_t = self.config_tables()
        grid = grid_t.get('Campaign_%s' % campaign_id)

        if not grid:
            self.w('!! 没有 Campaign_%s 的 GridBattle 配置' % campaign_id)
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
        # 之前是 attrs(20) 全属性放大 -> Atk=6000 对敌方 HP=3000 一击秒杀，
        # 战斗 9 秒结束，战斗内引导 Step36 来不及执行 -> 引导重播。
        # 现在只放大 HP/防，血厚保证不被打死，Atk 压到和敌方同量级把战斗拉长。
        PLAYER_ATTR = {'MaxHP': 60000, 'Atk': 300, 'PDef': 2000, 'MDef': 2000,
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

        enemies = []
        friends = []
        idx = 0
        for slot in area:
            unit = slot.get('enemy') or slot.get('friend')
            if not unit:
                continue
            idx += 1
            is_enemy = 'enemy' in slot
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
            )
            hero['combat'] = max(1000, power // max(1, len(area)))
            hero['attrs'] = attrs(1.0)
            (enemies if is_enemy else friends).append(hero)

        # 玩家侧：用 10001 里真实拥有的角色，站在 GridBattle 给的站位上
        player_heros = []
        try:
            owned = self.table['10001']['data']['player']['datas']['HeroesData']['heroes']
        except Exception:
            owned = {}
        # 站位取 PlayerPositonArea 前 N 个 actionNum 编号的格子
        spots = []
        try:
            for a in json.loads(grid.get('PlayerPositonArea') or '[]'):
                spots.append((int(a.get('x', 1)), int(a.get('y', 1))))
        except Exception:
            spots = [(1, 1)]
        for i, (cid, info) in enumerate(sorted(owned.items())):
            cfg = hero_t.get(cid, {})
            x, y = spots[i] if i < len(spots) else (1, 1 + i)
            h = self._hero_base(
                cid=cid, uid='100001_%d' % (i + 1), camp=1, x=x, y=y,
                level=int(info.get('level') or level), star=int(info.get('star') or 5),
                model_id=cfg.get('Resource') or ('C_' + cid),
                element=cfg.get('Element') or 'FIRE',
                profession=self.pick_profession(cfg, False),
                skills=self.hero_skills(skill_t, cid),
            )
            h['adv'] = int(info.get('adv') or 1)
            h['combat'] = int(info.get('combat') or 60000)
            # [调数值] 玩家侧只放大血量、**不放大攻击**。
            # 原因：第二关的战斗内引导 Step36（点戈琳）/Step36_1（佩璐对话）必须
            # 在战斗中有时间执行，而之前玩家 Atk=6000 对敌方 HP=3000 是 2 倍溢出、
            # 一击秒杀，整场 9 秒就结束（14002 13:42:03 -> 14003 13:42:14），
            # Step36 根本没机会触发，引导就跳回结算剧情 Step16 重播整段。
            # 降到 Atk≈300（打一只 3000 血的怪约 10 下），战斗拉长到能容下引导。
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

        # 14002：按 campaignId 从 GridBattle 配置生成战斗数据。
        # 表里那份写死的 C00S01 响应保持原样不动（第一关已实测能跑通），
        # 只有打到别的关卡才走生成逻辑，避免动到已验证的路径。
        if opcode == 14002:
            camp = self.extract_campaign(req.get('body') or b'')
            self.w('   14002 campaignId=%s' % camp)

            if camp and camp != 'C00S01':
                gen = self.gen_battle_data(camp)
                if gen:
                    self.w('   14002 按配置生成 %s：敌方 %d 个，友方 %d 个' % (
                        camp, len(gen['enemyData']['heros']),
                        len(gen['playerData']['heros'])))
                    resp = {'resCode': 0, 'data': gen}

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

        # 10001 玩家同步里下发引导进度（否则客户端判定服务端进度为 0）
        if opcode == 10001:
            self.w('   [哨兵] 进入 10001 钩子')
            gd = self.guide_data()
            if gd and isinstance(resp, dict) and isinstance(resp.get('data'), dict):
                player = resp['data'].get('player')
                if isinstance(player, dict):
                    player['guideData'] = gd
                    self.w('   10001 下发 guideData=%s' % json.dumps(gd, ensure_ascii=False))

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
            self.w('  !! 载荷太短，无法当 RPC 解析')
            return
        self.nreq += 1
        ver, rid, rest, _ = parse_app_body(req['body'])
        # 引导上报(10027)的 guideId 在 app 信封里而不在 req['body']（body 长度为 0），
        # 把它挂到 req 上给 build_response 用。只记引导相关的 opcode，代价可忽略。
        req['app_raw'] = rest
        self.w('  #%d REQ opcode=%d req_id=%d kind=%d comp=%d blen=%d tail=%d'
               % (self.nreq, req['opcode'], req['req_id'], req['kind'],
                  req['comp'], req['blen'], len(req['tail'])))
        self.w('     app: ver=%s rid=%r' % (ver, rid))
        try:
            j = json.loads(rest.decode('utf-8', 'replace'))
            self.w('     params: %s' % json.dumps(j, ensure_ascii=False)[:600])
        except Exception:
            self.w('     params(raw %d B): %s' % (len(rest), rest[:120].hex(' ')))
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