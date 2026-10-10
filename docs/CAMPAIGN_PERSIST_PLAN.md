# 关卡进度持久化 —— 实施方案

> 状态：**已实施并装包**（2026-10-10 22:20，signed_v5 1,727,294,147 B）
> 记录时间：2026-10-10
> 相关：`D:\Temp\yqlr\MEMORY.md` 第 52 / 54 / 55 / 56 节、`D:\Temp\yqlr\LUA_BUILD.md`

---

## 0. 实施时发现并修正的两处（先看这个）

照着初版方案写完第一遍，跑测试时发现两个问题，**方案本身已经改过**：

### 0.1 `last_stage` 一个变量承担了两个角色

初版方案让 `_state.last_stage` 同时表示
「本次 14002 打的关」和「已通关的最远那关」。这在真实链路里立刻坏掉：

```
14002(C01S02) -> last_stage = C01S02
14003(空body) -> cid = last_stage = C01S02
              -> campaign_farther(C01S02, last_stage=C01S02)  <- 自己跟自己比
              -> 永远不落盘
```

**已拆成两个变量**：
- `last_stage` = 本次 14002 打的关（内存态，只给 14003 兜底用）
- `saved_stage` = 已通关的最远那关（落盘态，给 10001 用）

比较用的是 `campaign_farther(cid, _state.saved_stage)`。

### 0.2 哨兵会漏到客户端（新装/清数据时）

`campaign_cd_ph` 哨兵是**字符串**，而 `CampaignData` 必须是**对象**。
初版方案里 10001 的替换条件是 `if ... and _state.last_stage then`，
于是**冷启动且无落盘时整个替换被跳过**，哨兵原样发给客户端：

```json
"CampaignData":"__YQLR_CD__"     <- 客户端拿到的是 string，不是 table
```

这会导致一装新包就进不了主线。

**已加初值快照兜底**：构建期取 `Campaign.tsv` 第一行（`C00S01`）的
`CampaignData` 存成 `campaignCDDefault`，运行时

```lua
local stage = _state.saved_stage or _state.campaign_cd_default
```

并在 `cd` 也拿不到时降级成 `"CampaignData":{}` ——
**任何情况下都不让哨兵流到客户端**。
语义上等于「全新玩家」，和 Python 侧冷启动一致。

### 0.3 排序键也不能用 `campaign_order_rank`

方案里原写「用 `campaign_order_rank` 比远近，`<0` 的跳过」。
实测 205 关只有 **178 个不同的 rank** —— `C00S01` 和 `C00M01` 这类剧情关
共用同一个 rank，于是「打完 C00M01 再打 C00S01」这种**正常推进**会打平，
`n > o` 为假 → 不更新落盘值 → 冷启动反而拿 C00M01 的快照。

**改用 `Campaign.tsv` 的行序**（1..205）：
- 205 关 rank 全不相同，无并列
- 行序正是 `campaignProgress` 快照的累加顺序
  （`gen_campaign_progress` 就是按它逐行 `campaign_passed.add`），
  所以「行序更大」==「快照包含更多关卡」，语义完全对齐

---

## 1. 问题

内置 Lua 服务端（离线包）的关卡进度**冷启动就丢**。

表现：打过的关卡在退出重进后回到构建时的初始状态，已解锁的下一关重新变灰。

## 2. 根因：架构差异，不是 bug

Python mock 是**有状态**的：

```
rrcp_server.Server
  self.campaign_passed = set()        # 已通关集合
  load_campaign_state()               # 启动时从 campaign_state.json 读
  14003 -> campaign_passed.add(camp)
         -> Server.save_campaign_state(self.campaign_passed)   # 落盘
```

离线端是**无状态回放器**（见 `LUA_BUILD.md` 第 2 节）：
`campaignProgress` 是构建期按「一路打上来」穷举出来的 **205 条静态快照**，
键是关卡号，值是含 `d.player.CampaignData` 的整份预编码应答。
Lua 侧只做「查表 → 原样发出」，**没有任何持久化设施**。

所以即使 Python 侧把进度修好了，离线端也不会自动跟着好 —— 这是**必须单独实现**的一条。

## 3. 两个必须处理的时机

只做 14003 的落盘是**不够**的：

| 时机 | 现状 | 需要 |
|---|---|---|
| 战斗中（14003） | 已能查到正确的 `campaignProgress[stage]` | 追加：把关卡号落盘 |
| **下次启动（10001）** | 下发的是**构建期**的 CampaignData，初始值 | **必须**用落盘的关卡号覆盖 |

第二点是关键：客户端每次冷启动先收 10001，进度是从这里读的。
只在 14003 落盘的话，重进游戏时 10001 仍然把进度打回原形。

## 4. 难点：`CampaignData` 不能在 Lua 里拼

硬约束（`LUA_BUILD.md` 第 2 节）：应答体是构建期预编码的字符串，
**禁止 `cjson.decode` → 改 → `cjson.encode` 往返**（空数组 `[]` 会变成 `{}`）。

所以不能「解出 10001 的 JSON、替换 CampaignData、再编回去」。

### 解法：沿用既有的「占位符 + 标量 splice」套路

和 `guideData` 完全一样的做法（`offline_server.lua` 里已有先例）。

**构建期**（`build_lua_table.py`）：

1. 从 `campaignProgress[stage]` 里把 `d.player.datas.CampaignData`
   那个**子对象**单独抽出来，另存一张表：

   ```
   campaignCD[stage] = '{"lastPassed":"C02S03","lastCampaign":...}'   # 预编码
   ```

2. 把 10001 应答里 `datas.CampaignData` 的**值**整个换成哨兵字符串：

   ```
   原文: "CampaignData":{"lastPassed":"C00S01", ... 18 个字段 ...}
   改后: "CampaignData":"__YQLR_CD__"
   ```

   注意是**整个值**换掉，不是逐字段 —— 这样运行时不需要知道原对象的字节范围。

**运行时**（`offline_server.lua`）：

```lua
-- 只在 10001 分支做一次标量替换
if req.opcode == 10001 and _state.campaign_cd_ph and _state.last_stage then
    local cd = _state.campaign_cd[_state.last_stage]
    if cd then
        body = string.gsub(body, '"CampaignData":"' .. _state.campaign_cd_ph .. '"',
                           function () return '"CampaignData":' .. cd end, 1)
    end
end
```

替换串里是预编码好的片段，**不重新编码任何东西**，只做一次拼接。

## 5. 落盘格式

沿用工程里已有的极简格式（`load_main_screen` / `save_team`），
**不引 JSON 库** —— 设备上的宿主未必有 `cjson`，本机 luajit 更是完全没有。

```
路径:  /sdcard/campaign_state.json
内容:  {"stage":"C02S03"}
```

```lua
local CAMPAIGN_PATH = '/sdcard/campaign_state.json'

local function load_campaign_state()
    local f = io.open(CAMPAIGN_PATH, 'r')
    _state.last_stage = nil
    if not f then return end
    local raw = f:read('*a')
    f:close()
    _state.last_stage = string.match(raw, '"stage"%s*:%s*"([^"]*)"')
    -- 落盘的关卡可能已经不在表里了（表重建过 / 版本回退），
    -- 这时必须丢掉回落默认值，不能带着一个查不到的 id 启动。
    if _state.last_stage and not _state.campaign_cd[_state.last_stage] then
        _state.last_stage = nil
    end
end

local function save_campaign_state()
    if not _state.last_stage then return false end
    local f = io.open(CAMPAIGN_PATH, 'w')
    if not f then
        slog('!! cannot write %s', CAMPAIGN_PATH)
        return false
    end
    f:write('{"stage":"', _state.last_stage, '"}')
    f:close()
    slog('campaign state saved: %s', _state.last_stage)
    return true
end
```

调用点：
- `load_opcode_table()` 末尾（和 `load_main_screen()` / `load_team()` 并列）
- 14003 命中预编码应答之后

## 6. 为什么只存「最远的那一关」而不是一个集合

Python 存的是 `campaign_passed` 全集。离线端不需要：

`campaignProgress[stage]` 本身就是「通关 stage 之后」的**累计快照**，
已经把之前所有关卡的效果都算进去了。所以只要记住**最远的那个关卡号**，
冷启动时直接取那一条快照，进度就完整了 —— 集合是冗余的。

分支关（`CxxMxx`，`Order` 为空）要注意：`campaign_order_rank()` 未知返回 `-1`，
所以拿它和主线关比较时必须**跳过**，否则会把主线进度误判成"退回去了"。
实现时用一个简单规则：只在 `campaign_order_rank(新) > campaign_order_rank(旧)`
且两者都 `>= 0` 时才更新 `_state.last_stage`。

## 7. 实施步骤（已全部完成）

1. `build_lua_table.py`
   - ✅ `CAMPAIGN_PLACEHOLDER = '__YQLR_CD__'`，10001 里 `CampaignData`
     的**值整个**换成哨兵。**必须深拷贝 `datas`**，否则会污染 `srv.table`
     （见 9.1）
   - ✅ `gen_campaign_cd()`：从每条 `campaignProgress` 里抽 `CampaignData`
     子对象，产出 `campaignCD`（205 条，76 KB）
   - ✅ `gen_campaign_order()`：`Campaign.tsv` 行序（205 条，1..205）
   - ✅ `campaignCDDefault` = `C00S01`（哨兵兜底，见 0.2）
   - ✅ `emit_lua()` 输出 `campaignCD` / `campaignOrder` / `campaignCDPh`
     / `campaignCDDefault`

2. `offline_server.lua`
   - ✅ `_state` 加 `last_stage` / `saved_stage` / `campaign_cd` /
     `campaign_cd_ph` / `campaign_cd_default` / `campaign_order`
   - ✅ `load_campaign_state()` / `save_campaign_state()`
   - ✅ `load_opcode_table()` 里赋值完 `campaign_cd` 再调 load
   - ✅ 10001 分支加哨兵替换 + 初值兜底 + `{}` 降级
   - ✅ 14003 分支按 `campaign_farther(cid, saved_stage)` 落盘
   - ✅ `OfflineServer.campaign_path()` 测试钩子（宿主机没有 `/sdcard`）

3. `test_rsp_offline.py`
   - ✅ `PERSIST_HARNESS` 跑**三遍**模拟冷启动：
     1. 无落盘 → 断言 `CampaignData` 是对象而非哨兵
     2. 打 C01S02 → C02S03 → **回头重打 C01S02** → 断言落盘仍是 C02S03
     3. 新进程读盘 → 断言 10001 的 `lastPassed` 是 C02S03

4. ✅ 打包 → `build_patched_luac.py` → `rebuild_v5.py`
   → zipalign → apksigner → install → **重推 `files/assets.db`**
   → **确认 `adb reverse` 为空** → 启动
   （`rebuild_v5.py` 20,333 条目 `总体: PASS`；签名后 1,727,294,147 B）

## 8. 验证清单

| 检查 | 期望 | 结果 |
|---|---|---|
| 打一关 → 退出 → 重进 | 该关仍显示已通关，下一关仍是解锁态 | 待机测 |
| `/sdcard/campaign_state.json` | `{"stage":"C02S03"}` | ✅ 离线测试通过 |
| 10001 应答里 `CampaignData` | 与 `campaignProgress[C02S03]` 里的**逐字节一致** | ✅ 205/205 逐字节相同 |
| 把文件改成不存在的关卡号 | 启动时自动丢弃，回落初值，不崩 | ✅ `已不在表里，丢弃回落初值` |
| 日志 | `campaign state saved/loaded: XXX` | ✅ |
| `adb reverse --list` | 必须为空（RL 包不能让 reverse 占住设备 8888） | ✅ 空 |
| 哨兵绝不能到客户端 | 冷启动无落盘时也必须是**对象** | ✅ `用 C00S01 替换（初值快照）` |

## 8.1 实施中新发现的坑

### 8.1.1 【坑】深拷贝 `datas`，否则污染 `srv.table`
`build_lua_table.py` 里 `resp['data']['player']` 和 `table['10001']['data']['player']`
**是同一个对象**（原代码 194-196 行就有这个警告）。
往 `p` 里写 `guideData` / `mainScreenHeroId` 这些标量无所谓 ——
写完立刻 `json.dumps`，没人再读。
但 `CampaignData` 不一样：后面的 `gen_campaign_progress()` 会通过
`s2.table` 读到它并 `cd.update(...)`。
直接写 `p['datas']['CampaignData'] = 哨兵` 会让 **205 条预编码进度应答里的
CampaignData 全变成那个字符串**。

→ 换哨兵之前必须 `copy.deepcopy(datas)` 再赋回去。
（`s2.table` 是不是真的共享对象取决于 `Server.__init__` 有没有深拷贝，
不赌，直接深拷贝最省事。）

### 8.1.2 别拿正则在生成好的 Lua 表上数条目
自检脚本用 `\n        \["..."\] = ` 数 `campaignProgress`，
结果 205 条只数出 204 条 —— 外层正则 `\n    campaignProgress = \{\n`
把第一条前的 `\n` 吃掉了，**第一条匹配不上**。
一度以为生成少了 1 条。

→ 数条目按行 split 再逐行匹配，别在换行处省字符。
（`block lines: 205` 才是真实值。）

## 9. 备选方案与为什么不选

| 方案 | 否决理由 |
|---|---|
| 把整个 10001 按关卡预编码多份 | 10001 有 68 KB × 205 份 = 14 MB，且要解决「选哪一份」的状态问题，不如只换 CampaignData 这一个小片段 |
| 在 Lua 里 decode/改/encode 10001 | 违反预编码约束，空数组 `[]` 会变 `{}`，客户端解析炸 |
| 每次启动都从第 1 关重放一遍 14003 | 要在 Lua 里维护一个 205 次的循环，且中间应答无法正确发给客户端（客户端不认没打过的结算） |
| 只存 `campaign_passed` 全集（学 Python） | 冗余；快照已经含累计信息，多存 205 个 id 只会让文件变大、逻辑更复杂 |

## 10. 遗留的语义差异（修完之后仍然存在）

离线端是**静态快照 + 线性推进**的假设，和 Python 的真实状态机不完全等价：

- **跳关**：Python 里玩家只打过 C00S01 和 C05S03，离线端只能给出
  「一路打到 C05S03」的快照。实测无感知（客户端只看 `lastPassed` 和
  `branchLastPassed`），但语义不同。
- **`branchLastPassed`**：离线端是按 Campaign.tsv 行序累加的，会把剧情关
  （`CxxMxx`）也算进章节进度；Python 那边取决于实际打过哪些。
  这个差异在对拍里已经标注为「已知且可解释」，**不在本次修复范围内**。
