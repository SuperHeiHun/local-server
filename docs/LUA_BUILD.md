# 内置 Lua 服务端构建说明

面向"改完 Python mock 之后，怎么把改动带进 APK"这件事。
权威实现只有一个：`E:\Test\Temp\yqlr\_out_rrcp\rrcp_server.py`。
`D:\Temp\yqlr\_out_repack` 里的 Lua 代码**不含任何业务逻辑**，只负责取字符串和查表。

---

## 1. 整体链路

```
rrcp_server.py (Python, 唯一权威)
   │  build_lua_table.py  —— 构建期跑一遍真逻辑，把应答物化成字符串
   ▼
lua/opcode_table.lua        —— 纯 ASCII，7~8 MB
   │  build_patched_luac.py —— 内联进 offline_server.lua
   ▼
lua/offline_server.lua       —— 取表 / 抠 id / 查表 / 发帧
   │  rebuild_v5.py + zipalign + apksigner
   ▼
signed_v5/yqlr-v5-offline-signed.apk
```

两棵树的分工：

| 树 | 角色 |
|---|---|
| `E:\Test\Temp\yqlr\_out_rrcp` | Python 权威实现 + 测试 + TSV 导出 |
| `D:\Temp\yqlr\_out_repack` | Lua 构建树 + 打包树 |
| `E:\Test\Temp\yqlr\_out_text\tables` | 反解出来的 TSV，两边共读 |

`build_lua_table.py` 里 `sys.path.insert` 到 E 盘是**刻意的**，
不要"修"成相对路径 —— 它就是要跨目录 import 权威实现。

---

## 2. 核心约束：应答体是预编码字符串

**这是整个设计的地基，违反它会出现"某些界面数据错乱"这种极难查的 bug。**

`build_lua_table.py` 在构建期把每个应答 `json.dumps` 成字符串存进表；
Lua 侧拿到后**原样发出**，一次都不 decode / encode。

原因：应答里有 5 处**空数组** `[]`（reward、clubList 等）。
LuaJIT 的 `cjson` 没有"区分空数组和空对象"的能力，
`cjson.decode('[]')` 之后再 `cjson.encode` 会得到 `{}`，客户端解析就炸。

所以：

- ✅ 允许：`string.sub` 截取、`string.find/gsub` 替换**标量片段**、字符串拼接
- ❌ 禁止：`cjson.decode` → 改 → `cjson.encode` 整段往返
- ❌ 禁止：在 Lua 里拼 JSON 对象再插回去（除非拼出来的片段本身就是预编码好的）

需要动态内容时，正确做法是**构建期多物化几份**，而不是运行时重编码。
本项目就是这么做的：`battles` 有 1889 份，`campaignProgress` 有 205 份。

---

## 3. `opcode_table.lua` 里有什么

| 字段 | 条数 | 用途 |
|---|---|---|
| `opcodes` | 17 + `default` | 固定应答（10001/10010/…/21002/29001/41001） |
| `battles` | 1889 | 14002 / 21001 / 21005 的**整份**应答，键是关卡号 |
| `heroTpl` | 300 | 我方英雄片段，键 `"<cid>#<槽位>"`，x/y/attrs 是占位符 |
| `spots` | 1889 | 每关我方默认站位 `"x,y;x,y;…"` |
| `attrs` | 1889 | 每关我方属性（由 `GridBattle.AttrCoef` 决定，逐关不同） |
| `tcb` | 1889 | 每关友军战功和，`totalCombat = 人数 × heroCombat + 本值` |
| `terrain` | 1888 | 每关压地形的格子（`MapDataId.landformSP`） |
| `campaignProgress` | 205 | 14003 的整份应答，键是关卡号 |
| `campaignCD` | 205 | 每关的 `CampaignData` 子对象，供 10001 冷启动替换哨兵（与上表同源、逐字节一致） |
| `campaignOrder` | 205 | 关卡 → `Campaign.tsv` 行序（1..205），Lua 靠它防止进度回退 |
| `campaignCDDefault` | — | 单个关卡号（`C00S01`），**没有落盘时 10001 用的初值**，防止哨兵流到客户端 |
| `gacha` | 194 | 15001 的整份应答，键是 `"<gachaId>"` 或 `"<gachaId>\|10"` |
| `heroIds` | 60 | 全部已拥有英雄 id，Lua 靠它从请求体的打包字节里认人名 |
| `defaultHeroIds` / `teamNotHero` / `teamCap` | — | 抠编队用的过滤名单，必须与 Python 侧一致 |

### 占位符约定

| 占位符 | 形态 | 谁替换 |
|---|---|---|
| `__YQLR_TEAM__` | 带引号的字符串 | Lua 换成英雄数组内容（外层 `[ ]` 保留） |
| `__YQLR_TEAM___TC` | 带引号的字符串 | Lua 换成算好的 `totalCombat` |
| `__YQLR_X__` / `__YQLR_Y__` | **裸** token | Lua 换成坐标数字 |
| `__YQLR_ATTRS__` | **裸** token | Lua 换成本关的属性对象 |
| `__YQLR_GUIDEDATA__` | 带引号的字符串 | 10001 里换成 `guideDataJson` |
| `__YQLR_MAINHERO__` / `__YQLR_MAINTYPE__` | 带引号的字符串 | 10001 里换成 `main_screen_state.json` 的值 |
| `__YQLR_CD__` | 带引号的字符串 | 10001 里换成 `campaignCD[stage]`（**必须有兜底**） |

裸 token 在 JSON 里是非法的，**必须**在发出前替换掉。
测试里有一条 `占位符残留 = false` 的断言专门守这个。

⚠️ `__YQLR_CD__` 和别的占位符不一样：`CampaignData` 必须是**对象**，
而占位符是**字符串**，一旦没被替换就会让客户端拿到 string 而不是 table
（一装新包就进不了主线）。所以它有 `campaignCDDefault` 和 `{}` 两层兜底。


---

## 4. 构建命令

```powershell
$env:PYTHONUTF8 = '1'
Set-Location 'D:\Temp\yqlr\_out_repack'

# 1) 物化应答表（约 200 s，主要花在 1686 关天梯战斗生成上）
python build_lua_table.py

# 2) 离线自测：Lua 应答层（秒级，省一次 4.5 分钟打包）
python test_rsp_offline.py

# 3) Python <-> Lua 对拍：证明两边行为一致（秒级）
python test_lua_parity.py

# 4) 打 release 包
$env:YQLR_PROFILE = 'release'
$env:YQLR_OSRV    = '1'
python build_patched_luac.py
python rebuild_v5.py
& 'E:\lib\android-sdk\build-tools\35.0.0\zipalign.exe' -p -f -v 4 `
    yqlr_v5_offline.apk yqlr-v5-offline-aligned.apk
& 'E:\lib\android-sdk\build-tools\35.0.0\apksigner.bat' sign `
    --ks debug.keystore --ks-pass pass:android --ks-key-alias androiddebugkey `
    --key-pass pass:android --out signed_v5\yqlr-v5-offline-signed.apk `
    yqlr-v5-offline-aligned.apk
```

**`YQLR_OSRV=1` 必须显式设置。** `build_patched_luac.py` 里注入内置服务端的
条件是 `os.environ.get('YQLR_OSRV','1') == '1'`，而不是原来的
`if IS_DEV and ...` —— 早先的写法会让 release 包**不带**离线服务端，
表现为装上 APK 后连不上 127.0.0.1:8888。

---

## 5. 改了 Python 之后要做什么

| 改动类型 | 要不要重跑 `build_lua_table.py` |
|---|---|
| 调数值（`PLAYER_ATTR`、资源量、关卡表） | **要**，全部数据都是构建期快照 |
| 新增/修改 TSV 字段 | **要** |
| 新增 opcode | **要**，还要在 `offline_server.lua` 里加分发 |
| 改传输层 / 帧解析 / RSA | 不用，只改 `offline_server.lua` |
| 改 `opcodes_table.json` 里的固定应答 | **要** |

改完先跑 2、3 两个测试，都过了再打包。
`test_lua_parity.py` 是判断"两边是否还一致"的唯一手段 —— 
**不要只看 opcode 数量对不对**。

---

## 6. 为什么会出现"两边 opcode 数量一样，行为却不同"

这是本项目踩过的最大的坑，值得单独记一笔。

早期两边都是 19 个 opcode，看起来"全同步"，实际上：

- Lua 的 `14002` 只有一份 C00S01 的应答 → 玩到第二关起，敌人和站位全是第一关的
- Lua 的 `14003` 是静态应答、没有 `d.player` → 主线进度永远不推进
- Lua 的 `21001/21005` 是一份 T24S40 模板 → 每关敌人都是那五个

原因：`opcodes` 里那一份 14002 是构建期跑 Python 逻辑跑出来的**某一个** stage，
不是"按请求参数生成"。

**教训：判断两个服务端是否同步，要对拍，不能数 opcode。**
`test_lua_parity.py` 就是为此写的，它对同一批请求同时喂给两边逐字段比。

---

## 7. Lua 侧的三条硬约束

1. **LuaJIT / Lua 5.1**
   - 没有 `string.pack` / `string.unpack`
   - `table.unpack` / `table.pack` 不存在，用 `unpack` / `{n=select('#',...)}`
   - `^` 是**按位异或**，不是乘方；乘方用 `math.pow` 或自己写
   - 数值 `for` 只向上计数，`for k = 7, 0 do` 一次都不执行

2. **socket 是局部变量**
   `socket` 模块在 `start()` 里是 local，全局为 nil。
   `tick()` 里必须用缓存的 `SOCK.select`，写 `socket.select` 会拿到 nil。

3. **非阻塞下的 `receive`**
   LuaSocket 即使有数据也可能返回 `nil, "timeout", partial`，
   字节在 `partial` 里。只看 `data` 会把整个握手丢掉。

---

## 8. 落盘状态（两种服务端共用）

| 文件 | 内容 | 写入方 |
|---|---|---|
| `/sdcard/main_screen_state.json` | 主屏助理 heroId/type | 10038 |
| `/sdcard/team_state.json` | 编队英雄列表 | 14002 / 29001 |
| `/sdcard/campaign_state.json` | 已通关的**最远**那关 `{"stage":"C02S03"}` | 14003 |
| `<python 目录>/campaign_state.json` | 已通关主线关卡集合 | Python 14003 |

前四者刻意用**不带引号库的极简格式**，因为设备上的宿主未必有 `cjson`，
而自测环境（本机 luajit）根本没有。Python 侧用同样的方式读写。

⚠️ 离线端只存**一个**关卡号，不是 Python 侧那样的通关集合 ——
因为 `campaignProgress[stage]` 本身就是「通关 stage 之后」的**累计**快照，
记住最远那关就够还原全部进度。排序键是 `Campaign.tsv` 行序，
**不是** `campaign_order_rank()`（后者有大量并列，会导致正常推进打平）。

`build_lua_table.py` 生成时会把这些路径重定向到**不存在的文件**：

```python
Server.TEAM_STATE_PATH     = <tmp>/no_team.json
Server.CAMPAIGN_STATE_PATH = <tmp>/no_campaign.json
```

不重定向的话，会读到你上次在真机上编的队 / 打的关，然后固化进表 ——
表现是"离线端的站位和 Python 端对不上"、"刚开局进度就已经是 C01S09 了"。

---

## 9. 已知的、有意保留的差异

| 项 | 原因 |
|---|---|
| `10032` 调试面板 | Lua 改开关要重跑 `apply_*()` 读 TSV，离线端做不到。如实返回 `resCode=1` + 说明，不静默走 default。 |
| `15001` 出货英雄 | 构建期跑一次把结果冻住；Python 每次调用重摇。离线端固定结果反而合脚（否则反复十连会不断重置）。 |
| `14003` 的 `branchLastPassed` | 离线端按"从第 1 关一路打上来"穷举，所以可能比 Python 当次会话的历史更靠后（含剧情/事件关 `CxxExx`）。 |
| `C00S01` | Python 的 14002 分支写死了 `camp != 'C00S01'`，这一关走手写静态响应（唯一在真机从头验通过的）。离线端原样照抄。 |

对拍时这四项会被单独标出来，不计入"不一致"。

---

## 10. 排查手册

| 现象 | 先查 |
|---|---|
| 装上 APK 连不上 8888 | 构建时有没有设 `YQLR_OSRV=1`；`logcat` 里有没有 `[osrv] opcode table loaded` |
| 某关敌人/站位是别的关卡的 | `battles` 里该关卡号在不在（天梯 id 有 `T07S13` 和 `T_FIRE_S001` **两种形态**，别用固定正则） |
| 客户端解析某段数据崩 | 找该 opcode 的应答里有没有空数组被 `cjson` 往返过 |
| 编队改了不生效 | `heroTpl` 里有没有 `"<cid>#<槽位>"` 这个键；槽位从 1 开始 |
| 英雄站到地形上导致战斗崩 | `terrain` 表有没有这一关；Lua 侧会校验并回退到 `spots` |
| 明文搜不到注入的标记 | `.luac` 是 XXTEA 加密的（`build_patched_luac.py:2989` `A.encrypt_blob`），搜不到是正常的，用构建往返验证 |
| 天梯某类关卡进不去 | Python 的 `STAIRS_ID_RE` 早期只认 `T\d{2}[SMX]\d{2}`，漏掉 `T_FIRE_S001` 这类；现已改为按 `StairsBattle` 的 rowId 集合校验 |

---

## 11. 体积

`opcode_table.lua` 约 7.3 MB（纯 ASCII），编成字节码后进 APK。
APK 总大小约 1.7 GB，所以这点增量可以忽略 —— 这是"全量物化"方案成立的前提。

如果将来关卡数再涨一个数量级（>2 万关），物化就不划算了，
那时才需要考虑"按需下载"或"只物化关键关"。
