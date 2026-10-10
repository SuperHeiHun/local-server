# 跃迁旅人 离线化改造 — 排查备忘

> 构建目录已迁到 `D:\Temp\yqlr`（原 `E:\Test\Temp\yqlr` 只保留历史产物）。
> 本文件记录**已验证的结论**与**被排除的假设**，避免以后重复走弯路。
> 纪律：所有字段 / ID / 协议 / 补丁必须先从代码、配置表、抓包或运行日志验证真实性，再落实。

---

## 一、战斗胜利结算页「点击关闭无响应」— 已解决

### 根因

**不是** `BattleSuccessMediator` 的问题，是我自己的 `GuideWidget` 补丁把引导系统留在**半初始化**状态：

```python
# 原补丁 1：saveCurGuideStepId 里跳过 self:openGuide()   -> 引导遮罩不显示
# 原补丁 2：checkIsGuideWorking() 恒返回 false           -> 全局解除引导接管
```

第 2 条让 `checkGuideStatus()` 永远为 false，但**引导链仍在推进**（10027 一直上报
`Guide1_Step2_1 -> Step3 -> ... -> Step19 -> Step27`），接管分支也照样存在，
只是引导层从来没真正打开过。结算页正好有一个这样的分支：

```lua
-- BattleSuccessMediator:initView 尾部
if self._guideSystem:checkGuideStatus() then
    -- 引导接管
else
    self._playerLevelSystem:checkPlayerLevelUp()
end
```

结果就是这个半截状态在结算页留下了挡住触摸的逻辑。还原两处补丁后立刻恢复。

### 验证证据

还原后日志：

```
11:24:59  触摸命中 child[07] size=751x350 (TouchBegin)      <- touchLayer 收到触摸
11:24:59  close:1 开始  _id=C00S01  _firstPass=true  _type=CHAPTER
11:24:59    controller=table:0x... _isTest=nil _skipStageChapterMapView=false _isActivity=false
11:24:59  close:2 EVENT_STAGE_REMOVWEVENT 已发
11:24:59  close:3 EVENT_BATTLE_SUCCESS 已发
11:24:59  close:4 stopVoiceId 完成
11:24:59  close:5 dismissWithOptions 完成
11:24:59  close:6 enterViewReturnBattle 已返回
```

### 已排除的假设（别再重查）

| 假设 | 排除依据 |
|---|---|
| 按钮绑定静默失败 | `touchLayer` 找得到，`getChildByFullName` 有命中，`addClickEventListener` 非 nil，`tempFunc=true` |
| `Click` 被事件类型 `(A)` 拦 | 实测收到 `eventType=2`、期望 `eventType=2` |
| `Click` 被 `checkfn` `(B)` 拦 | `kBtnHandlers` 四个按钮**都没有 `checkfn`**，`checkRe=true`、`hasCheckMethod=false` |
| 触摸被别的子节点吞 | 命中普查证明恢复后命中的正是 `child[07]=touchLayer` |
| `view` 没挂上活动 GRoot | `view:getRoot() == fgui.GRoot:getInstance()` 为 true，`anc4 isGRoot=true` |
| `touchLayer` 是悬空对象 | 节点普查 `isnull=ok=false`、`getContentSize()=751x350` 正常 |
| `blockUI` 遮罩残留 | `WaitingStyle.kLoading` 带 `delay=2000` 会自动消失；当时进程零 LUA ERROR |

### 踩过的坑（重要）

1. **`print()` 在这个游戏里根本不输出到 logcat。**
   代码里本来就有的 `print("[LOGIN]", "LoginMediator:connectGameServer1", ...)`
   和 `print("+++++++ PlayerLevelSystem:initData ...")`，在 logcat 和 LogFox 里**一条都搜不到**。
   → 探针必须用 `io.open("/sdcard/probe.txt", "a")` 写文件，再用 `adb exec-out` 取。

2. **`StageSystem.lua` 的反编译源码自身编译不过。**
   反编译器在 `StageSystem:screeningTeamSkill` 里留了 `return` 之后还跟语句的死代码
   （第 123 行 `local element = {...}`），Lua 5.1 要求 `return` 必须是块内最后一句。
   实测 ORIGINAL / PATCHED 都 FAIL。→ **这个文件不能从反编译源码改**，
   只能改 `BattleSuccessMediator` 这边去读它的字段。

3. **`DmViewMediator.lua` 第 103-107 行有静默失败点：**
   ```lua
   if DEBUG and DEBUG > 0 then
       assert(button ~= nil, ...)
   end
   if button then          -- button 为 nil 时整段跳过，且 DEBUG 关闭时不报错
   ```
   → 节点找不到也不会有日志。以后排查绑定问题要先看这一段。

4. **这套 UI 是 FairyGUI（`fgui` / `GObject`），不是 cocos2d-x 的 ccui。**
   `isTouchEnabled` / `getLocalZOrder` 这类 ccui 方法全部取不到。
   `GObject:addClickEventListener`（`yq/base/GObjectExt.lua:136`）只监听
   `fgui.UIEventType.Click` 一个事件，所以单看 Click 无法区分
   "触摸没到对象" 和 "到了但 Click 被取消"，必须额外挂 `TouchBegin` 做判别。

5. **`GObject:setName(name)` 只写 `self.__name`**，不调原生 `setName`
   （`GObjectExt.lua:33-35`）；而 `getChildByName`（`:36-51`）在 `__name` 查不到时
   会 fallback 到原生 `getChild(name)`。→ dump 节点名要读 `__name`。

6. **`tolua` 的 `invalid 'cobj'` 不是"指针已释放"**，而是「该位置不是注册的
   `fgui::GObject` userdata」。项目里 `tolua.cast(item, "fgui.GObject")` 有真实用法
   （`PropertyNode.lua:301`），派生类型走这条原生检查就会报这个错。
   我曾据此误判 `touchLayer` 是悬空对象，实际 `isnull=ok=false` 完全正常。

7. **`mapButtonHandlersClick` 被调用两次**（`BattleSuccessMediator.lua:171-176`）：
   `flash:addCallbackAtFrame(30, ...)` + `performWithDelay(view, ..., 1)`。
   那个 MovieClip 在循环播放，17 秒内重复绑定 8~40 次，每次 `addClickEventListener`
   都会叠加一个监听器。**这不是点击失效的原因**（traceback 精确对到这两行），
   但属于游戏自身的冗余行为。

8. **PowerShell 拉日志必须用二进制重定向**，否则编码损坏会让 grep 失配：
   ```powershell
   cmd /c "adb -s 127.0.0.1:5555 exec-out cat /sdcard/probe.txt > out.txt"
   ```
   我曾因此误判"场景树 dump 没执行"，实际它跑了。

9. **探针里对 cocos2d-x userdata 用 `rawget(c, ...)` / `c.xxx` 会直接抛错**，
   把整个 `pcall` 块带走，一行都写不出来。→ 属性读取一律过 `_safe()` 包 pcall，
   并且要打印 **pcall 的报错原文**，别压成 `?`（压成 `?` 会让我误判三次）。

---

## 二、战斗数据现状

### `GridBattle.EnemyPositonArea` 完整规定了每关的敌方与友方单位

```
Campaign_C00S01  [{"x":4,"y":3,"enemy":"C00S01_DEF"},{"x":6,"y":3,"enemy":"C00S01_MAR"},
                 {"x":5,"y":3,"enemy":"C00S01_MAG"},{"x":3,"friend":"C00S01_ShiZ","y":3"}]

Campaign_C00S02  [{"x":4,"y":3,"enemy":"C00S02_DEF"},{"x":4,"y":2,"enemy":"C00S02_FIG"},
                 {"x":4,"y":4,"enemy":"C00S02_FIG"},{"x":5,"y":3,"enemy":"C00S02_MAG"},
                 {"x":5,"y":2,"enemy":"C00S02_MAR"},{"x":2,"friend":"C00S02_HuL","y":2"}]

Campaign_C00S03  [{"x":4,"y":3,"enemy":"C00S03_DEF"},{"x":5,"y":3,"enemy":"C00S03_MAG"},
                 {"x":4,"y":4,"enemy":"C00S03_FIG"},{"x":4,"y":2,"enemy":"C00S03_FIG"}]
```

这些单位在 `Enemy.tsv`（1417 行）/ `Character.tsv`（60 行）里**全部存在**，
所以战斗数据可以**按配置生成**，不必写死。

### 当前 `opcodes_table.json` 的问题

- `14002` 的响应是**写死 C00S01** 的：`campaignId="C00S01"`、
  `gridBattleId="Campaign_C00S01"`、敌方 `C00S01_DEF/MAR/MAG`。
  → 打第二关会拿到第一关的数据。

### `10001` 里 `Teams` 与 `HeroesData` 自相矛盾

```
HeroesData.heroes = {"LaJ": {"level":30,"adv":3,"exp":0,"combat":60000}}   <- 只有 LaJ
Teams.teams["1"]  = {"ShiZ": {"uid": 1}}                                   <- 引用未拥有的 ShiZ
```

`ShiZ` 是合法角色 id（也是 `Campaign_C00S01` 的友方单位 `C00S01_ShiZ`），
但玩家的角色列表里没有它。编队界面解析时会拿到 nil。

### `Campaign.tsv` 里第二关的奖励不含角色

```
C00S02.UnlockId  = C00S01
C00S02.Reward    = C00S02_ClearReward
C00S02.SD_Default = LaJ
C00S02.SD_Follow  = ["ChuanSJ"]

Reward.tsv: C00S02_ClearReward -> RandomType=FIXED
            Content=[{"amount":50,"code":"IR_Diamond","type":"ITEM"}]
```

所以「无法获取角色」**不是奖励发放**问题。

---

## 三、mock 服务器速查

| 事项 | 值 |
|---|---|
| 响应表 | `E:\Test\Temp\yqlr\_out_rrcp\opcodes_table.json` |
| 服务 | `E:\Test\Temp\yqlr\_out_rrcp\rrcp_server.py`，监听 `8888` |
| 启动 | `start_mock_detached.ps1`（WMI 脱离，必须这样起） |
| 日志 | `%TEMP%\opencode\srv.txt` |
| 隧道 | `adb reverse tcp:8888 tcp:8888` / `tcp:18099 tcp:18099` |
| 读表失败表现 | 退回空表，看起来像"改了没生效"；改表后必须先 `python -c "import json;json.load(...)"` |
| 只发送的字段 | `resCode`、`data`、`d`、`del`（其他字段会污染客户端响应） |

opcode 清单：`10001 10010 10021 10027 10036 13015 14001 14002 14003 14009 14016 19002 41001`

---

## 四、构建速查（`D:\Temp\yqlr`）

| 步骤 | 命令 |
|---|---|
| 编译补丁 | `python build_patched_luac.py` |
| 重打包 | `python rebuild_v5.py` |
| 签名 | `zipalign -f -p 4` + `apksigner`（debug.keystore / android / androiddebugkey） |
| 推运行时库 | `python patch_runtime_db.py` |
| 装包 | `adb -s 127.0.0.1:5555 install -r signed_v5\yqlr_v5-aligned-signed.apk` |

- `build_patched_luac.py` 会把**补丁后的源码**导出到 `_out_repack/_patched_src/`。
  `debug.traceback()` 报的行号对应的是这份文件，不是 `_out_decompile` 里的原始文件
  （探针插了几十行，行号会错位）。
- 运行时资源库在 `/data/data/<包名>/files/assets.db`（不是 APK 内的
  `assets/32|64/assets.db`），改完必须 `chown 10062:10062` / `chmod 600`。
- 版本存档在 `_out_repack/versions\<MMdd-HHmm>\`。

### 当前补丁清单

| 文件 | 内容 |
|---|---|
| `sdk/SDKHelper.luac` | 关闭 SDK 登录门、解锁检查 |
| `yq/base/Service.luac` | cjson.encode 探针及空 JSON 兜底 |
| `yq/gameplay/playerLevel/controller/PlayerLevelSystem.luac` | `_oldLevel` 判空 |
| `yq/launch/login/LoginSystem.luac` | `_battleVersion` 兜底、rrcp 地址指向 `127.0.0.1:8888` |
| `yq/launch/login/view/LoginMediator.luac` | rrcp mock 连接 |
| `yq/gameplay/activity/model/ActivityList.luac` | `getActivityById` 去掉 assert；`syncAloneActivity` 改用 `getRecordById` |
| `yq/gameplay/team/view/TeamMediator.luac` | 编队：修三处非法硬编码站位；第一关不预置、第二关预置塔可（见第六章） |

**已停用**（保留函数与历史说明便于回滚）：

- `patch_guidewidget` — 战斗内教程引导已恢复
- `patch_battlesuccess` — 结算页探针，问题已定位
- `patch_dmviewmediator` / `StageSystem` — 探针用，已从 JOBS 移除

---

## 五、编队与默认上场（第二关）

### 站位合法性由配置决定，不是随便挑

`GridBattle.EnemyPositonArea` 里同时写敌方与友方单位，`PlayerPositonArea` 是玩家可用格，
**被友军/敌方占掉的格子会直接从玩家区的 `actionNum` 序列里消失**（序号跳号就是证据）。

```
C00S01  玩家区 14 格 (1,1)..(1,5) (2,1)..(2,5) (3,1)(3,2)(3,4)(3,5)
        友军 C00S01_ShiZ 占 (3,3)  -> actionNum 从 12 跳到 14
C00S02  玩家区 13 格
        友军 C00S02_HuL 占 (2,2)   -> actionNum 从 6 跳到 8
        (3,3) 反而是玩家格（actionNum 14）
C00S03  玩家区 14 格，缺 (3,2)（actionNum 从 11 跳到 13）
C00S04  玩家区 15 格，(1,3)/(3,3)/(2,3) 都可用且未被占
```

两关都合法且不含 `(3,3)` 的格子：
`(1,1) (1,2) (1,3) (1,4) (1,5) (2,1) (2,3) (2,4) (2,5) (3,1) (3,2) (3,4)`

### 关键：编队数据只有一张全局表

`CampaignData.team` 是**唯一**的编队来源，所有关卡共用：

```
CampaignData.team
  → CampaignModel:synchronize（CampaignModel.lua:277-278  valueReplace(data.team, self._team)）
  → CampaignModel:getTeam()      (:530)
  → StageSystem:getTeam()        (:569)
  → TeamMediator:2558-2562       if self._controller.getTeam then data = getTeam()
                                  else data = getTeamById(self._id) end   <-- 永远到不了
```

`getTeamByType(type)` 只被 `EquipZoneSystem.lua:226` 用，主线没有按关卡分表的机制。
**所以"按关卡写不同编队"只能落在 `TeamMediator` 引导分支那种按 `self._id` 分的代码上。**

### `Teams` 表的结构（一度写错过）

`TeamsSystem:getTeamById`（:123-131）读的是 `teams[id].team`，消费方
`TeamMediator:2573-2580` 需要 value 带 `x` / `y`，key 是**角色 id**：

```json
"Teams": { "maxNum": 2, "teams": { "1": { "name": "...", "leadSkills": {},
  "team": { "LaJ": {"x":1,"y":1,"type":"OWNED"} } } } }
```

`type` 取值见 `GameTypesCfg.lua:1033-1041` 的 `HeroRecruitType`，且**真实 14002 请求体里解出来
就是 `"type":"OWNED"`**，不是猜的。

### 坑：同名条目会「加了又删」

`TeamGroundWidget:controllerHero`（:1328-1337）：

```lua
if self._heroTeams[herodata.uid] then
    if self:checkHeroCanLeave(...) then
        self:removeHero(herodata)   -- 不是跳过，是移除
        return true, true
    end
```

所以服务端预置的角色 + 引导再塞一个同名条目 = 先 add 后 remove = **净 0 人**。
`TeamMediator:2622-2669` 的引导强制放置都有 `not self:checkIsHaveHeroId(team, X)` 前置条件，
预置正确就能避免，但**预置错位反而会清空**。

### 引导分支不能用来做「进入关卡时的默认编队」

`isFinshGuide`（`GuideModule.lua:114-130`）比的是**已完成**的最后一步：

```lua
local lastId = self:getFinishLastGuideId(groupId)
return config.Order <= GameStyle:getGuideById(lastId).Order
```

而 `Guide1_Step35`（Order=32）本身就是「点开始战斗」。用它当触发条件等于
**必须先点过一次开始战斗才可能生效** —— 循环依赖，实测第二关确实没塔可。
最后改成在引导块**外面**、`dump(team, ...)` 之前追加按 `_id` 的默认编队，不看引导状态。

---

## 六、构建管线的坑（这几条都踩过）

### `fix_syntax` 必须补 `nil`，不能删逗号

反编译器会留下丢失的实参：

```lua
local video = VideoSprite.create(usmPath, nil, , , true)
```

`VideoSprite.create` 的签名（`yq/utils/VideoSprite.lua:8`）是 6 个参数：

```lua
function create(audioPath, callback, player, isAsync, isLoop, noplay)
```

删逗号压成 `create(usmPath, nil, true)` 后，**`true` 落到第 3 个参数 `player`**，
运行时直接报 `bad argument #1 to 'createWithPlayer' (cri. Player or nil expected, got boolean)`。
正确做法是替换成 `, nil,`：`create(usmPath, nil, nil, nil, true)`。

另外两点：
- 正则里的 `\s` **包含换行**，原来的 `,(\s*),` 会跨行匹配，把 `,\n  ,` 换成 `, `，
  **吃掉换行、粘行**，行数会变。必须用 `[^\S\n]*`（只吃空格制表）。
- 单遍修不掉 `nil, , , true`（只消掉一个逗号），要**迭代到不动点**。

改完后 `TeamMediator.lua`（3526 行）由编译失败变成功，行数不变。

### `TeamGroundWidget.lua` 仍然编译不过

它的问题是 `return` 后面跟死代码（`function cellHero.refreshCombat(fetterTab) return` 下面还有 if），
Lua 5.1 要求 `return` 必须是块内最后一句。这种不能靠缩进可靠判断，
**不要尝试从反编译源码改它**。

### 内容寻址 → 路径会悬空

`real = release/<md5[0:2]>/<md5[2:4]>/<md5[4:]>.luac`，路径由明文 md5 决定。
把某个 logic 从 `JOBS` 移除后，APK 里不再生成该条目，**但本地 DB 是增量更新的，那行还指着
已不存在的路径** → 运行时报 `module 'xxx' not found`。

### APK 内置的 32/64 两份 DB 指向**不同的 blob**

```
assets/32/assets.db:  DmViewMediator -> release/a6/91/b32b9876...   flags 字节 0x00
assets/64/assets.db:  DmViewMediator -> release/68/2c/a3c82e46...   flags 字节 0x08
```

字节差异在第 4 字节（LuaJIT 字节码 flags），两份明文共 229 字节不同。
设备是 x86_64 模拟器，用 32 位那份会被判成 `cannot load incompatible bytecode`。
**自愈/还原的原版来源必须取 `assets/64`。**

### 自愈逻辑只管 `.luac`，且判断要精确

`patch_runtime_db.py` 现在推设备前会扫全表，但：
- 只处理 `.luac`（只有它们走"内容寻址 + 由 JOBS 决定是否重打包"这条链路）
- 语音等资源是**按需下载**的，APK 里只有 207 个 `.acb`，用"文件是否在 APK 里"判断必然误报
- 还原条件只有两种：路径悬空，或该行正好等于 32 位原版（说明被误写成 32 位变体）

### 服务端 14002 的 `profession` 必须是合法职业

客户端 `BattleDataParser:fillHeroSpeed`（:465-494）按 `heroData.profession` 去
`ConfigValue.tsv` 的 `ClassAniTime` 里找 `{front, jump, back}`，找不到直接断言：

```lua
assert(moveDur and #moveDur == 3, "Hero speed init failed!!!!")
```

合法职业只有 6 个：`ASSASIN DEFENDER FIGHTER MAGE MARKSMAN SUPPORTER`。
曾硬编码 `profession="WARRIOR"` → 第二关一点开始战斗就报
`BattleDataParser.lua:451: Hero speed init failed!!!!`。

**第一关没事是因为它走表里那份静态响应**（`profession="MAGE"`），第二关开始才走生成器。
`Character.tsv` 的 `Position` 是 `Char_Pos_LaJ` 这种**文本 key**，不能当职业用。

### 战斗数据来自服务端响应，不是客户端自己拼的

```lua
-- StageSystem.lua:694
self:enterStageBattle(response.data, leaveTeamView)   -- 就是 14002 的响应
```

所以 14002 里任何字段写错都会在 `buildAll → parseBattleData` 阶段炸。

### 角色中文名在 `Text.tsv` 里是明文

`dump_sample.json` 里的 `Char_Name_*` 是十六进制密文，读不出来；但 `Text.tsv` 未加密：

| id | 中文名 | English |
|---|---|---|
| LaJ | 塔可 | Tako |
| MoG | 姬露… | J-001 |
| ChuanSJ | 戈琳 | Golin |
| ShiZ | 利昂列夫 | Leonlev |
| HuL | 佩璐 | Peru |

（`StoryGelin` 是剧情 NPC，和角色列表是两回事，别搞混。）

---

## 七、引导进度必须由服务端下发（第二关死循环）

### 现象

```
13:01:53  Step19 → 19_1 → 20 → 27 → 29 → 34 → 35 → 35_1
13:02:17  Step16 ← 回退 → 17 → 17_0 → 18 → 19 → … → 35_1
13:03:01  Step16 ← 又回退 → …
```

每到 `Guide1_Step35_1` 就弹回 `Guide1_Step16`（Order=21）重播整段。

### 根因

`GuideWidget.lua:436-448`：

```lua
local server = self._guideSystem:getFinishServerLastGuideId(GroupId)
local serverConfigOrder = server and GameStyle:getGuideById(server).Order or 0
if saveConfig.Order <= serverConfigOrder then
    self._guideSystem:setFinishLastGuideId(curGuideData.Id)   -- 本地直接推进
else
    self._guideSystem:finshGuide({ curGuideData.Id }, callbackfinsh)  -- 去问服务端
end
```

而 `GuideSystem:requestGuideToServer`（:576-586）**只判 `resCode` 就回调，不读 `guideData`**。
`guideData` 全项目只有一个消费点：

```lua
-- DevelopSystem.lua:95-97
if data.guideData then
    self:getGuideModule():synchronize(data.guideData)
end
```

也就是必须放在**玩家同步**里，形状是 `{ [GroupId] = { guideId = "Guide1_StepXX" } }`（`GuideModule.lua:24-33`）。

我们以前从不下发 → `serverConfigOrder` 恒为 0 → 每步都走 `finshGuide` → 服务端仍不回 →
进度永远记不上 → 引导回组内起点。

### 修法

`rrcp_server.py` 里记录 10027（引导步上报）里出现过的最大 `Order`，
并在 `10001` 响应里加 `data.player.guideData`。

### 顺带注意：`Guide.tsv` 的 Order 有空档

`Guide1_Step35_1` 的 Order=33，下一步 `Guide1_Step36` 的 Order=**35**，**34 是空的**。
做"下一步"相关的判断时别假设 Order 连续。

---

## 20. 战斗技能等级必须发 1（已修 r5）

- 现象：拉长战斗后每帧报
  `LUA ERROR: .../script/skills/Skill_ChuanSJ.lua:326: attempt to compare number with nil`
- 报错路径是 APK 内 `pack_temp/Resources/script/skills/`，**不走 assets.db**，是原版文件。
- 根因在原表 `Skill.tsv` 的数据缺陷，不是 mock：
  `ChuanSJ_S2_B`（FuncName=`Skill_ChuanSJ_PassiveSkill`）的 Parameter：
  - `Parameter_1 = [{effParam2:30000, effParam1:3000, effParam:0.3}]`  <- 有 effParam
  - `Parameter_2..5 = [{effParam2:3000, effParam1:0.6}]`               <- 缺 effParam
  而 `Skill_ChuanSJ.lua:487` 无条件读：
  `if global.CheckCD(_env) and _env.curHpRatio <= _env.skillArgs.effParam then`
  -> `number <= nil`。
- `skillArgs` 来源：`BattleDataParser.lua:448-456` `getSkillArgs()` =
  `deepCopy(skillCfg["Parameter_"..lv])`，**列表取第 1 项**。
- 修法：`rrcp_server.py` `hero_skills()` 里 `out[k] = 5` 改 `out[k] = 1`。
- 全量扫描结论（5 角色 x 4 技能 x 5 等级，按 `all.<FuncName>` 块精确切分，
  只统计**参与比较/算术**的 nil）：
  **只有 lv1 全部 OK**；lv2~lv5 打断 `ChuanSJ_S2_B`(缺 effParam) 和 `HuL_U_B`(缺 effParam)。
- 为什么线上不报：真人新英雄是 1 级。我们写死 5 级才踩到。
- 之前战斗 9 秒秒杀、技能来不及触发，所以这个雷一直没暴露。

## 21. 引导 Step36 循环：静态可确认的触发链（上一节结论已推翻，勿重犯）

**先作废的错误结论**：曾判定"`isPlayingNextStep` 的 `GuideLink=="1"` 分支不 dispatch
`EVT_CHECKGUIDE`，导致 Step36 永不显示"。**这是错的**，战斗内另有专用派发链。
另外"`saveGuideStep` 里 `closeGuide()` 关掉了引导"也是错的——
`GuideWidget.lua:424` 的 `closeGuide()` 只在 `curGuideData.GuideLink == "-1"` 时调用，
`Step35_1` 是 `""`，走 426 行 `_curGuideStepId = NextGuideId`。

### 真正的触发链（战斗内专用，与 isPlayingNextStep 无关）

1. `BattleUIMediator:changeCardState(roleId, state)`（610-636），
   某张战斗卡片 `state == "show"`（ready）时：
   - `_cid == "ChuanSJ"` 且 `not isFinshGuide("Guide1_Step36")` -> 派发
     `EVT_CHECKGUIDE {index="guide601"}`
   - 同理 LaJ -> `guide6001`/`guide6`，MoG -> `guide6003`/`guide602`
2. `GuideWidget:changeCardState` 上方另有等价逻辑（BattleUIMediator:523-535）。
3. 唯一监听点：`MainSceneMediator.lua:185` -> `showGuideView` -> `GuideWidget:showGuide`(205)
4. `showGuide` 只用 `eventData.guideId`（战斗这条**不带 guideId**，靠当前 `_curGuideStepId`）
5. `checkCurGuideStep(215)` -> 视图匹配则 `playingCurGuideStep` -> `callBack`(467)
   -> `Step36.Param7=true` -> `pauseBattle()`，等玩家点 `_guide_ChuanSJ`
   -> 节点冒泡 `bubbleEvent`（`GuideWidget:342/355`）-> 完成该步。

### 静态逐个闸门核算结果：全部"应该通过"

- `_guideUIOpenStatus=true`：`saveCurGuideStepId`(266-277) 调 `openGuide()` 置位，
  教程开始后全程为 true。
- `checkGuideStatus()`=true（`GuideSystem:95-101`）。
- `isFinshGuide("Guide1_Step36")`=false：`GuideModule:isFinshGuide`(114-131)
  在 `lastId` 为空时直接 `return false`。本会话服务端没下发过 `guideData`
  （登录发生在进度累积之前），所以 `_finishLastGuideId` 为空 -> 闸门放行。
- `_curGuideStepId`=`Guide1_Step36`，`Param1=battlePlayer` 与顶层视图匹配。
- 戈琳确实在战斗数据里（`cid=ChuanSJ`，`C00S02` 的 playerData.heros）。

### 仍然剩下的唯一疑点（只能靠运行时探针）

既然所有闸门静态都算得通而 Step36 就是不出现，那只剩
`BattleUIMediator:changeCardState` 是否真的对**戈琳那张卡**被调用过 `"show"`，
以及 `heroCardView._cid` 是否严格等于 `"ChuanSJ"`。
这两点是运行时事实，静态读码无法确定 -> 必须加文件探针重打包验证。

### 其它已确认事实

- 调数值有效：第二关战斗 9 秒 -> **39 秒**（玩家 Atk 6000 -> 300，敌方 HP 3000，
  一击秒杀 -> 约 10 下打死一只），但循环依旧，**时长假设排除**。
- `ForcedGuideId` 唯一用途是**登录恢复**：`MainSceneMediator.lua:307-314`
  取上次完成步的 `ForcedGuideId` 当恢复点。
  `Step35_1.ForcedGuideId = Step35` -> 重登会退回"点战斗按钮"那步。
- `GuideModule:synchronize`(24-33) 把**同一份**服务端数据
  `valueReplace` 进 `_finishServerLastGuideId` 和 `_finishLastGuideId` 两个表，
  所以服务端下发的 `guideData` 会同时影响 `isFinshGuide` 的判定 ——
  下发前必须确认报出的 guideId 的 Order，否则会误关闸门。
- `checkCurGuideIdAndCurViewName`(249-260) 视图不匹配时**静默 return**，
  不报错不推进 -> 排查引导卡死不要指望日志。
- `Step16`/`Step17` 的 `Param1=battleSuccessView`，它们是**结算页剧情**，
  引导"回退"到 Step16 本身不是 bug，问题是本该在它之前的 Step36 从未执行。

## 22. 【根因】红点连环崩是自己埋的 unlock 标志导致的（已修）

- 现象：进主界面连环弹 Lua ERROR，6 轮逐个系统崩：
  `PayShopModel:282` -> `PayShopSystem:531` -> `PayShopSystem:715` ->
  `SuccessSystem:80` -> `PrismCoreModel:245` -> ...
  链路都是
  `HomeMediator:initVariable(799) -> initBottomListRed(827) -> refreshRedPointCtrl(854)
   -> RedPointController:new/initialize/refresh(142) -> HomeSystem:L_checkFunc(563)`
- **根因**：`build_patched_luac.py` 的 `patch_sdkhelper` 注入了
  `GameConfigs.closeCheckUnlockSystem = true`（注释里的因果写反了）。
  游戏原版代码：
      -- Unlock.lua:103-111
      function Unlock:getIsUnlock(systemId)
          if GameConfigs.closeCheckUnlockSystem then
              return true                    -- 打开 = 一切返回 true
          end
          return self._unlockSystemMap[systemId] and self._unlockSystemMap[systemId].unlock, configData
      end
  打开它 = 所有系统都"已解锁"，于是
      -- HomeSystem:698-711
      for v in {PostTask,Shop_main,Archive,PrismCore,Battlefield,Maze,EquipmentZone} do
          if self._unlockSystem:getIsUnlock(v) then   -- 永远为真
              local isRed = self:updataRedPoint(v)     -- 全部都会进去
          end
      end
  任何系统只要假设"服务端已下发对应 datas"就崩。
  **不是缺数据，是把门全打开后逐个撞到没数据的房间。**
- 修法：删掉该赋值，改为在 10001 的 `UnlockSystemListData.unlockSystemMap`
  里精确声明（当前 48 解锁 + `Friend_Main:{real:false}`）。没声明的自然为
  nil(falsy)，那些分支根本不会进。
- **解锁条目绝不能带 `unlockCondition`**：
      -- Unlock:compaSystemId (81-101) 首次同步时 _oldUnlockData 为空，
      -- 若条目带该字段且 syscfg.IsPlay==1 会索引 nil 报错。
- `UnlockSystem:checkSystemIsUnlock(128-132)` 在未解锁时会
  `assert(config ~= nil, ...)`，config 来自 `GameStyle:getUnlockSystem` =
  `FunctionUnlock` 表，所以 systemId 必须能在 `FunctionUnlock.tsv` 里找到。
- `FunctionUnlock.tsv` 共 82 个系统（列 rowId/Order/Page/IsPlay/...）。

### 已补的 datas（每个都按客户端消费代码反查字段，不猜）
| key | 客户端读取处 | 载荷要点 |
|---|---|---|
| `PlayerPay.monthCards` | `PayShopModel:synchronize:61` / `inquireMonthCardServiceData:283` | `expireTime=0` 可跳过 `expireTimeDate` 的 nil 陷阱 |
| `PlayerPay.gifts` | `PayShopSystem:isShowSecondRedPoint:530` / `getVipGiftInfo:700` | key 任意、value 必须有 `giftId`；`buyNums=1` 免红点 |
| `ActivityData` | `ActivitySystem:getFundTask:718` / `getDepositActivity:701` | `FundActivityMode._baseFundInfos` 默认 `{}`，空表安全 |
| `AchievementData` | `SuccessSystem:getSuccessTypeWorking:86` | typeMap 要覆盖 `AchievementType.tsv` 的 3 个 type |
| `PrismCoreData` | `PrismCoreModel:getNextOrderByType:290` | `order` 要 > `PrismCoreLevel.Limit`(max 16) 才能让 `isShowReadPointByType` 短路 |

## 23. 抽卡（15001）做不了，原因在这

- 卡池/掉落相关配置：
  `Gacha.tsv`(97 池) -> `GachaRoute.tsv`(91 条) -> `Reward.tsv`(**13332 行**)
- 抽卡请求是服务端的：`CardPoolService:requestDrawCard` = **opcode 15001**，
  另需 15002~15007（购买/兑换/记录/领奖/兑换码）。当前一个都没实现。
- `15001` 响应契约（从 `CardPoolModel:formatCardPoolData:193-229` 反推）：
  `data.result` = **多次抽取**的数组，每个元素 = 单次抽到的**奖励列表**，
  元素字段 `{code, type, amount, heroId?}`；`type` 会被 `string.upper()` 后与
  `RewardType` 比较（注意 `RewardType.kHero == "CHAR"`，不是 "HERO"）。
- **阻塞点**：`Reward.tsv` 的 `RandomType` 有 **23 种**语义：
  FIXED(10199) / ONCE2(1170) / ARRAYS(956) / TIMES(499) / GROUPARRAYS(152) /
  WEIGHT(189) / PROB(104) / NOREPLACE(17) / COUNT / SEEDS / PLAYERID /
  SERVERDAYS / SERVERSEEDS / SERVERTIMES / PLAYERDAYS / TIMESRESETBYMAXVALUE ...
  其中 TIMES 的桶 key 是**累计抽数阈值**（保底），NOREPLACE 是不重复机制，
  SEEDS/PLAYERID/SERVER* 依赖服务端 RNG 状态。
  各类型的 `Content` 结构还不一样（ARRAYS 是 `[{"1":[reward,...]}]`，
  遍历时甚至会遇到桶值不是数组的行）。
- 结论：这是**一个独立的逆向+实现任务**，不是补个 data key。
  做简化版会得到错误掉率，属于编造，不做。
  目前只提供了 `GachaponData`（3 个池）+ 门票 `IM_GachaTicket` 9999 张，
  **15001 未实现 -> 点抽卡会超时**。

## 24. 本轮新增的构建坑

- Lua 探针字符串字面量**不能跨行**。在 Python 里拼多行 Lua 字符串时，
  片段必须写成 `.. " xxx=" ..`（**每个片段自带首尾引号**），
  漏一个开引号就是 `')' expected near '='`，而且只在编译时才暴露。
  已踩 3 次（`gid=`、`act=`、`->`/`size=`）。干跑补丁函数 + 数引号能提前发现。
- `GuideWidget.lua` 现在带 3 处行为/探针改动：
  - `isPlayingNextStep` 的 `GuideLink=="1"` 分支补 `dispatch(EVT_CHECKGUIDE)`，
    并把 `_saving` 提前置 false（callbackfinsh 本来就在 saveFinish 之后才置）。
  - `/sdcard/gp.txt` 探针：`showGuide` / `MISMATCH` / `isPlayingNextStep` /
    `callBack` / `btnNode` / `windowFit`。
  - 已验证有效：Step36 能被显示（`DISPLAY Guide1_Step36`）。
    但引导层仍不可见，因为 `windowFit`(284-297) 在目标节点为 nil 时把遮罩
    挪到 `(-300,-300)` 零尺寸并静默 return，而 `callBack` 的 `pauseBattle()`
    已经执行 -> 战斗冻住、引导隐形。根因是 `_guide_ChuanSJ` 取不到
    （来自 `BattleMainMediator:setGuideEvent` 遍历 `getCardWidget()` 的
    `widget._heroCard`）。**这个还没修**。

### 24.5 红点总入口加 pcall 兜底（2026-10-08 已装）

- 邮件红点那条**不走** `getIsUnlock`，所以上一步的解锁表盖不住：
      HomeSystem:updataMailRedPoint(149) -> MailSystem:synchronizeMail(41)
        -> GuildModel:getsHaveGuild(254) -> GuildModel:getGuildId(54)
        -> string.split(self._guildData.clubId, "_")  <- clubId 为 nil
      `string.split` 第 19 行是 `string.find(str, p, nextpos, plain)`，
      str 为 nil 就报 `bad argument #1 to 'find'`。
- 已补 `PlayerClubData`，**`clubId` 必须是 `""`**：
  `string.split("")` 里 `string.find("","_")` 返回 nil -> 返回 `{}` -> `ids[1]`=nil
  -> `GuildModel:99 return getGuildId() and getGuildId() ~= ""` -> nil(falsy)
  -> `updataGuildHomeRedPoint(345)` 与 `ChatPlayerSystem:getGuildChatRedPoint(340)`
     都提前return。
  **别填 "0_0"**：那样 `getGuildId()=="0"` != "" -> 判定"有公会"
  -> 反而去取 nil 的公会/聊天数据。
- 但继续静态追下去还有 `ApexRank:getRedPointStatusByRankType(366)` ->
  `getTaskModel():checkCanReceiveTaskByType`、`BattlePassSystem:homeRedPoint(332)` ->
  `getOpenBattlePass()`、`getFistPayGiftData(888)` -> `getFirstGift()` 都依赖
  没有的数据，一个一个补 datas 是打地鼠。
- 因此给**唯一聚合入口**加了兜底（已有 tagpath，从运行时 db 查的：
  `assets/release/5a/74/0122e0470061381b0599daae090f.luac`，源文件 1914 B）：
      -- RedPointController:refresh(42)  local show, num = self._checkFunc()
      -- 改成 pcall；失败就 /sdcard/rp.txt 记一笔并按 show=false, num=0 处理
  理由：红点只是提示，缺数据时正确行为是"不显示红点"，
  而不是弹模态错误框卡住玩家。pcall 正好表达这个语义。
- 踩坑：`D:\Temp\yqlr\_out_decompile` 只是**补丁用到的部分拷贝**，
  新增补丁文件的源要先从 `E:\Test\Temp\yqlr\_out_decompile` 拷过去，
  否则 build 报 `FileNotFoundError: job['src']`。
- 查逻辑文件的 tagpath 办法（不用翻 pathmap.json，那是图片映射）：
  运行时 db `assets` 表 `select logic,real,size,hash from assets where logic=?`，
  `real` 就是 `release/xx/yy/....luac`。本地副本在
  `%TEMP%\opencode\rt_assets.db`（`patch_runtime_db.py` 拉下来的）。

## 八、待办

- [ ] `PayShopModel.lua:282` 的 `serverCfg` 空指针（月卡数据未提供）
- [ ] 编队上限：`ConfigValue.tsv` 的 `BattleNumberUnlock` 条件是 `ClearChapter0`
      （通关整个 C00 章），所以第一关上限 1、第二关上限 3。要提高得另想办法
- [ ] `TeamGroundWidget.lua` 若必须改，得先解决 `return` 后死代码的反编译产物问题

### 24.5 红点总入口加 pcall 兜底（2026-10-08 已装）

- 邮件红点那条**不走** `getIsUnlock`，所以上一步的解锁表盖不住：
      HomeSystem:updataMailRedPoint(149) -> MailSystem:synchronizeMail(41)
        -> GuildModel:getsHaveGuild(254) -> GuildModel:getGuildId(54)
        -> string.split(self._guildData.clubId, "_")  <- clubId 为 nil
      `string.split` 第 19 行是 `string.find(str, p, nextpos, plain)`，
      str 为 nil 就报 `bad argument #1 to 'find'`。
- 已补 `PlayerClubData`，**`clubId` 必须是 `""`**：
  `string.split("")` 里 `string.find("","_")` 返回 nil -> 返回 `{}` -> `ids[1]`=nil
  -> `GuildModel:99 return getGuildId() and getGuildId() ~= ""` -> nil(falsy)
  -> `updataGuildHomeRedPoint(345)` 与 `ChatPlayerSystem:getGuildChatRedPoint(340)`
     都提前return。
  **别填 "0_0"**：那样 `getGuildId()=="0"` != "" -> 判定"有公会"
  -> 反而去取 nil 的公会/聊天数据。
- 但继续静态追下去还有 `ApexRank:getRedPointStatusByRankType(366)` ->
  `getTaskModel():checkCanReceiveTaskByType`、`BattlePassSystem:homeRedPoint(332)` ->
  `getOpenBattlePass()`、`getFistPayGiftData(888)` -> `getFirstGift()` 都依赖
  没有的数据，一个一个补 datas 是打地鼠。
- 因此给**唯一聚合入口**加了兜底（已有 tagpath，从运行时 db 查的：
  `assets/release/5a/74/0122e0470061381b0599daae090f.luac`，源文件 1914 B）：
      -- RedPointController:refresh(42)  local show, num = self._checkFunc()
      -- 改成 pcall；失败就 /sdcard/rp.txt 记一笔并按 show=false, num=0 处理
  理由：红点只是提示，缺数据时正确行为是"不显示红点"，
  而不是弹模态错误框卡住玩家。pcall 正好表达这个语义。
- 踩坑：`D:\Temp\yqlr\_out_decompile` 只是**补丁用到的部分拷贝**，
  新增补丁文件的源要先从 `E:\Test\Temp\yqlr\_out_decompile` 拷过去，
  否则 build 报 `FileNotFoundError: job['src']`。
- 查逻辑文件的 tagpath 办法（不用翻 pathmap.json，那是图片映射）：
  运行时 db `assets` 表 `select logic,real,size,hash from assets where logic=?`，
  `real` 就是 `release/xx/yy/....luac`。本地副本在
  `%TEMP%\opencode\rt_assets.db`（`patch_runtime_db.py` 拉下来的）。

---

## 25. full unlock 后主界面报错长尾：`ScheduleData` / `SiteSystem` 名片三件套 / 玩家 31 字段补齐 (2026-10-08 17:08 - 17:17)

背景：按用户要求 full unlock（`UnlockSystemListData.unlockSystemMap` 覆盖 `FunctionUnlock.tsv` 全部 82 项，
每项 `{"unlock":true,"show":true,"real":true}`，**不得含 `unlockCondition`**）后，主界面暴露一串
"服务端字段缺失 -> 客户端 nil 索引" 的模态报错。此类问题的共同特征：
**服务端少下发一个字段，客户端某处直接 `local cfg = sys:getXxx()` 后索引 `cfg.Res` 就崩**。

### 25.1 `DailyScheduleModel.lua:124 dutyHero` = 补 `ScheduleData` (r18)
根因：`getSchedule()` 直接 `data.dutyHero.heroId`，无 nil 保护。
修复（服务端补数据，不改客户端）：
```json
{"dutyHero":{"heroId":""}, "segmentMap":{}, "weatherMap":{}, "assistHeroMap":{},
 "finishHeroMap":{}, "indexTotalMap":{}, "heroData":{"heroId":"","resetTimes":0}}
```
教训：full unlock 打开的每个系统都需要一份完整的空壳数据结构，不能只补"用到的"字段。

### 25.2 `HomeCenterWidget.lua:941 cardConfig` = 名片/头像/头像框三件套 (r19)
链路：`HomeCenterWidget:initialize(61)` -> `setCenterView(1671)` -> `setPlayerInfoWidget(941)`
```lua
-- HomeCenterWidget.lua:1056-1063
local cardConfig = self._siteSystem:getNameCard()
local headConfig = self._siteSystem:getNameHead()
local path = string.format(kSitePath .. cardConfig.Res, "a")   -- cardConfig 为 nil
```
```lua
-- SiteSystem.lua:218-226 / 230-238 / 208-215
function SiteSystem:getNameCard()
    local cardId = self._developSystem:getPlayer():getNameCard()
    if cardId == "" then cardId = self:getDefaultCard() end      -- 只认 ""，不认 nil
    local config = ConfigReader:getRecordById("ShowCard", cardId)  -- nil -> 崩
```
**关键判据：代码写的是 `== ""` 而不是 `or 默认值`，所以"未设置"必须下发空串 `""`，
下发 nil 会让 fallback 分支失效。** 修法：`nameCard=""`, `avatar=""`, `headBox=""`。
（这三个字段正是上一轮我判为"只影响显示、nil 可容忍"而没填的，教训：**显示字段不等于可省略字段**。）

### 25.3 剩余 10 个玩家字段按代码实际类型一次性补齐 (r20)
`player` 从 21 字段补到 31 字段。类型全部取自客户端代码，不猜：
| 字段 | 值 | 依据（客户端原代码） |
|---|---|---|
| `loginDays` | `0` | `Login.lua:143  self._loginDays = 0` |
| `heroShow` | `{}` | `BasePlayer.lua:107  self._heroShow = {}`；`ChatPlayerInfoModelBase:101` 直写 `data.heroShow`，`:196` 立刻 `pairs(self._heroShow)` |
| `todayOnlineTime` | `0` | `Player.lua:194  self._todayOnlineTime = 0` |
| `lastForeground` | `0` | `BasePlayer.lua:137` 直写，无消费者 |
| `totalMoney` | `0` | `PayShopModel.lua:82/:87  self._totalMoney <= 0`（nil 比较会崩） |
| `headFrames` | `{}` | `BasePlayer.lua:246  self._headFrames[id] = value`（nil 索引会崩） |
| `vipLevel` | `0` | `ChatPlayerInfoModelBase.lua:59  self._vipLevel = 0` |
| `gender` | `0` | 全工程无 `getGender()` 消费者，死字段 |
| `birthday` | `""` | `SitePlayerPageWidget:91,197  if birthday == ""` |
| `signature` | `""` | `Player:getSignature` + `ChatPlayerInfoModelBase:266  if signature and utf8.len(...)` |

### 25.4 访问器由 objectlua 运行时生成（重要）
`DevelopSystem.lua:770-771` 调用 `self:getPlayer():getVipLevel()`，
但全工程 `function *.getVipLevel` **只有 DevelopSystem / PayShopMainMediator 的定义**，
`Player.lua` 里也没有 `getmetatable/__index/rawset` 生成器，`BasePlayer.lua:1` 是
`BasePlayer = class("BasePlayer", objectlua.Object, _M)`。
结论：`objectlua.Object` 基类按字段列表**运行时生成**访问器（与 `redirectAssignmentToPrototype`
把方法搬到 `__prototype__` 是同一套机制）。**所以补数据就能生效，不需要给客户端加桩方法。**

### 25.5 本轮版本
- `r18-scheduledata-20261008` -> `DailyScheduleModel` 报错已消除（用户实测通过）
- `r19-sitecard-20261008` -> 名片三件套
- `r20-playerfields-20261008` -> 剩余 10 字段
当前 mock 已重启为 r20（17:17:00），**等待客户端实测**。
观察点：`ChatPlayerInfoModelBase`（开聊天）、`PayShopSystem/PayShopModel`（开商城）、
`SitePlayerPageWidget`（个人主页）。三处若仍有报错，说明本轮类型判断有误，需回查。

---

## 26. `GuideWidget.luac:765 getName` = 我自己探针的 bug（非游戏 bug） (2026-10-08 17:18 - 17:31)

### 26.1 现象
`GuideWidget.lua:765: attempt to call method 'getName' (a nil value)`
链路 `MainSceneMediator:149 dispatch -> isPlayingCurGuideStep:253 -> showGuide:221
-> isPlayingNextStep:679 -> callBack:506 -> showBtn:791 -> getBtnNodeByName:765`。

**排查关键：`.lua` 源里 grep 不到 `getName`，装机包也没有独立 luac 条目（Lua 打包在 assets.db）。**
真正原因：GuideWidget 的补丁不是改 `.lua` 源，而是由
`build_patched_luac.py:841 patch_guidewidget()` **在编译期注入**，`getName` 藏在 Python 字符串里。
**以后定位补丁问题要 grep `build_patched_luac.py`，不能只 grep `.lua` 源。**

### 26.2 根因（探针 5，`build_patched_luac.py` 原 973-976 行）
```lua
_gp_probe("btnNode P2=" .. tostring(curGuideData.Param2) ..
" -> " .. tostring(node1 and node1:getName() or "NIL") .. ...)
```
`node1` 为**真值但不是 cocos 节点**（objectlua 缺方法时 Lua 正是报
`attempt to call method 'getName' (a nil value)`），于是探针自己把游戏打崩了。
`Guide500_Step2` 的 `Param2=homeLayer.playView.activityLayer.starfieldBtn` 找不到节点，
落到 `getGuidePoint1` 钩子返回非节点对象 -> 探针调 `getName()` 崩。

### 26.3 修法
在 `patch_guidewidget` 的 helper 里注入安全取名器，探针 5/6 全部改用它：
```lua
local function _gp_nodename(n)
    if not n then return "NIL" end
    local ok, v = pcall(function () return n:getName() end)
    return ok and tostring(v) or ("NO_NAME(" .. type(n) .. ")")
end
```
**教训：调试探针绝不能假设对象类型。凡是对外部返回对象调方法，一律 pcall 包住。**

### 26.4 `Guide500` 是什么（full unlock 触发，与 Guide1 无关）
`Guide.tsv` 第 197-204 行，`GroupId=Guide500`，共 8 步，是 **StarField 星域探索活动引导**：
| rowId | Order | ActionType | Param1(视图) | Param2(目标) |
|---|---|---|---|---|
| Guide500_Step1 | 2 | TALK | homeView | **(空)** |
| Guide500_Step2 | 3 | CLICK | homeView | homeLayer.playView.activityLayer.starfieldBtn |
| Guide500_Step3 | 4 | CLICK | StarFieldMainView | _guide_floorNode_0 |
| ... | | | | |
| Guide500_Step8 | 9 | TALK | teamMultiView | (空)，`GuideLink=-1` 结束标记 |

- 服务端 `guide_data()` 只返回 `{'Guide1': {'guideId':'Guide1_Step107'}}`，
  **对 Guide500 无效** —— Guide500 是 full unlock 解锁活动后由客户端自己触发的。
- `guide_state.json` = `{"Guide1":33,"Guide719":1}`，Guide1 卡在 33（跳过标记 Step107 只在响应里，不落盘）。

### 26.5 纠正一个错误判断
之前以为 `windowFit MISS -> 引导被挪到屏幕外` 意味着引导不可见（Step36 冻屏）。
**实测证明：`windowFit MISS` 只表示"该步骤没有高亮目标节点"，
`ActionType=TALK` 的步骤对话框照样完整渲染**（Step1 的姬霓霞台词正常显示）。
Step36 冻屏是**另一个**原因（`pauseBattle()` 已执行 + 目标 `_guide_ChuanSJ` 不存在），别混为一谈。

### 26.6 本轮验证结果（17:31）
- 新进程 27147：**无任何 LUA ERROR**
- `gp.txt` 探针正常：`btnNode P2= -> nil P3= -> nil`
- 主界面 82 个入口全部渲染（收集/作战/行程中心/曜变玩法/跃迁战记/量子阶梯/荣耀对决/
  星际旅团/星际探索/悬赏平台/瑰丽百货/日志档案/云脑系统/玩法/聊天）
- 日志辨伪：logcat 里 25893/26727 的报错都是**旧进程残留**，
  判断当前状态必须用 `ps -A` 拿当前 PID 再过滤，否则会误判"修了没生效"。

---

## 27. 签到活动两条报错：服务器时间偏移 + `MonthSignData` (2026-10-08 17:45 - 17:54)

### 27.1 `ActivitySignMonthModel.lua:64 没有找到当月奖励月10年2026` -> 服务器时间前移 (r22)
链路：`HomeMediator:149 -> SignMonthMediator:184 updateViewUI -> :55 enterWithData
-> :40 getMonthReward -> ActivitySignMonthModel:64 getRewardCfg`

- `getMonthReward(:34-38)` 用**服务器时间**算当月：
  `GameServerAgent():remoteTimestamp()` -> `os.date("%m"/"%Y")`
- `getRewardCfg(:56-71)` 遍历 `getSignMonthTable()` 找 `v.Month.year==year and v.Month.month==month`
- `getSignMonthTable(:158-163)` 读的是**配置表** `SignMonth.tsv`，**不是服务端数据 -> 补字段没用**
- `SignMonth.tsv` 实测 34 行，只覆盖 **2022-03 ~ 2024-12**；设备 2026-10 -> 必然 assert

**修法**：`rrcp_server.py` 新增 `SERVER_TIME_TARGET='2024-10-15 12:00:00'` +
`Server.server_time_ms()`，把响应包头 `i64 timestamp` 整体前移 -723.2 天。
偏移在首次调用时算一次，之后时间照常流逝（不冻结）。设 `None` 关闭。

**实测已验证有效**：设备时间从 17:45 变成 04:00，证明
`GameServerAgent:remoteTimeMillis()` 取的是**包头时间戳**，不是设备时间。
（此前无法静态确认，因为 `client` 由 `rrcp.createClient()` 这个 **C++ 模块
`lua_rrcp.cpp`** 创建，源码不在工作区；`_timeOffset` 恒为 0、从未被服务端赋值。）

### 27.2 `SignMonthMediator.lua:372 almanac 为 nil` -> 补 `MonthSignData` (r23)
- `_activtyServerData` = `ActivitySignMonthModel._serverMonthSignData`，
  `initialize:18` 初始化为 `{}`，由 `synchronizeActData:22-26` 灌入
- `refrestRewardList(:396-404，源码拼写是 refrest)` 直接索引
  `self._activtyServerData.almanac.reward`，**无 nil 保护**

**找数据入口的关键**：`Activity.tsv` 里根本没有 SignMonth 活动（Type 分布里也没有），
`ActivitySignMonthSystem:getActivityModel(:201-205)` 走的是
`DevelopSystem:getSignMonthModel()` 单例，所以数据不走 ActivityList。
真正入口在 **`DevelopSystem.lua:254-256`**：
```lua
if otherDatas and otherDatas.MonthSignData then
    self:getSignMonthModel():synchronizeActData(otherDatas.MonthSignData)
end
```
即 `10001.data.player.datas.MonthSignData`，**扁平 payload**（非按活动 id 的 map）。

写入值全部取自配置表，未手填：
| 字段 | 值 | 依据 |
|---|---|---|
| `almanac.event` | `Fun_Birth128` | `SignMonthEvent.tsv` 中 `ServerTime=2024-10-11`，与前移后的服务器日期相符 |
| `almanac.tip` | `SignMonthEvent_Fun_Birth_24` | 上一行 `Describe` 的 key |
| `almanac.should` | 9 条 | `SignMonthAlmanac.tsv` 行 `Should`.Describe |
| `almanac.taboo` | 8 条 | 同上，行 `Taboo`.Describe |
| `almanac.buff` | `""` | `updateBuff(:234)` 要求 `~= ""` 才查 `getRewardBuffById`，空串即跳过 |
| `almanac.reward` | `[]` | `mergeRewardData:907` 对空表是 `pairs({})` 空循环，安全 |
| `almanac.openCondition` | `{currentValue:1, targetValue:0}` | 见下 |
| `num` / `isToday` | `0` / `false` | `SignMonthMediator:359/:225`、`:48` |

18 个 Strings key 已逐个在 `Text.tsv` 中校验存在。

**为什么 openCondition 取 1/0 而不是 0/0 或 0/1**（`SignMonthMediator:216-276` 三分支）：
- `currentValue == targetValue` -> `:219 updateAlmanac()` 走 `getSignMonthEventById`
  （安全），但 `:252 gotoDeblockingView` 条件也成立，会**自动弹出 signMonthBuffView**
- `currentValue < targetValue`（0<1）-> `:262` 命中 `lock` 分支，会
  `animateWidget:playAniamte -> sendReceiveRequest()`，**发出 mock 未实现的网络请求**
- `1 > 0` -> 三个分支都不命中，`:273` 只切个 page，无网络请求、无自动弹窗 -> **最稳**

### 27.3 经验
- **定位服务端数据入口别只看活动表**：本例活动不在 `Activity.tsv` 里，
  是 DevelopSystem 直接 sync 的单例模型。找法：从 `getXxxModel()` 反查
  `has("_xxx")` 字段，再搜 `synchronizeActData(` / `:synchronize(` 的调用点，
  调用点的 `otherDatas.XXX` 字段名才是真正的数据 key。
- **配置表覆盖范围是硬约束**：日期类断言（SignMonth/活动窗口/每日重置）
  往往受 `SignMonth.tsv` 这类表限定，装机能改的只有"服务器时间"。

---

## 28. 档案页三条报错：`VoiceData.unlocked`（其中一条是连锁反应）(2026-10-08 18:00)

用户一次贴出三条：
1. `ArchivesModel.lua:177 attempt to index field 'unlocked' (a nil value)`
   链路 `ArchivesHeroDetailsMediator:177 initSoundView -> ArchivesModel:193 getVoiceCfg -> :177 getVoiceUnlock`
2. `ArchivesHeroDetailsMediator.lua:127 attempt to concatenate local 'max' (a nil value)`
3. `ArchivesHeroDetailsMediator.lua:127 setNumCom`（同一条的不同栈）

### 28.1 第 1 条根因
```lua
-- ArchivesModel.lua:160-162
function ArchivesModel:getVoiceUnlock(condition)
    return self._voiceUnlock.unlocked[condition]   -- _voiceUnlock 是 initialize:26 的 {} -> .unlocked 为 nil
end
```
`_voiceUnlock` 由 `synchronizeVoice(:50-54)` 灌入，调用点在
**`DevelopSystem.lua:275  self:getArchivesModel():synchronizeVoice(otherDatas.VoiceData)`**
即数据 key = `10001.data.player.datas.VoiceData`。

### 28.2 第 2/3 条是**第 1 条的连锁反应**（不要单独修）
`ArchivesHeroDetailsMediator:initView:147-154` 是顺序调用：
```
147 initUpView()
148 initSoundView()      <-- 这里崩了
149 initBaseView()
150 initDeepData()
152 initDeepView()       (performWithDelay 0.02)
154 initChatView()       <-- 根本没执行
```
`initChatView(:368-373)` 才给 `_haveChatNum`/`_totalChatNum` 赋值。
它没跑 -> 切到 tab 1 时 `setNumCom(:157-160)` 收到 nil 的 max ->
`self._maxNum:setText("/" .. max)` 拼接 nil -> 崩。
**修 VoiceData 即可连带解决，不用给 setNumCom 加保护。**

### 28.3 写入内容（全部由配置表推导）
`VoiceData = {"unlocked": {<Condition>: 1, ...}}`
- 键来源：`Voice.tsv` 的 `Condition` 列，**只取 `Show==1` 的 3745 行**
  （因为 `getVoiceCfg:179` 只对 `Show==1` 的 cfg 调 `getVoiceUnlock(cfg.Condition)`）
- 共 **294 个不同 Condition**（`Unconditional` 1912 条、`Function_unlock_Stage_C00S04` 1292 条等）
- 值用 `1`：`ArchivesHeroDetailsMediator:229-232` 是 `if v.isUnlock then` 纯真值判断
- 按full unlock 原则全部标记为已解锁

### 28.4 `ArchiveData` 暂不补（依据充分）
`DevelopSystem.lua:258-260` 确实有 `otherDatas.ArchiveData` 入口
（`heroArchive` / `storyMap` / `books` / `seasonBuffs`），但 grep 全工程发现
**`_heroArchive` 只有 `ArchivesModel:3/22/32` 三处，全是写入，没有任何读取点**。
`synchronize(:30-48)` 每个字段也都有 `if data.X then` 保护，
所以缺 `ArchiveData` 不会崩，只是档案页内容为空。等真需要展示时再补。

### 28.5 经验
- 一次贴出多条同页报错时，先判断**是不是连锁**：顺着 `initView` 的调用顺序看
  前一个函数有没有崩，比逐条追更省时间。
- 判断某个 `datas.XXX` 是否必需，除了看入口，还要 grep 字段有没有**读取点**；
  只有写入没有读取的（如 `_heroArchive`）不必急着补。

---

## 29. 角色养成配置项（全解锁 / 满星 / 满级 / 满突破），上限全部由表推导 (2026-10-08 18:05)

用户要求：「给服务端加个角色全解全满星，**不要写死而是加配置项**」。

### 29.1 新增配置项（`rrcp_server.py` 的 `Server` 类，紧跟 `valid_professions()` 之后）
```python
HERO_UNLOCK_ALL = True      # 全部角色都放进 HeroesData.heroes
HERO_MAX_STAR   = True      # starId 指向该角色满星档
HERO_MAX_RANK   = True      # adv 拉满
HERO_MAX_LEVEL  = True      # level 拉满
HERO_MAX_FAVOR  = False     # 好感拉满（默认关）
HERO_KEEP_EXISTING = True   # 保留 opcodes_table.json 里已有角色的字段
HERO_LEVEL_CAP  = None      # 覆盖等级上限；None = 取表
HERO_RANK_CAP   = None      # 覆盖突破上限；None = 取表
HERO_STAR_CAP   = None      # 覆盖星级；None = 取表
HERO_SET_EXP    = 0
```
新增方法：`read_tsv()` / `hero_ids()` / `hero_caps()` / `apply_hero_config()`，
在 `__init__` 里紧跟 `self.load_table()` 之后调用
（**必须早于 14002 战斗生成**，那边也读同一份 `HeroesData.heroes`）。

### 29.2 上限的推导依据（表驱动，不是常量）
| 项 | 来源 | 实测值 |
|---|---|---|
| 角色全集 | `Character.tsv` 的 60 个 rowId | 60（与 JSON `_heroIds.all` 完全一致） |
| 等级上限 | `CharLevel.tsv` rowId | 1..**150** |
| 突破上限 | `CharUpRank.tsv` rowId=`<heroId>_<rank>` | 每角色 1..**10** |
| 满星档 | `CharUpgrade.tsv` 中 **`NextId == "-1"`** 的行 | `<heroId>_5`，StarAmount=5，60/60 全有标记 |

### 29.3 客户端字段对应（`HeroBase.lua:synchronize:120-166`）
- `starId` -> `self.star = self:_getStar()` ← **这才是星级**
  （`_getStar:511-516` 走 `getUpgradeConfig:952-956`
   = `ConfigReader:getRecordById("CharUpgrade", starId)`，返回 `StarAmount`；
   `getIsMaxStar:518-522` 判 `upgradeConfig.NextId == "-1"`）
- `adv` -> `getRank():1422-1424`，**不是星级**，是突破；`getMaxRank():1430-1432` 客户端写死 `return 10`
- `level` / `exp`
- `heroFavor.favorLv` -> `favorLv`（好感）

### 29.4 运行结果（18:05:48）
```
[角色] HERO_UNLOCK_ALL=True MAX_STAR=True MAX_RANK=True MAX_LEVEL=True
[角色] 共 60 个角色（新增 56 / 改写 0），上限 level=150 adv=10 满星=60
```
- 原有 4 个角色（LaJ / MoG / ChuanSJ / ShiZ）按 `HERO_KEEP_EXISTING=True` 保留字段，
  只覆盖 level/adv/exp 并补 starId
- starId 自洽性校验通过：`AnWZ_5` / `LaJ_5` / `ChuanSJ_5` / `MoG_5`，
  且每行 `StarAmount` 与推导值一致
- 日志末尾会对缺满星 starId 的角色报警，便于发现表变动

### 29.5 已知遗留
原有 4 个角色带 `combat: 60000`，新增 56 个没有 `combat` 字段。
读侧 `HeroBase:125 if data.combat then` 有保护，暂时不崩；
但如果之后发现战力显示/结算不一致，需要给 combat 也加一个配置项。

---

## 30. `CarPoolNewWidget:32 format got table` + `ChipSystem:35 pairs got nil` (2026-10-08 18:12)

### 30.1 卡池报错：`gachaponInfos[*].today` 类型错（是数字不是对象）
链路：`HomePoolWidget:547 initWidget -> :94 initCardPool -> CarPoolNewWidget updateView`
```
-- CarPoolNewWidget.lua:27-32
local rewardNum, total = self._cardPoolSystem:getPoolRewardNum(copyPoolCfg)
self._count:setText(string.format("%d/%d", rewardNum, tostring(total)))
```
`#2` 是 `rewardNum`，实际拿到了 table。追下去：
```
-- CardPoolModel.lua:88-91（synchronize）
if v.today ~= nil then self._poolRewardNum[k] = v.today end
-- CardPoolSystem.lua:80-84（getPoolRewardNum 的非 NEW 分支）
local serverCfg = self:getCardPoolModel():getPoolRewardNum()   -- = self._poolRewardNum
rewardNum = serverCfg[poolCfg.Id] or 0
```
我们下发的 `GachaponData.gachaponInfos[x].today = {}` 被原样塞进 `_poolRewardNum`，
取出来就是**空表** -> `%d` 报 `number expected, got table`。
**修**：`today` 全部改成 `0`。

依据：全 cardPool/chip 目录里 `.today` 只出现在 `CardPoolModel:89-90` 两行，
其消费者是 `checkLimitMaxNum:117 rewardNum = total - rewardNum`（算术）
和上面的 `%d`，所以必须是 number。

### 30.2 芯片报错：缺 `datas.ChipBag`
```
-- ChipModel.lua:3-9（initialize）只建 self._chips = {}
-- ChipModel.lua:49-51（setChipList）才建 _chipList / _chipHeroIds
-- setChipList 只被 synchronize:34 / syncDeleteData:46 调用
-- ChipSystem.lua:33-41（checkHeroIsHaveChip）
local list = self:getChipModel():getChipsOnHero()   -- nil
for k, v in pairs(list) do                            -- pairs(nil) 崩
```
不发 `ChipBag` -> `synchronize` 不跑 -> 两个字段永远 nil。
入口 `DevelopSystem.lua:292-293  if otherDatas.ChipBag then getChipModel():synchronize(...)`。
**修**：`datas.ChipBag = {"chips": {}}`（空表即可，`setChipList` 会把两字段初始化为 `{}`）。

### 30.3 顺带记录两个坑
1. **文件名拼写**：`CarPoolNewWidget.lua`（游戏源码少个 d），
   traceback 里显示成 `CardPoolNewWidget.lua`，按后者 glob 会找不到文件。
2. **版本号正则**：`CODE_VERSION` 的中间段含连字符（`r25-hero-config-...`），
   我用的 `r[0-9]+-[a-z0-9]+-[0-9]+` 匹配不到导致 assert 失败。
   现在统一改成 `CODE_VERSION = '[^']*'`。

### 30.4 当前 datas 全量 key（17 个）
AchievementData / ActivityData / CampaignData / **ChipBag** / FunctionListData /
GachaponData / HeroesData / MonthSignData / PlayerClubData / PlayerPay /
PrismCoreData / ScheduleData / StairsBattleData / TaskCenter / Teams /
UnlockSystemListData / **VoiceData**
（仍缺但暂不崩的：ArchiveData，见第 28.4 节 —— `_heroArchive` 无读取点）

---

## 31. 中文配音：默认配音语言是 JP，不是 CN (2026-10-08 18:33 - 18:40)

用户：「修复一下中文配音」。

### 31.1 根因（两层）
**客户端默认值层**
```
langConfig_release.lua:6 / langConfig_debug.lua:6
GameDefaultVoiceLanguage = GameLanguageType.JP      <-- 语言表里 CN="cn" JP="jp"
language.lua:87/89   trycall(require, 'yq.langConfig_debug' / 'yq.langConfig_release')
language.lua:158-162 getCurrentLanguageForVoice() 读 UserDefault 的 GAME_VOICE_LANGUAGE，
                    未设置时回落到 GameDefaultVoiceLanguage
dmAudio.lua:1-2      relativePath="sound/"  cvRelativePath="sound/voice"
dmAudio.lua:42-50    getVoiceLanguage() 用它拼出 "sound/voice_" .. lang
```
实测设备 `shared_prefs/Cocos2dxPrefsFile.xml` 里 **`GAME_VOICE_LANGUAGE` 根本不存在**，
所以取默认 `jp` -> 客户端去找 `sound/voice_jp/`。
**结果：中文文本 + 日语配音。**

**数据层（已排除，不是原因）**
运行时 `assets.db` 里三个语音目录**都在**：
`sound/voice_cn` 120 条 / `sound/voice_en` 119 条 / `sound/voice_jp` 117 条，
且 cn 是超集（独有 3 条）。所以切到 cn 一定有资源。

### 31.2 修了什么（两层都上保险）
1. **改默认值（持久，客户端补丁）**
   - 把两个 langConfig 的 `GameDefaultVoiceLanguage` 从 `JP` 改成 `CN`
   - D:\_out_decompile 里原本**没有**这两个源文件，先从 E: 复制过去
   - `build_patched_luac.py` 的 `JOBS` 追加 2 项 + 新增 `patch_langconfig()`
     （该函数带两条 assert，防止源里漏改或残留 JP）
2. **写 SharedPreferences（即时生效，当前安装立刻有效）**
   ```
   <string name="GAME_VOICE_LANGUAGE">cn</string>
   ```
   步骤：force-stop -> pull -> 改 -> push -> `chown 10062:10062` + `chmod 660`
   （adb push 会把属主变成 root，必须修回来）

### 31.3 两个踩坑
1. **内容寻址路径算错**
   `assets.db` 的 `real` 字段格式是
   `release/<hash[0:2]>/<hash[2:4]>/<hash[4:]>`，APK 路径 = `assets/` + real。
   我一开始把**整个 32 位 hash 当文件名**，结果
   `KeyError: There is no item named ... in the archive`。
   正确值（已验证存在于 APK）：
   - `yq/langConfig_release.luac` -> `assets/release/44/73/aa6c2200db3ee29612af64e0a74e.luac`
   - `yq/langConfig_debug.luac`   -> `assets/release/3b/ff/b732753c07600ae3e1156685e738.luac`
   > 从 db 取路径的通用写法：`select real from assets where logic=?`，
   > 再拼 `'assets/' + real`，**不要自己按 hash 推**。
2. **`JOBS` 每一项都必须在 `PATCHERS` 里有函数**
   `build_patched_luac.py:1361` 是 `PATCHERS[logic](fix_syntax(src, logic), None)`，
   缺项直接 KeyError。哪怕源文件不需要改，也要给个恒等函数。

### 31.4 一个观察（未处理）
`localization.lua:145-155` 里
```lua
if region_cn_Channel[channel] or GameConfigs and GameConfigs.Region_CN then
    function _G.checkLocale(checkType, params) ... end
end
_G.checkLocale = nil        -- 紧接着无条件清掉
```
即 CN 区的资源替换（`region_cn_Voice` 21 个 id / `region_cn_Spine` / `region_cn_Live2d`）
**从不生效**。实测那 21 个 voice id 在 cn/en/jp 三个包里**都不存在**，
所以目前看不出症状；但 `asset/anim/region_cn_*.skel`（219 条）是存在的，
意味着国区的 Spine 替换资源在包里躺着却不会被加载。
若日后出现「国区立绘/骨骼显示不对」，根因就在这里，需要删掉那行 `_G.checkLocale = nil`。

---

## 32. 【已回退】中文配音改成 CN 后配音完全消失 (2026-10-08 18:48)

第 31 节的改动**导致配音整体没声**，用户要求改回去。已完整回退。

### 32.1 回退动作
1. `build_patched_luac.py`：删掉 2 个 langConfig 的 `JOBS` 条目、
   `patch_langconfig()` 函数、`PATCHERS` 两行注册（断言 `langConfig` 无残留）
2. D:\_out_decompile 里两个 `langConfig_*.lua` 从 E: 原始文件恢复为 `JP`
3. 重新 编译 -> patch_runtime_db -> rebuild_v5 -> zipalign -> apksigner -> install
   - 条目总数从 **20329 回到 20327**（langConfig 贡献的 +2 消失）
   - 签名包 **1720645739 字节**，与 17:01 已知可用版本尺寸完全一致
4. SharedPreferences 删除 `<string name="GAME_VOICE_LANGUAGE">cn</string>`，
   回落到默认 JP；校验：现在只剩 `GAME_LOCAL_SETTING_LANGUAGE=cn`
   和空的 `GAME_SETTING_LANGUAGE`

### 32.2 为什么我的推理错了（教训）
我当时只验证了「`sound/voice_cn` 在 assets.db 里存在，且是 jp 的超集」，
就断定切到 cn 一定有资源。**这个结论不成立**，忽略了 `_G.isSupportLangAudio`
这套 DLC 存在性机制：
```
GameExtensionAsset.lua:741-749
    local isDefault = GameDefaultVoiceLanguage == key     -- 默认语言视为"已就绪"
    local has  = sizeInfo.list[key] and sizeInfo.list[key] > 0
    local need = sizeInfo.need[key]  and sizeInfo.need[key]  > 0
    local already = isDefault or has and finishedInfo[key].finished and not need
    _G.isSupportLangAudio[key] = already == true
dmAudio.lua:42-50  getVoiceLanguage()  若 isSupportLangAudio[lang] 为假 -> 回落默认语言
```
**`GameDefaultVoiceLanguage` 不只是"回退默认值"，它还是"哪个语言包算基础包/无需下载"的判据。**
把它从 JP 改成 CN，等于同时改了"回退目标"和"基础包归属"，
而离线环境下语音包的下载/就绪状态对不上，最终一个都不播。

### 32.3 教训（比结论重要）
1. **"资源在 db 里存在" ≠ "运行时能加载"**。
   资源可用性还受 DLC/热更新状态机（`sizeInfo` / `need` / `finishedInfo`）控制，
   静态扫 db 得出的结论不能直接当运行时结论。
2. **改"默认值"前要先看它被当成什么语义用**。
   这里它同时是「回退目标」和「基础包标记」，是个复合语义的常量，
   改之前应该 grep 所有引用点（第 31 节我只看了
   `language.lua:158` 和 `dmAudio.lua:42` 两处就动手了）。
3. **改动前先留可回退的基线**：本次因为有 17:01 的已知可用 APK，
   才能靠「签名包字节数完全一致」快速确认回到原状。

---

## 33. 回退后的收尾：为什么配音会彻底没声 + db 与 APK 不同步 (2026-10-08 18:48 - 18:54)

### 33.1 【硬证据】只有 jp 的语音文件真的在包里
把**设备 db 的每一条 `real` 与 APK zip 的 namelist 逐条比对**，结果：

| 目录 | 在 APK | 缺 APK |
|---|---|---|
| `sound/voice_cn` | **0** | **240** |
| `sound/voice_en` | **0** | **230** |
| `sound/voice_jp` | **234** | **0** |

全库 20541 条中，`real` 指向 `release/` 却不在 ZIP 里的共 **470 条，全部是 voice_cn / voice_en**。

**结论：cn / en 语音是需下载的可选语言包，音频文件根本没打进这个 APK；
只有默认的 jp 是基础包、随包发布。**
所以第 31 节把默认语言改成 CN 后，客户端去找 `sound/voice_cn/xxx`，
文件不存在 -> **一个都不播**，与用户现象"配音直接没了"完全吻合。
回退是唯一正确的选择，中文配音在离线环境下**不可能**实现
（除非把 470 个文件也打进包，而我们手上没有它们）。

> 顺带修正第 31/32 节的推理方向：当时猜的是 `_G.isSupportLangAudio`
> 的 DLC 就绪状态机（方向没错），但真正的硬原因是**文件不存在**。
> 教训：判断"资源能不能用"必须做 **db.real × ZIP namelist 的逐条比对**，
> 只统计目录条目数（我先前数到"cn 120 条、比 jp 还多"）会得出完全相反的结论 ——
> 条目数在 db 里，不代表文件在包里。

### 33.2 回退时踩的坑：热推 db 与 APK 不同步
回退 APK 装上后立刻报：
```
language.lua:105  module 'yq.langConfig_release' not found
  no field package.preload['yq.langConfig_release']
  no file 'script/yq/langConfig_release.lua' / './yq/langConfig_release.lua' / ...
```
即 `require` 的自定义 searcher 在 db 里查到了条目、但按 `real` 去 APK 取文件失败，
于是退回到文件系统路径全部落空。

原因：18:39 那次带 CN 补丁的构建通过 `patch_runtime_db.py` 往设备
`/data/data/<pkg>/files/assets.db` 热推了一份**指向 CN 新内容寻址路径**的 db
（`release/3e/cf/b950…`，size 361/357）。18:48 回退时我只重装了 APK，
**没有重新生成并推送运行时 db**，于是设备 db 仍指向包里已不存在的文件。

修法：回退流程里 **`patch_runtime_db.py` 必须重跑**（18:51 执行，推送成功），
推送后 langConfig 的 `real` 回到原始值 `release/44/73/aa6c…`（size 414）。

### 33.3 以后每次打包都该做的自检（这次靠它抓到问题）
把 db 的 `real` 与 APK zip 逐条比对，两个库都要查：
```python
import zipfile, sqlite3
z = set(zipfile.ZipFile(APK).namelist())
# 设备运行时库
c = sqlite3.connect(r'...\dev_assets.db')
# APK 内库
c = sqlite3.connect(APK_DB32)   # 先把 assets/32/assets.db 抽出来
for lg, real in c.execute("select logic, real from assets where real like 'release/%'"):
    if ('assets/' + real) not in z:
        print('缺:', lg, '->', real)
```
正常状态：**只有 470 条 voice_cn/voice_en 缺失**，其余 0 缺失。
若缺失数明显大于 470，说明 db 与 APK 不同步，要重跑 `patch_runtime_db.py`。

### 33.4 判 logcat 的坑（这次差点误判）
用 `-v time` 格式时行结构是 `MM-DD HH:MM:SS.mmm  PID  L/TAG: message`，
用 `" $pid: "` 过滤会**匹配不到任何东西**（PID 后面没有紧跟冒号），
应写成 `" $pid "`。另外截图里的报错框可能是**上一轮启动残留**，
判断"修好没有"必须 force-stop + `logcat -c` + 冷启动后重看。

---

## 34. 配音修复成功：真正原因是 `GAME_VOICE_LANGUAGE` 被写成 `cn` (2026-10-08 19:11 - 19:16)

### 34.1 定位手段：把 dmAudio 接进已有的文件探针通道
`print()` 已进不了 logcat（`cocos2d-x` tag 0 命中），但 `/sdcard/rp.txt`
通道是活的（GameStyle/RedPoint/AssistSystem 探针一直在写）。
所以给 `yq/assets/dmAudio.luac` 加探针，沿配音链路埋 6 个判定点：
`getVoiceLanguage()` 返回值 / `filePath`+`awbFilePath` 的 isFileExist /
`loadAcbFile` 返回的 acbHn / `playCueByNameFromBlock` 返回的 playback /
传给 native 的 CueName。

新增内容（`build_patched_luac.py`）：
- `JOBS` 加 `yq/assets/dmAudio.luac`
  （tagpath `assets/release/11/a0/fa23d2579e18f7b5989e9fac6178.luac`，从 db.real 取）
- `patch_dmaudio()`，内含 `_ap_probe()` 写 `/sdcard/rp.txt`

### 34.2 一行探针就定位到根因
```
[voice] getVoiceLanguage pkg=LaJ pref=cn default=jp support=nil
[voice] !! file NOT exist path=sound/voice_cn/LaJ.acb type=3 pkg=LaJ
```
`default=jp`（说明第 31 节的默认值改动确实是 CN，被我回退了），
但 **`pref=cn`** —— `GAME_VOICE_LANGUAGE` 这个用户偏好里存着 `cn`。
它优先于默认值，于是去找 `sound/voice_cn/LaJ.acb`，
而 cn 语音包 240 个文件**根本不在 APK 里**（第 33.1 节）→ 静默。

**所以第 31 节我改默认值是对的方向但改错了对象**：
真正需要的是这个 **pref**，不是 `GameDefaultVoiceLanguage`。
更糟的是我改 pref 时先删掉、结果它又被游戏写回 cn，白折腾一轮。

### 34.3 修法（一行数据）
```
SharedPreferences/Cocos2dxPrefsFile.xml
  <string name="GAME_VOICE_LANGUAGE">jp</string>
```
- 与 `GameDefaultVoiceLanguage`（jp）一致，也是包内唯一有音频的语言
- 写入后**未被游戏改回**（19:14 复查仍是 jp）
- 稳定机制：`VoiceSelectWidget:28`
  `self._curVoice = getCurrentLanguageForVoice() or GameDefaultVoiceLanguage`
  —— `getCurrentLanguageForVoice()` 永远返回字符串（默认 jp），
  所以 `or` 分支永不触发；只要 pref 是 jp，`:98` 的
  `setCurrentLanguageForVoice(lang)` 只会把 jp 再写回 jp，自我一致

### 34.4 修复后探针（19:16:33，全程无失败分支）
```
[voice] getVoiceLanguage pkg=WuY pref=jp default=jp support=nil
[voice] file OK path=sound/voice_jp/WuY.acb type=3 cue=WuY_Voice_Login_01
[voice] acbPath=sound/voice_jp/WuY.acb awbPath=sound/voice_jp/WuY.awb awbExist=true acbExist=true
[voice] loadAcbFile -> acbHn=userdata: 0x7218c66ede50 fileExist=true pkg=WuY
[voice] playCue -> playback=userdata: 0x7218c66e8c08 cue=WuY_Voice_Login_01 block=0
```
文件存在 -> native 加载返回句柄 -> cue 播放返回 playback 对象，**配音恢复**。
BGM(type=1) / UI 音效(type=2) 也全程正常。

### 34.5 结论：中文配音在离线下仍不可能
`voice_cn` 240 个文件不在包里，除非能拿到并打进 APK。
能做到的上限就是 **jp 配音**（已达成）。

### 34.6 教训
1. **同名的两个"语言来源"要分清**：`GameDefaultVoiceLanguage`（编译期常量）
   vs `GAME_VOICE_LANGUAGE`（运行期 UserDefault 偏好，后者优先）。
   第 31 节只改了前者。
2. **静态推断必须落到运行时数据上**。第 31/32 节反复纠结
   `_G.isSupportLangAudio` 的 DLC 状态机，真正答案是一个 pref 值；
   而 `getCurrentLanguageForVoice()` 的默认值参数把 `nil` 可能性排除了，
   这一点如果早点注意到，就能直接想到去查 pref。
3. **删用户偏好前先确认谁会写回它**。我删掉 `GAME_VOICE_LANGUAGE` 后
   它又出现，浪费了一轮回退+重打。
4. **`print` 不可用时优先复用既有的文件探针通道**，别再去猜。

---

## 35. 角色好感 `heroFavor` 缺失导致两个界面崩 (2026-10-08 19:22)

用户贴了两条报错，**同一个根因**：
- `HeroInfoMediator.lua:1248 attempt to index field 'heroFavor' (a nil value)`
  链：`HomeHeroListWidget:485 clickCallBack -> :461 -> :170 -> HeroInfoMediator:1881
  changeHeroRefreshView -> :1831 initView -> :214 enterWithData -> refreshHeroPersonalityView`
- `ArchivesHeroDetailsMediator.lua:495 attempt to index field 'heroFavor' (a nil value)`
  链：`setNumItems -> initDeepView -> setNumItems`

### 35.1 无保护索引点（都没有 nil 判断）
```
HeroInfoMediator.lua:1377-1378
    self.heroFavorLevel = self._heroConfig.heroFavor.favorLv
    self.heroFavorCur   = self._heroConfig.heroFavor.curFavor
HeroInfoMediator.lua:1317
    return self._heroConfig.heroFavor.favorLv == len - 1
ArchivesHeroDetailsMediator.lua:593
    if self._heroConfig.heroFavor.favorLv < paramData.level then
```

### 35.2 这是第 29 节 hero 配置项引入的暴露面
`HeroBase:synchronize:145-147` 写端有保护：
```lua
if data.heroFavor then self.favorLv = data.heroFavor.favorLv end
```
**但读取端照样崩**，所以"这是可选字段"的判断是错的。
第 29 节开了 `HERO_UNLOCK_ALL` 后 60 个角色全部可点，之前只有 4 个，
才把这些读取点暴露出来。

### 35.3 `heroFavor` 只需要两个字段
全工程 `heroFavor.<字段>` 统计：`favorLv` 22 处、`curFavor` 11 处，
而 `value` / `FLevel` 是 **UI 节点名**
（`DailyScheduleWidget:431-433 getChildByFullName("heroFavor.value")`），不是数据字段。

### 35.4 上限来自 Favorability.tsv
```
HeroSystem:getFavoraData():600-609   data = ConfigReader:getDataTable("Favorability"); return data, len
HeroInfoMediator:1381  self.favorDatalen = len - 1        -- 满级 = len-1
HeroInfoMediator:1385  if heroFavorMax == -1 then        -- 满级档
```
实测 `Favorability.tsv` 11 行(rowId 0..10)，`FavorabilityValue`
= 60/90/150/210/270/365/450/565/700/745/**-1**
-> 最大 `favorLv` = **10**，满级档是 -1（无上限）。

### 35.5 修法
`apply_hero_config()` 里改为**无条件**写 `heroFavor`，
`HERO_MAX_FAVOR` 只决定它的值（不再决定"写不写"）：
```python
if Server.HERO_MAX_FAVOR:
    h['heroFavor'] = {'favorLv': fav['max_lv'], 'curFavor': fav['cur_max']}
else:
    h['heroFavor'] = {'favorLv': 0, 'curFavor': 0}
```
新增 `favor_caps()` 读表推导上限（`max_lv`=行数-1，`cur_max`=最后一个有限值 745）。
启动日志新增两行自检：已下发 heroFavor 的数量、以及缺 heroFavor 的角色报警。

运行结果（19:22:15）：
```
[角色] 共 60 个角色（新增 56 / 改写 0），上限 level=150 adv=10 满星=60
[角色] heroFavor 下发 60 个，favorLv 上限=10 curFavor=745（MAX_FAVOR=False）
```

### 35.6 遗留（游戏自身缺陷，非本次引入）
`HeroInfoMediator:1264-1273` 送礼升好感时
```lua
elseif self.heroFavorMax <= value then
    local nextData = self.favorData[tostring(self.heroFavorLevel + 1)]
    ...
    self.heroFavorMax = nextData.FavorabilityValue   -- favorLevel 已满 10 时 favorData[11] 为 nil -> 崩
```
满级后再送礼会崩。`favorLv=0` 时要一路升到 10 才会碰到，
`favorLv=10` 则立刻能碰到。要彻底修需要客户端加钳位。

---

## 36. `personalityMap` 缺失 -> 角色性格雷达图崩 (2026-10-08 19:26)

### 36.1 现象
`HeroInfoMediator.lua:1351: attempt to index local 'curPerData' (a nil value)`
链：`HomeHeroListWidget:485 clickCallBack -> :461 -> :170
-> HeroInfoMediator:1881 changeHeroRefreshView -> :1831 initView
-> :214 enterWithData -> refreshHeroPresonalityView -> drawRegularPolygon`

### 36.2 根因
```lua
-- HeroInfoMediator:1475-1488（drawRegularPolygon）
local curPerData = self._heroConfig.personalityMap      -- :1478
...
local cur = curPerData[v]                              -- :1486  <- nil 就崩
cur = cur and cur or data.init                          -- :1488 有兜底，但兜底在崩溃之后
```
和第 35 节的 `heroFavor` 同一类问题：**写端有 `if data.personalityMap then`
保护（HeroBase:183-189），读取端照样崩**。上一轮补了 `heroFavor` 后
执行流前进了一步，才暴露出紧接着的 `personalityMap`。

### 36.3 无保护读取点共 6 处（补一个字段一次修好 4 个潜在崩溃）
| 位置 | 代码 |
|---|---|
| `HeroInfoMediator:1478` | `local curPerData = self._heroConfig.personalityMap` |
| `DailyScheduleChooseHeroMediator:322` | 同上 |
| `DailyScheduleClinicViewMediator:531` | 同上 |
| `DailyScheduleHeroInfoViewMediator:119` | 同上 |
| `HomeWorldSystem:654 / :666 / :817` | 同上 |
| `HomeWorldHeroSelectMediator:128` | `hero.personalityMap[newFavor] > 0`（缺 key 直接崩） |

### 36.4 键集合来自客户端枚举
`GameTypesCfg.lua:592-617`
```lua
HeroFavorType = { ALL="ALL", HEDONIC="Hedonic", DOMINATE="Dominate",
                  CALM="Calm", RIGOROUS="Rigorous", LIVELY="Lively",
                  AMIABLE="Amiable" }
HeroFavorContList = { Calm, Hedonic, Amiable, Rigorous, Dominate, Lively }
```
6 个维度，`ALL` 是伪类型、**不在 ContList 里，不应作为 map 的键**。

### 36.5 取值 0 为什么安全
- `HeroInfoMediator:1488` `cur = cur and cur or data.init`
  —— **Lua 里 0 是真值**，所以 `cur = 0`，不会走 `data.init`；
  随后 `:1490-1496` 按配置的 `data.min/data.max` 钳位，不会越界
- `HomeWorldHeroSelectMediator:128` `0 > 0` 为假，不崩
- `HomeWorldSystem:1019-1020` 本身带 `or 0` 保护

### 36.6 修法（配置项）
新增三项（沿用第 29 节"不写死"的要求）：
```python
HERO_PERSONALITY_MAP = True    # 是否下发 —— 必须 True，否则上表 6 处会崩
HERO_PERSONALITY_VALUE = 0     # 6 个维度的默认值
HERO_PERSONALITY_KEYS = ('Calm', 'Hedonic', 'Amiable',
                         'Rigorous', 'Dominate', 'Lively')
```
启动日志新增自检行与缺失报警。运行结果（19:26:13）：
```
[角色] 共 60 个角色（新增 56 / 改写 0），上限 level=150 adv=10 满星=60
[角色] heroFavor 下发 60 个，favorLv 上限=10 curFavor=745（MAX_FAVOR=False）
[角色] personalityMap 已下发（键 ['Calm','Hedonic','Amiable','Rigorous','Dominate','Lively'] 值 0）
```

### 36.7 方法论：一次把角色的"必填字段"列全
这两轮都是**同一个模式**：写端可选、读端必填。与其逐个崩溃再补，
不如在 `HeroBase:synchronize` 里把客户端会无保护索引的字段
一次列出来。目前已知必填清单：`level` `adv` `starId` `heroFavor`
`personalityMap`。后续若再出现同类报错，直接对照这张清单。

---

## 37. 角色「临界3」与「跃升立绘」无法查看 (2026-10-08 19:34)

用户截图：SSR 角色页四个面板，临界/临界5/芯链/跃升中「跃升」带锁，
提示"XX 还没到临界3时解锁独立立绘"。

### 37.1 判定链（全部来自源码）
```
HeroInfoMediator:1669-1786  initHeroUpView  四个面板 = node_rank / node_star
                                       / node_link / node_up(=跃升)
HeroInfoMediator:1721       local unLock = self._heroConfig:getBeyondUpIsUnlock()
HeroInfoMediator:1725       local unLock, str1 = self._heroSystem:getByondUpFuncUnlock()
                            -> str1 就是用户看到的"还没到临界3…"提示
HeroInfoMediator:1739       GameStyle:checkResourceReady("Hero_Awaken", true)
HeroInfoMediator:1751       GameStyle:checkHeroResourceReady(heroId, "Illustration")
HeroBase:389-391            getBeyondUpIsUnlock() = self._beyondUpId and self._beyondUpId ~= ""
HeroBase:397-401            getBeyondUpLevel()   = GameStyle:getCharBeyondUp(id).StarAmount  <- 临界N
HeroBase:403-409            getBeyondUpNum()
HeroSystem:912-916          getByondUpFuncUnlock() = unlockSystem:checkSystemIsUnlock("Hero_Awaken")
HeroBase:363-386            getBeyondUpBtnIsShow() 按 Character.tsv 的 OpenParam 判 level/star/rank
```
即「临界N」就是 `CharBeyondUp.tsv` 里那一行的 `StarAmount`。

### 37.2 逐个排查结论
| 闸门 | 状态 |
|---|---|
| `Hero_Awaken` 系统解锁 | **已满足**（在 82 项全解锁表里） |
| `Character.tsv` 的 `OpenParam` | 59/60 角色有值 `{"star":1,"level":0,"rank":0}`，我们满级满星满足 |
| `beyondUp.id` | **未下发 -> 面板锁死（本次修复）** |
| `checkHeroResourceReady(heroId,"Illustration")` 的资源 | **在包里** |

### 37.3 关键：立绘资源并不缺（与第 33 节 voice_cn 不同）
`asset/Illustration/` 共 118 条，**全部命中 APK**，且清晰版与模糊版都有：
```
asset/Illustration/role_full_AnWZ.jpg          <- 清晰原图
asset/Illustration/role_full_AnWZ_blur.jpg     <- 模糊版
```
59 + 59 = 118，60 个角色全覆盖。
所以「跃升立绘看不了」**不是资源缺失**，而是 DLC 就绪判定：
`GameStyle:checkHeroResourceReady:2741-2757` -> name = `role_full_<heroId>`
-> `GameFastFollowAsset:checkUnlock(name,"nosort")`。
其中 `GameFastFollowAsset:checkUnlock:250-263` 有个关键分支：
```lua
local finished = self:checkFinished()   -- 全部 DLC 完成 -> 直接 true
if finished then return true end
local rawInfo = self:checkInfoExist(name, itype)
if not rawInfo then return true, "not find info for name:..." end   -- 查不到也放过
```
所以只有「DLC 表里**有**该条目、但不在 `finishedList` 里」才会被拦。
设备上 `files/ExtensionInfo_local.json` = `{"needDownload":{}}`。

### 37.4 修法（服务端，配置项）
```python
HERO_MAX_BEYOND_UP = True   # 是否把跃升拉满
HERO_BEYOND_UP_CAP = None   # 覆盖档位；None = 取 CharBeyondUp.tsv 该角色最大档
```
新增 `beyond_caps()` 读 `CharBeyondUp.tsv`（240 行 = 60 角色 x 4 档 0..3），
按 `StarAmount` 取每角色最大值 → 下发
`beyondUp = {"id": "CharBeyondUp_<heroId>_3"}`。

`upChecks` **不用下发**：`HeroBase:44` 已 `self._upChecks = {}`，
且 `getBeyondCheck:217-220` 未解锁时返回 `{}`，有守卫。

运行结果（19:34:17）：
```
[角色] beyondUp 下发 60 个，档位(临界)=[3]（MAX_BEYOND_UP=True CAP=None）
```

### 37.5 待验证
临界3 已修。**跃升立绘是否随之解锁取决于 DLC 判定**：
若仍被拦，需要给 `GameFastFollowAsset` 加文件探针（照 dmAudio 的做法），
看 `checkUnlock` 走的是 `checkFinished` 分支还是 `finishedList` 分支。
立绘资源已确认在包内，所以理论上可解，不像 voice_cn 那样无解。

---

## 38. 临界3立绘：探针定位 + 真相是"两个不同的锁" (2026-10-08 19:45)

### 38.1 探针结论（HeroInfoMediator 已加入 `patch_heroinfomediator`）
```
[beyondUp] gates hero=ShiZ funcUnlock=true btnIsShow=true btnIsHave=true
          unLock=true beyondId=CharBeyondUp_ShiZ_3 level=3
          max=1 cfgBeyondUpId=CharBeyondUp_ShiZ_0
```
- `refreshHeroBeyondUp:1788-1797` 的三道闸（`funcUnlock` / `btnIsShow` / `btnIsHave`）**全部通过**
- `unLock=true` -> `beyondUp.id` 下发**生效**，`HeroBase:389-391` 那道锁已开
- `level=3`（临界3）
- **`max=1`** <- 新的矛盾点

### 38.2 立绘锁其实已经开了
```lua
-- HeroBase:1370-1372
function HeroBase:isUnlockIllustration()
    return self:getBeyondUpNum() > 0
    -- getBeyondUpNum():403-409 = getBeyondUpLevel() = CharBeyondUp(id).StarAmount = 3 -> 3 > 0 = true
end
```
所以 **Illustration（立绘）判定已为 true**，r29 的 `beyondUp.id` 就是为此而加。

### 38.3 那句提示对应的是 L2D，不是立绘
```lua
-- HeroBase:1374-1397 getUnlockTips
tips = { Illustration = "hero_no_paint",   -- Text.tsv: "旅人跃升后解锁"
         L2D          = "heroInfo_no_spine", -- Text.tsv: "旅人达到临界3时解锁立绘"  <- 用户看到的那句
         Por_Spine    = "" }
local star1 = self._config.InitStar
repeat
    local upConfig = GameStyle:getCharUpgrade(star1)
    hasL2d = upConfig.Live2DResource > 0
    star1 = upConfig.NextId
until hasL2d or star1 == "-1"
if not hasL2d then tips.L2D = "heroInfo_no_spine1" end   -- "敬请期待"
```
即提示是 **Live2D(spine)** 的，门槛来自 `CharUpgrade.Live2DResource`（**配置表**）。
实测 `CharUpgrade.tsv` 的 `Live2DResource` 只有 0/1 两种；**60 个角色里 51 个**在
`_3`/`_4`/`_5` 档带 L2D 资源（如 `ShiZ_3/_4/_5`、`AnWZ_3/_4/_5`），
其余 9 个没有 -> 提示会是"敬请期待"。同样是配置，服务端改不了。

### 38.4 `max=1` 的来源：`NextId` 链只有两档
```lua
-- HeroBase:419-421
getBeyondUpMax() = #getBeyondUpAllLevel() - 1
-- HeroBase:423-424  从 _config.BeyondUpId（Character.tsv 列）出发，沿 NextId 走
```
`Character.tsv` 每个角色 `BeyondUpId = CharBeyondUp_<hid>_0`，
而 `CharBeyondUp.tsv` 的链实测为：
```
CharBeyondUp_AnWZ_0  NextId='CharBeyondUp_AnWZ_1'
CharBeyondUp_AnWZ_1  NextId=''
CharBeyondUp_AnWZ_2  NextId=''      <- 孤立，不在链上
CharBeyondUp_AnWZ_3  NextId=''      <- 孤立，不在链上
```
链只有 `0 -> 1`，所以 `#=2`、`max=1`。
**即游戏自身配置只支持 2 档跃升，"临界3"在这个版本里走 BeyondUp 链到不了。**

### 38.5 由此产生的显示不一致（需要用户决策）
`refreshHeroBeyondUp:1814-1818` 会显示 `level` 和 `/max`：
- 现在 `beyondUp.id = <hid>_3` -> 面板显示 **"3/1"**（不一致但无功能影响）
- 若改成 `HERO_BEYOND_UP_CAP = 1` -> 显示 **"1/1"**（一致），
  且 `isUnlockIllustration()` 仍是 `1 > 0` = true，**立绘照样解锁**
两者都能满足"立绘可看"，差别只是面板数字好不好看。等用户选。

### 38.6 结论：服务端能做的已做完
`beyondUp.id` 已下发、60 个角色全绿、三道闸全过、立绘判定为 true。
若界面仍有锁，剩下的是 **L2D / 额外形态的 DLC 资源**（截图里的"未解锁"项与
"+"占位），与第 33 节 voice_cn 同类问题，需要先确认资源是否在包内才能定性。

---

## 39. 真正的开关是 `charUnlockResource`（服务端字段）(2026-10-08 19:52)

第 38 节把 `beyondUp.id` 补上后 `unLock=true`、`level=3`、三道闸全过，
立绘仍锁着 -> 说明还有另一把锁。这把锁也是**服务端字段**，之前漏了。

### 39.1 `charUnlockResource`（HeroBase）
```lua
-- HeroBase:43-50  initialize 的默认值
self.charUnlockResource = {}
self.charUnlockResource.Por_Spine    = 1
self.charUnlockResource.L2D         = 0     <- 默认锁着
self.charUnlockResource.Illustration = 0

-- HeroBase:305-321  服务端字段，逐键覆盖
if data.charUnlockResource then
    for k, v in pairs(data.charUnlockResource) do
        if k == "Por_Spine"   and v == 1 then self._newUnlockSpine = v end
        if k == "Illustration" and v == 1 then self._newIllustration = v end
        self.charUnlockResource[k] = v
    end
end
```

### 39.2 三个判定各看不同的东西（这是之前绕圈的原因）
| 判定 | 依据 | 之前的状态 |
|---|---|---|
| `isUnlockSpine():1354-1360` | `charUnlockResource.Por_Spine == 1` | ✅ 默认就是 1 |
| `isUnlockL2D():1362-1368` | **`charUnlockResource.L2D == 1`** | ❌ 默认 0，**一直锁着** |
| `isUnlockIllustration():1370-1372` | `getBeyondUpNum() > 0` | ✅ 第 37 节已开 |

注意 `isUnlockIllustration` **不看** `charUnlockResource.Illustration`，
后者只用来置 `_newIllustration`（新解锁标记）。
所以第 37 节补 `beyondUp.id` 确实打开了立绘判定，但 L2D 那道门仍锁着。

消费点 `ArchivesHeroDetailsMediator:747-781 openRoleView`：
```lua
if self._heroConfig:isUnlockIllustration() then
    local ready = GameStyle:checkHeroResourceReady(self._heroId, "Illustration") ... end
if self._heroConfig:isUnlockL2D() then
    local ready = GameStyle:checkHeroResourceReady(self._heroId, "L2d") ... end
```

### 39.3 修法（配置项）
```python
HERO_UNLOCK_RESOURCES = True                              # 是否下发 charUnlockResource
HERO_RESOURCE_VALUE = 1                                   # 三键统一取值（1=已解锁）
HERO_RESOURCE_KEYS = ('Por_Spine', 'L2D', 'Illustration')
```
运行结果（19:52:12）：
```
[角色] beyondUp 下发 60 个，档位(临界)=[3]（MAX_BEYOND_UP=True CAP=None）
[角色] charUnlockResource 下发 60 个（['Por_Spine','L2D','Illustration']=1，UNLOCK_RESOURCES=True）
```

### 39.4 教训：一个模型可能有**多个并存的解锁字段**
`HeroBase` 里同时存在三套解锁语义，字段名还高度相似，极易混淆：
- `starId` -> `star`（星级）
- `adv` -> `getRank()`（突破）
- `heroFavor` -> 好感
- `personalityMap` -> 性格六维
- `beyondUp.id` -> 跃升档位（临界）
- `charUnlockResource.{Por_Spine,L2D,Illustration}` -> 形态资源解锁
**补数据前应把"这个界面/判定到底读哪个字段"逐个确认，不要按名字猜。**

另外：角色数据随 10001 在**登录时**下发，改完服务端配置必须**完整退出重登**
才能看到效果，热重连不生效。

---

## 40. 天梯 `StairsBattleData.typeData[*].order` 缺失 (2026-10-08 19:57)

新报错（道具详情弹窗打开时）：
```
LadderSystem.lua:658 attempt to perform arithmetic on local 'order' (a nil value)
链：ItemInfoDetailMediator:184 addPopupView -> :55 enterWithData
    -> LadderSystem:658 getAutoBattleSpeedData -> :578 getAutoBattleSpeed
```

### 40.1 根因
```lua
-- LadderSystem:735-743 getAutoBattleSpeed(offset)
local info = self:getLadderInfoForType(LadderType.COMMON)   -- :293-297 -> _ladderList[type]
local order = info.order            -- 我们从没下发过 -> nil
local battleInfo = self:getBattleInfo(LadderType.COMMON, order + 1 + offset)
--                                                        ^^^^^^^^^^^^^^^ 崩
```
同样的 `info.order` 还被 `getCur2TargetAutoBattleSpeed:745-753`、
`getCurStairId:767-771` 使用，三处都无 nil 保护。

### 40.2 数据入口（已在下发，只是缺字段）
```
DevelopSystem:206   self:getLadder():synchronize(otherDatas.StairsBattleData, isDiff)
LadderModel:85-116  synchronize
    if ladderData.typeData    then GameStyle:valueReplace(ladderData.typeData, self._ladderList) end
    if ladderData.checkMaps   then ... end
    if ladderData.todayReward ~= nil then ... end
```
我们原有的 `StairsBattleData`：
```json
{"typeData":{"COMMON":{"keepingHeroes":{"LaJ":{"uid":1}},"rank":0,"score":0,
            "todayReward":false,"todayRewardGot":false}},
 "checkMaps":{}, "todayReward":false}
```
有 5 个字段，**独缺 `order`**。

### 40.3 order 的语义
```lua
-- LadderSystem:581-591 getBattleInfo(type, order)
local battleGroup = self._developSystem:getLadder():getGroupByType(type)
table.sort(battleGroup, function (a, b) if a.Order ~= b.Order then return a.Order < b.Order end end)
return battleGroup and battleGroup[order] or {}
```
即**名次下标**（1 起）。取不到只返回 `{}` 不崩，
但 nil 会在调用方 `order + 1` 时崩，所以**必须存在**。

`LadderType`（LadderSystem:51-59）= WIND / COMMON / FIRE / LIGHT / WATER / DARK / EARTH，
与 `LadderModel:29` 的 `config.Type == "COMMON"` 配合。

### 40.4 修法（配置项）
```python
LADDER_ORDER = 1
LADDER_TYPES = ('COMMON','WIND','FIRE','LIGHT','WATER','DARK','EARTH')
```
新增 `apply_ladder_config()`，在 `__init__` 里紧跟 `apply_hero_config()` 调用。
运行结果（19:57:59）：
```
[天梯] StairsBattleData.typeData order=1，补齐 7 个类型: [COMMON, WIND, FIRE, LIGHT, WATER, DARK, EARTH]
```
一次给全部 7 种塔类型都补上，避免换塔类型时再崩。

### 40.5 模式复用
`apply_hero_config` / `apply_ladder_config` 都遵循同一套路：
配置项放 `Server` 类 -> 从配置表推导上限 -> 写进 `self.table`
-> 启动日志打印覆盖数量与缺失报警。后续补数据沿用即可。

---

## 41. 无限资源 + 顺带修掉一个一直存在的 bag 结构错误 (2026-10-08 20:04)

用户：「添加无限资源也要给单独配置项」。

### 41.1 【重要】发现 bag 结构一直是错的
我们原先下发的是**扁平 map**：
```json
"bag": {"IR_Gold":{"count":999999,"uniqId":""}, "IR_Diamond":{...}, ...}
```
但客户端只认：
```lua
-- DevelopSystem:137-138
if data.bag then self:getBag():synchronize(data.bag, isDiff) end
-- Bag:synchronize:30-40
if bagData.items then
    for k, v in pairs(bagData.items) do
        self:syncBagPageItems(v.itemId or k, v)
    end
end
-- Bag:syncBagPageItems:42-71
local configData = GameStyle:getItemConfig(itemId)
if configData == nil or configData.Page == nil then return end   -- Page 为空直接丢弃
item.config = configData
self._entryList[itemId] = item
-- 再按 configData.Page 分桶：_resourceList / _charPieceList / _otherList / _equipList
```
正确形状是 `bag.items`。因为**缺了 `items` 这一层，客户端背包一直是空的**，
`BagSystem:getCountById:231-236`（`getEntryById` -> count）恒为 0。
这解释了此前"资源不够/道具不足"类问题的根源。

### 41.2 物品清单来源
`Item.tsv` 451 行，**全部有 Page**：RESOURCE 141 / OTHER 243 / CHAR_PIECE 61 / EQUIP 6。
- `CHAR_PIECE` 就是 `CharUpgrade.Cost` 里用的 `ICP_<heroId>` 碎片（60 个）
- `MaxPile = -1` 的是货币（本就无上限）；活动材料多为 9999
- `BagSystem:getCountById:233-235` 对负数 count 返回 1（`MinUseCnt<0` 的道具）

### 41.3 独立配置项（与 HERO_* 那套完全分开）
```python
RESOURCE_INFINITE = True       # 总开关
RESOURCE_COUNT = 99999999      # 统一数量
RESOURCE_PAGES = ('RESOURCE', 'CHAR_PIECE')   # 只对这些 Item.Page 生效；None = 全部
RESOURCE_EXCLUDE_TYPES = ('RANDOM_CHEST','CHOICE_CHEST','HOURGLASS')  # 排除
RESOURCE_SKIP_EXISTING = False  # True = 保留 JSON 里已有条目的 count
RESOURCE_PLAYER_CURRENCY = True  # 同时拉满 player.coin/diamond/exp
RESOURCE_CURRENCY_COUNT = 99999999
```
新增 `apply_resource_config()`，在 `__init__` 里依次调用
`apply_hero_config()` -> `apply_ladder_config()` -> `apply_resource_config()`。
会自动把旧的扁平条目迁移进 `items` 层。

运行结果（20:04:14）：
```
[资源] 无限资源=True count=99999999 pages=('RESOURCE','CHAR_PIECE') 排除类型=['RANDOM_CHEST','CHOICE_CHEST','HOURGLASS']
[资源] 旧扁平条目迁移 5 个；新增/覆盖 202 个，保留 0 个，共 203 项
[资源] player.coin/diamond/exp = 99999999
```

### 41.4 为什么默认排除三种道具类型
`RANDOM_CHEST` / `CHOICE_CHEST` / `HOURGLASS` 走的是**使用流程**
（`BagSystem:openItemInfoDetailView:238-250` 会按 `MinUseCnt`、`ItemType.CHOICE_CHEST`、
`ItemType.HOURGLASS`、`Page == CHAR_PIECE` 改变弹窗类型），
塞满数量可能触发非预期的使用分支，所以默认排除。需要时把
`RESOURCE_EXCLUDE_TYPES` 置空即可。

### 41.5 教训
「本地写死的几条资源」和「客户端真正读的字段」是两回事。
`bag` 这一处结构错误从项目初期就存在，期间所有"资源不足"的现象都会
被误判成数值问题，直到这次要"全量资源"才暴露出来。
**给字段补全量数据时，正好是核对结构的好时机。**

---

## 42. `SiteModel:getAllBackGround` 的 pairs(nil) -> 补 `SettingInfo` (2026-10-08 20:13)

报错（点主页入口）：
```
SiteModel.lua:115 bad argument #1 to 'pairs' (table expected, got nil)
链：HomeCenterWidget:114 handleClick -> SiteSystem:114 -> SiteModel:344 getUserSite
    -> SiteModel:53 initData -> SitePlayerPageWidget:36 initialize
    -> SiteMainMediator:68 enterWithData
```

### 42.1 根因
```lua
-- SiteModel:114-122
for k, v in pairs(self._setverSettingInfo.allBackGround) do   -- nil -> 崩
-- SiteModel:38  initialize 里 self._setverSettingInfo = {}
-- DevelopSystem:242-243
if otherDatas and otherDatas.SettingInfo then
    self:getSiteModel():synchronizeSettingInfo(otherDatas.SettingInfo)
end
-- SiteModel:60-65  synchronizeSettingInfo -> GameStyle:valueReplace(...)
```

### 42.2 SettingInfo 各字段必需性（全工程 grep）
| 字段 | 读取处 | nil 安全? |
|---|---|---|
| `allBackGround` | `SiteModel:117  pairs(...)` | ❌ **无保护，必须给表** |
| `backGround` | `SiteModel:125  == ""` | ✅ nil 安全（走 ConfigValue 默认） |
| `position` | `SiteModel:135  type(...) ~= "table"` | ✅ 有保护 |
| `achieveMedals` | `SiteSystem:556` | ✅ 消费方 `SuccessWallMedalWidget:16/126` 有 `or {}` |

### 42.3 取值来源
- `allBackGround` 的键取自 `ShowBackGround.tsv`，**实测只有 1 行 `BackGround1`**
- 默认背景 `ConfigValue.tsv` 的 `Common_ShowBackGround = "BackGround1"`
- 注意 `SiteSystem:359` 会把 `getAllBackGround()` 的**全部键**上报服务器，
  所以只填配置表里真实存在的 id，不编造

### 42.4 独立配置项
```python
SITE_SETTING_INFO = True        # 是否下发 datas.SettingInfo
SITE_BACKGROUND_KEYS = None     # allBackGround 的键；None = 取 ShowBackGround.tsv 全部
SITE_BACKGROUND_VALUE = True    # allBackGround 每个键的值
SITE_BACKGROUND = ""            # backGround；"" = 用 ConfigValue 的 Common_ShowBackGround
SITE_MEDALS = None              # achieveMedals；None = 不下发（消费方有兜底）
```
新增 `apply_site_config()`，调用链：
`apply_hero_config -> apply_ladder_config -> apply_resource_config -> apply_site_config`

运行结果（20:13:54）：
```
[空间] SettingInfo 已下发：allBackGround 键 ['BackGround1']，backGround=''
```

### 42.5 当前 mock 的四个 apply_* 顺序与职责
| 方法 | 负责的 datas / player 字段 |
|---|---|
| `apply_hero_config` | `HeroesData.heroes[*]`：level/adv/starId/heroFavor/personalityMap/beyondUp/charUnlockResource |
| `apply_ladder_config` | `StairsBattleData.typeData[*].order` |
| `apply_resource_config` | `player.bag.items`（含旧扁平条目迁移）、`player.coin/diamond/exp` |
| `apply_site_config` | `SettingInfo.allBackGround/backGround/achieveMedals` |

---

## 43. `SuccessWallMedalWidget:124` 的 pairs(nil) -> achieveMedals 必须是表 (2026-10-08 20:19)

报错（进个人空间主页）：
```
SuccessWallMedalWidget.lua:124 bad argument #1 to 'pairs' (table expected, got nil)
链：SitePlayerPageWidget:473 initView -> :482 initBannerList
    -> SitePlayerPageWidget:39 initialize -> SiteMainMediator:68 enterWithData
```

### 43.1 修正第 42 节的一个错误结论
第 42 节我判定 `achieveMedals` "消费方有 `or {}` 兜底"，**这是错的**——
我只看到 `SuccessWallMedalWidget:16`（initialize）有 `or {}`，就以为整条链都安全：
```lua
-- :16  initialize —— 有兜底
self._medals = self._siteSystem:getMedals() or {}

-- :125-138  updateView —— 没有兜底
function SuccessWallMedalWidget:updateView(medals)
    self._medals = medals or self._siteSystem:getMedals()   -- :126 只是 or 传入参，不是 or {}
    for k2, v2 in pairs(self._medals) do                     -- :138 pairs(nil) 崩
```
`medals or ...` 里的 `medals` 是**函数入参**，不是字面量 `{}`。
**教训：判定"某字段 nil 是否安全"，必须看每一处读取点，不能因为其中一处有兜底就放过。**

### 43.2 形状与来源
- `SiteSystem:555-559  getMedals() = getSetverSettingInfo().achieveMedals`
- 形状：`medals[medalId] = index`，`index` 是墙上的槽位号
  - `SuccessWallMedalWidget:10   local WallMaxNum = 13`
  - `SuccessWallMedalWidget:202  newMedals[targetIndex.medalId] = self._moveMedalData.index`
- 奖章 id 来自 `AchievementMedal.tsv`（17 行，如 `AchievementMedal_Adventure_1..5`）
- `setMedals` 的调用方只有拖拽逻辑自己 -> **medals 完全由服务端下发**

### 43.3 修法
```python
SITE_MEDALS = None              # None = 只发空表 {}（最小改动，仅防崩）
SITE_MEDALS_FILL_ALL = False    # True = 按 AchievementMedal.tsv 的 order 填满前 N 个
SITE_MEDALS_MAX = 13            # 墙上槽位数（WallMaxNum）
```
运行结果（20:19:02）：
```
[空间] achieveMedals 空表（0 项）
```
默认只发空表：墙上不显示奖章，但不再崩。
填满属于玩法偏好，且 17 个奖章 vs 13 个槽位、且要按成就类型挑选，
没有代码依据说明该填哪 13 个，所以不擅自预填；要填把
`SITE_MEDALS_FILL_ALL = True`。

---

## 44. 构建分包：dev / release 两个 profile (2026-10-08 22:20 - 22:45)

用户要求：「内置服务端包体和测试包体分开」。之前**只有一个产物**，
探针（dmAudio / HeroInfoMediator）和将来的内置服务端会混在一起，不适合交付。

### 44.1 切换方式（PowerShell）
```powershell
$env:YQLR_PROFILE='dev'      ; python build_patched_luac.py   # 产物 yqlr_v5_dev.apk
$env:YQLR_PROFILE='release'  ; python build_patched_luac.py   # 产物 yqlr_v5_offline.apk
```
产物：`signed_v5/yqlr_v5-dev-signed.apk`、`signed_v5/yqlr_v5-offline-signed.apk`

### 44.2 设计约定：探针只经由 7 个 helper 落地
```
_gp_probe      patch_guidewidget        -> /sdcard/gp.txt
_rp_probe      patch_redpointcontroller -> /sdcard/rp.txt
_gs_probe      patch_gamestyle          -> /sdcard/rp.txt
_ap_probe      patch_dmaudio            -> /sdcard/rp.txt   （dev-only 文件）
_bu_probe      patch_heroinfomediator   -> /sdcard/rp.txt   （dev-only 文件）
_probe_v       patch_dmviewmediator     -> /sdcard/probe.txt（当前不在 JOBS）
_assist_probe  patch_assistsystem       -> /sdcard/rp.txt
```
所以 release 只需在这 7 个函数入口插空返回，就能去掉**全部**文件 I/O，
不必逐个 patcher 改 —— 改动面最小、回归风险最低。
两个纯探针文件（dmAudio / HeroInfoMediator）**直接不编译不替换**。

### 44.3 两个实现坑
1. **helper 有两种写法**，正则必须都覆盖：
   ```lua
   local function _rp_probe(msg)                  -- 多数
   local _assist_probe = function (_tag, _msg)    -- patch_assistsystem 是匿名函数赋值
   ```
   最初只匹配 `local function X\([^)]*\)`，漏了后者，release 里 AssistSystem 仍在写 rp.txt。
2. **正则不能只匹配到左括号**：早期写成 `local function %s\(`，
   替换后变成 `local function _gp_probe(` + 换行 + `if ...` —— 参数列表被截断，
   直接编译失败（`<name> or '...' expected near 'if'`）。
   正确：`r'(?:local function %s\([^)]*\)|local %s = function\s*\([^)]*\))'`

### 44.4 build 脚本新增的 profile 设施
- `PROFILE` / `IS_DEV` / `PROBE_FNS` / `DEV_ONLY_LOGICS` 常量
- 主流程里 release 先剔除 `DEV_ONLY_LOGICS`（JOBS 14 -> 12）
- 对最终产物源码统一插入 `local YQLR_PROBE = false` + `if not YQLR_PROBE then return end`
- 结尾打印「已关闭 N 处探针 I/O」的清单
- **清理陈旧 `_patched_src` dump**：dev-only 文件在 release 下不编译，
  留着旧 dump 会让「还有哪些探针没关掉」的审计被误导（已经踩过一次）
- `rebuild_v5.py` / `patch_runtime_db.py` 产物名按 profile 化

### 44.5 又踩了一次"db 与 APK 不同步"，这次是文件名
`patch_runtime_db.py` 里本来**硬编码**读 `yqlr_v5.apk`：
```python
apk_path = os.path.join(dirname, 'yqlr_v5.apk')
if os.path.exists(apk_path) and os.path.exists(orig_apk):   # -> profile 化后为 False
    ... 整段"悬空路径自愈"被静默跳过
```
后果：两个 dev-only 文件的 db 行仍指向 dev 构建的内容寻址路径，
发布 APK 里不存在 -> `main.lua:496 module 'yq.assets.GameStyle' not found`。
修法：`apk_path` 改为 `yqlr_v5_{dev|offline}.apk`，找不到再回退原始 APK。
这也是 MEMORY 第 33.2 节记的同一个病的**第二次**复发，根因是
`patch_runtime_db` 以 `adb pull` 的**设备现有 db** 为基址（脚本第 91 行），
device db 会被上一次构建污染。**每次换 profile 必须重跑 patch_runtime_db。**

### 44.6 正确的构建顺序（之前搞反过）
```
1) build_patched_luac.py     编译 + 写 replacements_v5.json / patch_manifest.json
2) rebuild_v5.py             产出 yqlr_v5_<profile>.apk
3) patch_runtime_db.py       以【刚产出的 APK】为参考做校验与悬空自愈，再推设备
4) zipalign + apksigner
```
我长期按 1→3→2 跑，导致 patch_runtime_db 校验的是**上一次**的 APK。
第 3 步必须在第 2 步之后。

### 44.7 内省结论（方案 B 可行性的决定性证据）
在 dmAudio 里临时加了一个模块加载时自省块，结果：
```
socket_members = bind/listen/accept/connect/select/sleep/try/source/sink/udp...
tcp_bind=true  tcp_listen=true  tcp_accept=true
bit=table   jit=LuaJIT 2.1.0-beta3
cjson=nil    string_pack=nil    bit32=nil
```
- **socket 是完整版，bind/listen/accept 都有** -> 内置 Lua 服务端可行
- **`socket.select` 可用** -> 能做非阻塞 accept，绕开"服务端跑在 UI 线程会冻屏"这个最大难点
- `algo=0` 不需要 XXTEA（mock 帧层不做加解密）
- `cjson` / `string.pack` 不是全局：移植时要 `require("cjson")`；
  二进制打包用 `bit` + `string.char` 手写
- 注：`tcp_io=false` 是误报——那是在服务端 socket 上调 send，
  应该用 accept 返回的 client 对象

### 44.8 发布包验证结果（22:32 / 22:45）
```
LUA ERROR: (无)
/sdcard/rp.txt   -> 未创建
/sdcard/gp.txt   -> 未创建
/sdcard/probe.txt-> 未创建
非语音类 db 缺失: 0（仅剩 470 条 voice_cn/voice_en，按需下载包，见第 33.1 节）
```
dev 包同时验证非语音类缺失 0、探针全部启用。
---

## 45. 内置 Lua 服务端：调度、RSA 握手与 RPC 解析（00:00 ~ 00:45）

阶段目标从「只解析不回包」推进到「完成 RSA 握手并进入 data 阶段」。

### 45.1 cocos Scheduler 在本构建里的三种行为（踩了 4 次）
游戏自己的每帧心跳是 `biubiu/schedule/LuaScheduler.lua:137`：

```lua
self.tickEntry = getCCScheduler():scheduleScriptFunc(function (dt) self:tick(dt) end, 0, false)
```

**注册一次、永不重排**，却能持续运行。实测本构建的 `scheduleScriptFunc`：

| 写法 | 结果 |
| --- | --- |
| `scheduleScriptFunc(fn, 0, true)` | 回调一次都不跑 |
| `scheduleScriptFunc(fn, 0.05, true)` | 回调一次都不跑 |
| `scheduleScriptFunc(fn, 0, false)` + 回调内重排 | 原始回调 **27 万~78 万次/秒** |
| `scheduleScriptFunc(fn, 0.05, false)` + 回调内重排 | 约 52k 次/秒 |
| `scheduleScriptFunc(fn, 0, false)`，**只注册一次不重排** | **60 次/秒，正确** |

爆速的原因：cocos 在遍历定时器列表时，我们从回调里 `scheduleScriptFunc` 追加了新条目，
新条目在同一 pass 里就被再次访问（interval=0 时 `elapsed >= interval` 立即成立），
形成自我触发；每次都要付一次 pcall + 新建定时器的代价，把游戏卡在 61%「资源加载中」。

**结论：照抄游戏模式——注册一次，绝不重排。** 修好后 tick 稳定 60 次/秒，游戏能正常走到登录界面。

### 45.2 LuaSocket 非阻塞 recv 会丢数据
`sock:settimeout(0)` 之后 `sock:receive(4096)` 即使有数据，也可能返回
`nil, "timeout", partial`，**数据在 partial 里**。只判断 `data` 非 nil 会把整包丢掉，
表现是「客户端已连接 → 一直没有任何帧日志 → 客户端超时重连」。

正确写法：
```lua
local data, err, partial = sock:receive(4096)
local chunk = data or partial          -- partial 也要用
if chunk and #chunk > 0 then ... end
if err == 'timeout' then return true end   -- 没有新数据不等于断开
```

同理 `send`：非阻塞下 132 字节的握手应答也返回 nil。要先 `settimeout(2)` 再发，
发完 `settimeout(0)`。

### 45.3 握手字节（实测抓包，与 Python mock 完全一致）
```
00 A6 00 01 | 00 A2 | 30 81 9F 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00 03 81 8D 00 30 81 89 02 81 81 00 ...
| len=166  type=1| u16=162| SPKI DER（162 B）
尾部 2 B = 01 01
```
- SPKI = **RSA-1024**，模数 128 B，指数固定 `01 00 01` = 65537。
- **客户端每次连接都重新生成密钥对**（模数每次都不一样）。
- 应答：`type=3`，payload = RSA-PKCS1v15(客户端公钥, `[u16 keylen=16][16B 会话密钥][u8 algo=0]`)。
- 应答后客户端立刻进入 data 阶段并开始发 RPC —— 说明 type 3 已被正确接受。

### 45.4 纯 Lua RSA（16-bit limb + Montgomery CIOS）
`rrcp` C 模块不暴露 RSA，Lua 也没有大整数，因此整套自己写：

- **必须用 16-bit limb，不能用 32-bit**：乘法的中间值会超过 2^53，
  LuaJIT 的 double 会丢精度。16-bit 下中间值 <= 65535*65535+2^17 < 2^33，安全。
- 内存表示：**小端**，即 `limb[1]` 是最低 16 位。
  （一开始写成从 `bytes[1]` 开始取＝大端，而 mont/ge/sub 全按"索引 1 = 最低位"处理，
   两边不一致，全错。）
- `mont_mul` 里 `a`/`b` 是 1-based、`t` 是 0-based，索引要写成 `a[j+1]` / `b[i+1]`，
  否则最高 limb 从不参与运算，结果全错。
- `mont_mul` 结尾的 0-based `res` 必须先转成 1-based 再和 `n` 比较。
- `dbl_mod` 不能"无条件减 n"（x 很小时 2x < n），也不能"carry>0 才减"（借位方向会反）。
  正确做法：算出 nlen+1 个 limb 的 t=2x，减 n，**看有没有借位，有就把 n 加回去**。
- **Lua 的 `^` 是按位异或，不是乘方**。`math.floor(byte / (2 ^ k)) % 2` 取的位全错，
  改用 `POW2 = {1,2,4,8,16,32,64,128}` 查表。
- **Lua 5.1 的数值 for 只向上计数，不会自动反向**。`for k = 7, 0 do` 一次都不执行
  （7 永远到不了 0），于是 modexp 无论 e 是多少都返回 1。必须写成
  `for idx = 0, 7 do local k = 7 - idx ... end`。

自检（`selfTestRsa`）：用 Python `cryptography` 生成固定 1024-bit 测试向量并把 PS 填充定死，
设备上实测 `RSA 自检 PASS`。另外离线端到端验证过：
Python 出密钥和 SPKI → Lua `der_parse_spki` + `rsa_encrypt` → Python 用私钥解密，
明文逐字节一致（`u16 keylen=16`、会话密钥、`algo=0`）。
1024-bit 模式幂在设备上约 0.01 s，UI 线程完全无压力。

DER 解析只需走两跳：`SEQUENCE{ SEQUENCE{oid,NULL}, BIT STRING{ SEQUENCE{ INTEGER n, INTEGER e } } }`，
INTEGER 要剥掉前导 `00`。

### 45.5 RPC 头布局（我一开始读错了，客户端一直重发）
以 Python mock `rrcp_server.py:1259 parse_request` 为准：

```
[0]     kind = 1
[1]     compression
[2:6]   i32 req_id
[6:10]  i32 unknown（实测 0）
[10:14] i32 opcode        <-- 不是 [6:10]
[14:18] u32 body_len      <-- 错读成 opcode 会静默走默认响应
[18:]   body
```

app 信封：`body = [i32 native 前缀][u8 ver][u8 ridlen][rid][cjson][TLV...]`，
即 ver/ridlen 在 body 的第 5/6 个字节，**前面还有 4 字节 native 前缀**。
我漏掉前缀时把 `D3 03 74 00` 当成 ver/ridlen/rid，解出 ver=211、rid="t\t"。

实测首帧：
```
RPC kind=1 comp=1 req_id=1 opcode=10001 body_len=364
数据帧：声明 crc=0x70E55A3E 实算=0x70E55A3E MATCH | plainlen=382 实长=382 MATCH
ver=211? rid=? params={"token":"","rid":"...","baseInfo":{"imei","os","pas","sdkType","channel":"caihong"}}
```
（ver/ridlen 修正后需重新确认，rid 应为 `tester_11`。）

### 45.6 环境踩坑
- **MuMu 快照会回滚 `/data/data/<pkg>`**：虚拟机卡死重启后 `assets.db` 被还原到旧快照，
  表现为 `main.lua:496 module 'yq.assets.GameStyle' not found`
  （即 MEMORY 44.5 那个「db 与 APK 不同步」的老问题）。重新 `patch_runtime_db.py` 即可。
- **`patch_runtime_db.py` 的自愈审计需要 `adb root`**，否则拉取设备 db 时
  `Permission denied` 被吞掉、审计静默跳过。
- 打包/装机流程被打断时不会有任何提示，容易以为「已安装」实际还是旧包。
  改完包务必先看 `/sdcard/osrv.txt` 的时间戳是否与本次签名时间一致。

### 45.7 当前进度与下一步
- 已完成：内置服务端监听 → 接受连接 → 解析握手 → DER 取 n/e → RSA 加密 → 回 type 3
  → 客户端进入 data 阶段 → CRC 校验通过 → 正确读出 opcode/req_id/body_len。
- 未完成：**还没有发任何 RPC 响应**，所以客户端每 2 秒重发 10001。
- 下一步：按 `opcodes_table.json` 把 Python mock 的应答逻辑（含 hero/ladder/resource/site/guide
  等表驱动配置）移植到 Lua，从 10001 开始。
---

## 46. 内置 Lua 服务端：应答层打通，登录成功（09:37 ~ 09:55）

### 46.1 关键设计：构建期物化，不在 Lua 里重实现
`apply_hero_config` / `apply_ladder_config` / `apply_resource_config` /
`apply_site_config` 依赖 9 个 TSV（Character / CharLevel / CharUpRank / CharUpgrade /
CharBeyondUp / Favorability / Item / ShowBackGround / AchievementMedal / Guide）。
把这些逻辑抄进 Lua 必然和 Python mock 分叉，而且改一处配置要改两处。

做法：新增 `build_lua_table.py`，它直接 `import rrcp_server` 并实例化
`Server`（那份已实测跑通登录的实现），跑完所有 `apply_*` 后把结果导出。
**Python mock 是唯一权威实现，改配置只改一处。**

### 46.2 响应体必须在构建期就 json.dumps 成字符串
不能"在 Lua 里 decode -> encode 往返"：表里有 5 处空数组 `[]`
（`reward`、`clubList`、`19002.data.list` 等），cjson 解码成空表再编码会变成 `{}`，
数组悄悄变对象。所以每个 opcode 的响应体在构建期就编码成字符串，
Lua 端一次都不重新编码；唯一要拼的地方（10001 的 guideData）用唯一占位符
`__YQLR_GUIDEDATA__` 做一次 `string.find`/`sub` 替换。

### 46.3 承载格式：Lua 字面量，不是 JSON
第一版把整包塞进 Lua 长字符串再 `require('cjson.safe').decode`，结果**离线自测跑不起来** ——
宿主 luajit 没有 cjson，只有设备上有。既然这里的值本来就全是字符串，
改成 `build_lua_table.py` 直接生成 `lua/opcode_table.lua`（纯 ASCII 的
`OPCODE_TABLE = { ... }` 字面量），构建期内联进 offline_server.lua，**连 cjson 都不需要了**。
注意该文件以 ascii 编码写出，所有字面量必须纯 ASCII（中文注释会直接
`UnicodeEncodeError`）。

### 46.4 响应线格式（与 rrcp_server.Server.build_response 一致）
```
[0]     kind = 2
[1]     comp = 0
[2:6]   i32 req_id
[6:14]  i64 timestamp   (ms)
[14:18] i32 0
[18:20] i16 0
[20:24] u32 body_len
[24:]   body
```
外层再套数据帧 `[u32 BE crc32(rsp)][u32 BE len(rsp)]`，`type = 0`。
时间戳必须平移到 `SERVER_TIME_TARGET = 2024-10-15 12:00:00`（本地时区），
否则客户端用真实的 2026 年会让 SignMonth 失效。

### 46.5 踩到的两个 Lua 作用域/调用坑
1. **`local function` 在定义之前不可见**。应答层代码写在 `on_frame` **之后**，
   `on_frame` 里的 `build_response` 在模块加载时拿到 nil
   （`attempt to call global 'build_response' (a nil value)`）。
   修法：在文件靠前处前置声明 `local build_response, send_data_frame`，
   再用 `function name(...)`（不加 `local`）赋值给它们。
2. **`xpcall(f, handler)` 不给 f 传额外参数**。写成 `xpcall(on_frame, handler)`
   会丢掉 `fr`。必须用闭包 `xpcall(function () return on_frame(fr) end, handler)`。

### 46.6 slog 落盘失败会静默吞掉调试信息
`slog` 原来把 `io.open('/sdcard/osrv.txt')` 包在 pcall 里且不检查返回值，
宿主 luajit 调试时全部日志消失，`load_opcode_table` 返回 false 却看不到原因。
改成写失败时退回 `io.write`，另外 `load_opcode_table` / `init_time_shift`
都导出成 `OfflineServer.*`，可在离线测试里直接调。

### 46.7 离线自测（test_rsp_offline.py）
每次改应答层不必等 4.5 分钟打包：把 `lua/opcode_table.lua` 内联进
offline_server.lua，用 luajit 加载后直接调 `build_response`，校验
24 字节头布局、body 长度、guideData 占位符已替换、body 是合法 JSON、
`default` 兜底正常。实测 10001 = 57090 B，`bag.items` 203 项，
`player.coin = 99999999`，`player.datas` 12 个子表齐全。

### 46.8 成果
设备实测：登录 → 主界面，`99M` 金币/钻石、`9999` 体力，
全部系统入口可见。内置 Lua 服务端已完整替代 Python mock 的登录链路。
观测到的请求序列：`10001 → 10010 → 10037 → 19002 → 35001 → 41001`
（其中 10037 / 35001 表里没有，走 `default` 兜底，日后按需补）。
**还差**：14002 战斗生成（目前只有 C00S01 写死那份）、抽卡 15001。
## 47. 主屏助理切换后语音不变：opcode 10038 缺失（20:05 ~ 20:08）

现象：设置里把主屏助理从 A 换成 B，**画面变了但语音还是 A 的**。

### 47.1 定位链条（每一步都有源码出处，不猜）
1. `HomeCenterWidget:562 getCurScreenHeroInfo()` -> `Player:getScreenHero()`
   （`Player.lua:339-346`）只读 `_mainScreenType` / `_mainScreenHeroId`。
2. 这两个字段**只**在 `BasePlayer:synchronizeInfoDiff` 里被写
   （`BasePlayer.lua:224-230`），调用点是 `DevelopSystem:syncPlayer`（`:93`）。
3. `syncPlayer` 的数据来自 `data.d.player`，来源只有两处：
   `PushSystem`（推送）和 `Service.lua:71-77`（**任何** GS_SUCCESS 应答里
   只要有 `response.d` 就派发 `EVT_SYNCHRONIZE_DIFF`）。
4. 所以：切换动作必须由服务端回一个 `d.player` diff，否则字段不变。
5. 切换动作的 opcode：`HomeCenterWidget:771` -> `CustomDataSystem:ChangeHero`
   （`CustomDataSystem.lua:112-123`）-> `CustomDataService:requestChangeHero`
   -> `opType.changeHero = 10038`（`CustomDataService.lua:2-7`）。
6. **`10038` 不在服务端表里**，走 `default` 空应答 -> diff 缺失。

### 47.2 为什么画面会变而语音不会
画面是三个 tab 回调直接换模型：`SelectPanelWidget` 的
`clickItem` 调 `self._callBackTable[screenType](heroId)`
（`SelectPanelWidget.lua:39-47`），对应
`HomeCenterWidget:754-790` 的 `live2dCallBack` / `spineCallBack` /
`illustrationCallBack` -> `changeLive2d` / `changeSpine` /
`changeIllustration`。这**不经过 Player**。
而语音三处（`HomeCenterWidget:591` / `:611` / `:830`）都读
`getCurScreenHeroInfo()`，走 Player 拿旧 heroId -> 播旧角色。
这就是"模型换了、Player 没换"的分裂。

### 47.3 resourceType 的含义（不是猜的）
`resourceType` = `HomeCenterWidget:718 self._selectHeroType = pageName`，
即 fgui tab 的页名。合法值只有三个（`SelectPanelWidget.lua:10-12`）：
`Por_Spine` / `L2D` / `Illustration`，与 `getScreenHero()` 的
`screenType` 是同一套字符串。

### 47.4 修法
服务端加 10038 分支，回 `d.player = {mainScreenHeroId, mainScreenType}`；
同时 10001 也下发这个值，否则重连会被表内初值（`LaJ` / `Por_Spine`）盖掉。
落盘到 `main_screen_state.json`（照 `guide_state.json` 的写法），
mock 重启不该把玩家选的角色打回初值。

### 47.5 两个防护（都是因为客户端 JSON 会带坏字节）
沿用 15001 的教训：按字节正则抽参数，不依赖整体 `json.loads`。
- `heroId` 不在 `Character.tsv` -> 拒绝并保留上一个有效值。
  脏值（如 `'AnWZ\x01\n'`）绝不能写进玩家数据。
- `resourceType` 不在三个合法值里 -> 沿用当前形态。
- 但**整体 JSON 坏、heroId 本身干净**时必须照样抽出来，
  否则又是"客户端明明换了、服务端按旧值应答"。

### 47.6 版本与验证
`CODE_VERSION` 升到 `r36-mainhero-20261009`。
新增 `E:\Test\Temp\yqlr\_out_rrcp\test_changehero_10038.py`，
13 项断言全过（A->B、10001 带回、只切形态、形态缺失沿用、
非法形态、非法 heroId、JSON 坏但 heroId 干净、脏 heroId 被拒、落盘）。

**踩坑**：`build_response` 返回的是**线上帧 bytes**，不是 dict。
帧布局 `u8 kind | u8 0 | i32 req_id | q ts | i32 0 | h 0 | u32 len | body`
-> 长度字段在偏移 **20**，body 从 **24** 开始（我先按 19/23 算，连错两次；
是直接探测 `wire.find(b'{')` 才定下来的，不要再凭手算）。

## 48. 调试面板：在线改服务端配置（20:22 ~ 20:45）

目标：做一个调试用活动，点进去能改服务端配置，Python mock 和内置 Lua offline 都要能响应。

### 48.1 关键发现：不用自己造面板，opcode 10032 早就有了
游戏自带调试面板 `DebugBox`（`yq/debug/debugBox/`），并且**已经有服务端指令通道**：
- `DebugBoxService.lua:2-5`  `OPCODE_DATA_MODIFICATION = 10032`，
  `requestTest(params)` 发的体是 `{cmd = params}`。
- `DebugBoxMediator.lua:180-221` 把面板上的一条命令组装成
  `{FuncName, 参数1, 参数2, ...}`，然后 `requestTest` 发出去。
- `DebugBoxMediator.lua:122` 命令表来自 `require("...DebugModule")`，
  即 `yq/debug/debugBox/view/DebugModule.lua` 返回的 `modules` 表。
- 命令项 `{FuncName, FuncDesc, param}`：不填 `isLocal` = 走服务端；
  `param` 的每个名字在面板上是一个输入框，点"真"把文本原样发出。
- 应答里的 `d.player` 会走 `Service.lua:71-77` 自动同步回客户端，
  所以服务端改完直接回一整份新 player 就能看到效果。

### 48.2 服务端：这些开关本来就是 Server 的类属性
`apply_hero_config` / `apply_resource_config` / `apply_ladder_config` 里读的是
`Server.HERO_MAX_STAR` 这类**类属性**。所以运行时 `setattr` 就够，
**不用改 apply_*() 里的任何一行**，改完重跑对应的 `apply_*()` 重新生成
`table['10001']` 即可。白名单 `Server.DEBUG_TOGGLES` 共 19 项（角色/资源/天梯）。

**刻意不开放**（改了会把客户端打崩，理由在各自 apply_*() 的注释里）：
`HERO_PERSONALITY_MAP`（HeroInfoMediator:1478 等 7 处无保护读取，必须 True）、
`HERO_PERSONALITY_KEYS`/`HERO_RESOURCE_KEYS`（结构键）、
`HERO_KEEP_EXISTING`（内部实现）、`RESOURCE_PAGES`/`RESOURCE_EXCLUDE_TYPES`、
`LADDER_TYPES`/`LADDER_REWARD_TSV`。

落盘到 `debug_config.json`，**必须在 `load_table()` 之后、所有 `apply_*()` 之前**载入，
否则读的还是默认值。默认值快照 `DEFAULTS` 取自模块末尾（类定义跑完后立刻取，
再往后就被 `load_debug_config()` 覆盖了）。

### 48.3 调试活动为什么要"注入配置行"，光下发 ActivityData 不够
`ActivityList:syncAloneActivity`（`:27-42`）拿 id 去
`ConfigReader:getRecordById("Activity", id)` 查配置行，**查不到整条活动被静默丢弃**
（`if config then` 的 else 分支什么都不做）。
所以要两边配套：
1. 服务端在 `datas.ActivityData` 下发 `Activity_Debug_Config`
   （`apply_debug_activity`，字段含义对齐 `BaseActivity:synchronize:40-67`）。
2. 客户端在 `syncAloneActivity` 里调 `ensureDebugActivityConfig()`，
   往 ConfigReader 的 Activity 表塞一行。
   - `ConfigReader._Tables` 就是普通 Lua 表（`ConfigReader.lua:125`
     `return dataTable and dataTable[id]`），可以安全写。
   - 注入点选在 `ActivityList` 而不是 `ConfigReader`：前者已在补丁清单里，
     不需要新增资源条目；后者是全局热点，不去碰。
   - `Type = "Meaningless"` 走 `MeaninglessModel`，它只是 BaseActivity 的空壳
     （全文 9 行，只有 initialize/synchronize），不会去读一堆没下发的子表。
   - `Link = "view://debugBoxView"` -> `ActivityMediator:104` 的
     `enterViewByUrl(cfg.Link)`。`DebugBoxView`/`DebugBoxMediator` 在
     `modules.lua:192-193` 已注册。
   - `YQLR_DEBUG_ACTIVITY=0` 可关。

### 48.4 新增补丁资源：DebugModule.luac
`DebugModule` 原本不在补丁清单里，需要自己算 tagpath。**推导规则**：
    tagpath = assets/release/<md5[0:2]>/<md5[2:4]>/<md5[4:]>.luac
md5 取 **decrypted_all 里的原始 .luac**。本次：
    DebugModule.luac md5 = 86508af6...  ->  assets/release/86/50/8af682...luac
（已在 APK `yqlr_v5_dev.apk` 的 zip 条目里核对存在。）
**注意** `patch_manifest.json` 里的 `md5` 字段是**另一回事**，不是这个 hash。

### 48.5 踩坑：往表字面量里插 = 语法错误
第一版往 `local modules = {` 后面插新组，漏了组前和与原第一组之间的逗号，
产出 `{ , {...} {...} }` —— luajit 编译**居然没报错**，但表结构是错的。
改成 `table.insert(modules, {...})` 追加到 `return modules` 之前才干净。
**教训**：这类拼接一律用 `table.insert`，别手补逗号；改完必须
`luajit -e "loadfile(...)"` 单独验一次语法，不能只看构建脚本报没报错。

### 48.6 Lua 侧的硬约束（所以 10032 在 offline 是拒绝而不是半实现）
offline 的应答体是**构建期 json.dumps 好的字符串**（MEMORY 46.2：Lua 侧一次都
不能重新编码，cjson 往返会把 5 处空数组 `[]` 变成 `{}`）。
- 能改的只有**标量字段**，用占位符 + `gsub` 是安全的。
- 改不了的：`LADDER_ORDER`（要重算整棵 typeData）、
  `HERO_MAX_STAR`（要**删** `"starId":"xxx_N"` 字段）。
- 真要支持就得把 `apply_*()` 连同 TSV 读取整个移植到 Lua。
所以 offline 的 10032 返回 `resCode:1` + 明确说明，**好过静默走 default
空应答让人以为改了**。

offline 侧已经补上的：`10038`（同 47 的 diff 机制）+ `mainScreenHeroId`/
`mainScreenType` 两个占位符（`__YQLR_MAINHERO__` / `__YQLR_MAINTYPE__`），
状态与 Python 共用 `/sdcard/main_screen_state.json`，两种服务端之间切换不丢选择。

### 48.7 踩坑：Lua 的 string.find 不给捕获组
`string.find(s, '"heroId"%s*:%s*"([^"]*)"')` 返回的是**整个匹配**的起止位置，
`string.sub(raw, a+1, b)` 会把 `"heroId":` 一起截进去 —— 实测抽出过
`'heroId":"BaiJ'` 这种脏值，还被写进了玩家数据。**必须用 `string.match`**。
Python 侧的正则 `re.search(...).group(1)` 没这个问题。

### 48.8 版本与验证
`CODE_VERSION` -> `r37-debugcfg-20261009`。
- `test_debugcfg_10032.py`（新建）36 项断言全过：cmd 解析、关/开满星后
  `d.player` 真的变、资源数量、满好感、天梯、非白名单被拒且不污染类属性、
  int 收到 `abc` 被拒且不写坏配置、`int` 开关的 0 归一成 None、
  参数不足、`addHero` 明确报未实现、落盘、重启载入、陌生键不崩、reset。
- `test_rsp_offline.py` 加了 10038 / 10001 带回 / 非法形态沿用 / 10032 拒绝，
  luajit 实跑通过，占位符无残留。
- 两边白名单一致性：`gcheck` 脚本比对 `Server.DEBUG_TOGGLES` 与
  `build_patched_luac.py` 的 `DEBUG_TOGGLES`，19/19 完全一致（含类型）。
- dev 包已签名安装（20:37）。**设备实测待做**。

## 49. 排查"连不上服务端"：adb reverse 会自己丢（20:47）

现象：客户端突然连不上服务端，但 8888 上 mock 进程活着、logcat 里也没有网络错误。

**第一步就查 `adb reverse --list`** —— 这次是**空的**。模拟器/设备重连后
adb 的 reverse 映射会被清掉，而客户端连的是 `127.0.0.1:8888`（设备自己的
localhost，靠 reverse 转到宿主），映射没了就必然连不上。
重建即可：
    adb -s 127.0.0.1:5555 reverse tcp:8888 tcp:8888

**判断依据**（下次直接照这个顺序查）：
1. 宿主 `Get-NetTCPConnection -LocalPort 8888 -State Listen` -> 有监听？
2. `adb reverse --list` -> **空就是它**（最常见，且最容易被忽略，
   因为 mock 进程明明活着、日志明明有历史记录）。
3. mock 日志末尾有没有**新的** REQ 行 -> 没有新行 = 请求根本没到宿主，
   问题在连接层而不是协议层；有新行但没 RESP = 服务端处理的问题。
4. logcat 筛 `cocos2d-x debug info` -> 只有 `[CSM] [W]RotationDeformer`
   这类是 L2D 动画的正常噪声，不是错误。

**注意**：每次重启模拟器、重新 `adb devices` 之后都要补一遍 reverse，
建议把它并进固定的启动检查步骤。

## 50. 「限时活动」弹窗：从白板到可用（21:00 ~ 22:02）

三个独立问题叠在一起，逐个拆的。**教训：每层都有独立的判据，
不能只看上一层「我以为已经生效了」。**

### 50.1 第一层：入口是我们自己禁用的
主页右上角第一个图标（秒表样式）= `HomeCenterWidget:KRightListData[1]`：
`btnType = "Banner"`, `funcCallback = "bannerCallback"`, `icon = "main_icon_09"`。
上一轮为了绕开「空白弹窗」，`patch_homecenterwidget` 把
`bannerCallback` / `showActivityList` 都改成 `if true then return end`，
所以点它**毫无反应、也不发任何包**。
已把 `YQLR_NO_ACT_POPUP` 默认值从 1 改成 0（入口默认保留）。

### 50.2 第二层：白板的真因是「两个条件同时不满足」
弹窗内容由 `ActivityMediator:145-156` -> `BannerSystem:41-59` 决定：
    1. activity:getIsTodayOpen() == 1   <- BaseActivity:53 读 data.status
    2. activityCfg.Icon ~= "" 且 Icon[1].ListRes 非空
原来表里那 3 个活动（Activity_MainLineFund / Activity_TowerFund /
Activity_Deposit）**都没带 status** -> `getIsTodayOpen()` 恒为
`STATUS_INIT(0)`，一个都进不了 banner 列表 -> 白板。
新增 `apply_banner_activity()`，下发 3 个 Activity.tsv 里**真实存在**的
Limit 类活动（Activity_CharUpgrade / Activity_PVP / Activity_StarField1），
status=1 + ListRes 非空。选它们是因为 LimitActivityMode 只是 BaseActivity
的空壳（21 行），且 Config 指向的 ActivityConfig 行都存在
（`BaseActivity:_getActivityConfig:157` 对缺失 configId 是 assert）。

### 50.3 第三层：**ActivityData 必须嵌套一层 activities**
这是排查最久的一个。服务端日志明明显示数据已下发、status=1 也对，
客户端就是一条活动都没有。
`DevelopSystem.lua:262-263` 要的是：
    if otherDatas and otherDatas.ActivityData
       and otherDatas.ActivityData.activities then
     self:getActivityList():synchronize(otherDatas.ActivityData.activities)
我下发成了**扁平**的 `ActivityData: {活动id: {...}}`，
`and ....activities` 直接短路 -> `synchronize` 一次都没被调用
-> status 读不到 -> getIsTodayOpen() 恒 0 -> banner 列表恒空。
**`opcodes_table.json` 里 `datas.ActivityData` 那条注释早就写明了
`.activities` 形状，是我没核对就按扁平写了。**
连带把原来顶层那 3 个占位活动搬进了 `activities`（否则顶层残留同 id 副本）。

### 50.4 第四层：写 ConfigReader 没用，必须写 DataReader 的缓存
调试活动的配置行 `Activity_Debug_Config` 不在 Activity.tsv 里，
`syncAloneActivity` 查不到就静默丢弃（`if config then` 的 else 什么都不做）。
想运行时注入，但踩了两轮：
    ConfigReader.lua:14   isUseDBReader = true
    => ConfigReader:getRecordById / getDataTable 全部转发给 DataReader
    DataReader:getDataTable(:138-152) 每次调用都**新建一个 temp 表**
       （还要过 `if value ~= false` 过滤），返回的是**临时副本**
    => 往它的返回值里写 tbl[id] = {...}，下次读拿到的是另一个副本，写入丢失
正解：直接写 `DataReader._cacheDataTable["Activity"][id]`。
`DataReader` 是**全局表**（DataReader.lua:1-17），不是 injector 实例。
（`_getRecordById:110-112` 查不到时还会把 false 写进缓存，一并要注意。）

### 50.5 第五层：调试活动点了会崩（UrlEntry 路由）
点调试活动 -> `UrlEntry.lua:343: attempt to index a nil value`。
链路：ActivityMediator:103-110 -> UnlockSystem:294 enterViewByUrl ->
:284 openViewEventByUrl -> EVT_OPENURL ->
biubiu/legs/core/command/OpenUrlCommand:4-25 ->
`UrlEntryManage.resolveUrlWithUserData`
该函数查找有两级（:304-313）：
    1. `mapping = getURLMappingEntries()`  -- **可写的普通 Lua 表**
    2. mapping[page] 为空才 fallback 到 `kExtResponseMap[viewName].entry`
debugBoxView 两边都没有，:310 直接索引 nil。
讽刺的是 :313 的 assert 和 OpenUrlCommand:9-16 的「功能未开放」提示
**本来就是干净的兜底**，但崩在它们前面，永远到不了。
正解：往第 1 级表加一条（`patch_urlentry`），DebugBoxView 在
modules.lua:192-193 已注册，只差这条路由。

### 50.6 Icon 也不能留空
一开始注入的配置行写了 `Icon = ""`，结果活动出现了但**弹窗里看不到它** ——
这个弹窗是**唯一**的活动列表，不存在另一条不依赖 Icon 的显示路径。
`ActivityMediator:100` 用 `icon:setURL(kBannerIcon .. cfg.icon[1].ListRes .. ".png")`，
`kBannerIcon = "asset/lang_banner/"`（GameTypesCfg.lua:898）。
复用 `main_show_19_m`，已确认
`asset/lang_banner/main_show_19_m.png` 在 decrypted_all 里真实存在
（**复用前务必核对文件真的在，别靠猜**）。

### 50.7 新增补丁资源的 tagpath 推导
新加 `yq/gameplay/base/UrlEntry.luac` 时按 48.4 的规则算：
    tagpath = assets/release/<md5[0:2]>/<md5[2:4]>/<md5[4:]>.luac
md5 取 `_out_conf/decrypted_all` 下的原始 .luac（本次 7544/3109cc35...）。
**注意逻辑名 ≠ 目录名**：modules.lua 里注册的是
`yq.gameplay.base.UrlEntry`，而目录是 `yq/gameplay/base/`（不是 `yq/base/`）。
找不到反编译工具时，`_out_decompile/samples/net_UrlEntry.lua` 有现成源码可用。

### 50.8 ⚠️ 部署顺序（有硬依赖，踩了两次）
`install -r` 会把 `files/assets.db` **覆盖回 APK 内的 4 MB 原始版**，
而 `patch_runtime_db.py` 生成的是 **7.98 MB 运行时库**
（`dmAudio` 等只存在于运行时库里）。不重推就会报
`module 'yq.assets.dmAudio' not found`，客户端起不来。
另外 `adb root` / `adb unroot` 都会**重启 adbd 并清掉 reverse 映射**。
所以正确顺序固定为：
    build_patched_luac -> rebuild_v5 -> zipalign -> apksigner
    -> install -r -d
    -> adb root -> patch_runtime_db.py -> adb unroot   # 必须在 install 之后
    -> adb reverse tcp:8888 tcp:8888                   # 必须在 root 之后
    -> 重启 mock -> 启动客户端
**已把这套固化成 `D:\Temp\yqlr\_out_repack\deploy_dev.ps1`（7 步，含校验），
以后直接跑它，不要手工一步步来。**
（脚本必须是纯 ASCII：PS 5.1 按 ANSI 读 UTF-8 无 BOM 文件，中文会变乱码
并导致语法错误。）

### 50.9 自测的教训
`test_banner_activity.py` 最初只断言「数据已下发、status=1、ListRes 非空」，
**全是服务端视角**，所以 50.3 那个层级错误它一条都测不出来。
现在第一件事就是断言 `ActivityData.activities` 这层存在（层级错了后面
断言全无意义），外加一条「防再次摊平」的对照断言。
**凡是「客户端会不会读」的判据，都要写进自测，不能只测自己下发了什么。**
探针（`[ACT]` 写 /sdcard/rp.txt）这次帮了大忙：它一行就证明
`syncAloneActivity` 到底被调用没有、status 和 ListRes 读到了没有。

## 51. Debug GUI 重构：挂进游戏设置页（11:20 ~ 12:12）

需求是"重写一份**与游戏一致**的 Debug GUI"。第一版做错了方向，纠正记录在此。

### 51.1 走错的方向：复用 DebugBox 面板
最初把 19 个开关塞进游戏自带的调试面板 `DebugBox`（`ui://DeBugBox/BoxView`），
用它的 `type="params"` 分支（`DebugBoxMediator.lua:154-176`）渲染成下拉。
功能没问题，但外观不对 —— 渲染出来是蓝底 + 白色默认色块。
**证据**：`What's your dream?` 就是 `DeBugBox.fui` 里的原文标题（实测该字符串
在文件里），整个包 7275 B、**不引用任何图集** —— 它本来就是游戏自带的
**无美术开发面板**，不是渲染失败。
教训：看到"无样式"先分辨是"组件没取到"还是"本来就长这样"，
别急着往加载失败方向查（我为此白查了一轮 fgui/UrlEntry/DataReader）。

### 51.2 正确方向：一行 UI 代码都不写，复用设置页渲染链
游戏真正的设置页是 `ui://Site/SiteMainView`（`SiteMainMediator`），
其中"游戏设置"那层的渲染器是 `SiteGamePageWidget`：
- `getSiteGameData()`（:61-251）是**纯数据函数**，返回一组设置项描述
- `initSiteList()`（:253-357）是它的通用渲染器，已完整处理三种行：
    type="list"      下拉（:292-322）setItemRenderer/ClickItem -> selectCb
    type="slider"    滑条（:324-344）
    type="voiceList" 自定义 widget（:346-351）
  每行还有 `obj:getController("mode"):setSelectedPage(nodeType)`（:282-284）
  和 `obj:setTitle(Strings:get(config.title or config.name))`（:285）

所以只要在 `return GameSiteConfig`（:250）前把我们的行 table.insert 进去，
**外观/排版/点击音效/红点/选中态全部天然一致** —— 用的就是同一套渲染代码
和同一个 fgui 组件。新增 `patch_sitegamepagewidget` 就是干这一件事。
调试活动入口的 Link 也随之改成
`view://siteMainView&viewType=push&type=siteGame`
（`FunctionUnlock.tsv` 里 `Setting_System` 用的就是这个值）。

行数据形状（对齐 :64-88 的 gameSiteAni）：
    { name=, type="list", index=, title=, enable=true, values={...},
      selectCb=function(index) ... end,   -- 玩家改动
      initFunc =function(userSite) ... end }  -- 当前值，返回下标

### 51.3 新增补丁目标：SiteGamePageWidget.luac
tagpath 按 48.4 的规则算（md5 取 `_out_conf/decrypted_all` 下原始 .luac）：
    yq/gameplay/site/view/SiteGamePageWidget.luac
    md5 = 19424521a05635353cc60752e027
    tagpath = assets/release/19/15/19424521a05635353cc60752e027.luac
（已在 APK zip 条目里核对存在。反编译源码本来就有，14538 B。）

### 51.4 踩坑：`table.unpack` 在本工程不存在
写法 `table.insert(GameSiteConfig, table.unpack(self:getYqlrServerCfg()))`
直接报：
    SiteGamePageWidget.lua:603: attempt to call 'unpack' (a nil value)
**宿主是 LuaJIT 2.1（Lua 5.1）**，没有 `table.unpack` / `table.pack` /
位运算这些 5.2+ 扩展，只有全局 `unpack`。
**luajit loadfile 的语法检查抓不到这个** —— 它是运行时才炸的。
改成逐条 `table.insert` 循环。

### 51.5 踩坑（更重要）：反编译器的还原错误会被固化进产物
`initSiteList` 里那行反编译产物是：
    initVal = (type(initFunc) ~= "function" or initFunc(userSite)) and (initFunc or 0)
**这是错的还原**。Lua 里 `0` 是**真值**，所以只要 `initFunc(userSite)` 返回
任何数字（原表返回 0/1/2 全在此列），`X and (initFunc or 0)` 就取到
**函数本身**，随后 `list:setSelectedIndex(函数)` 报
    "invalid arguments in function '..._GList_setSelectedIndex'"
原字节码的语义显然是"是函数就调它，否则用配置默认值"。
**注意：这不是我们加的配置项引起的** —— 游戏原有那 20 多个设置项同样会崩；
是"反编译源码 → 重新编译成 luac"这个动作把反编译器自己的错误固化了。
改成无歧义的 if/else。
**教训**：凡是会被重新编译的文件，都要留一条"这份源码能不能自洽跑起来"的
验证路径。语法通过 != 语义正确，`and/or` 这类表达式最容易中招。

### 51.6 踩坑：没有全局 `getInstance`，BaseWidget 也没有 getInjector
写 `_YQLR_CFG_SET` 时用 `getInstance("DebugBoxService")`，报
    SiteGamePageWidget.lua:119: attempt to call global 'getInstance' (a nil value)
- 全局 `getInstance` 在本工程**不存在**
- `BaseWidget` 只有 getView / getChildView / setVisible / dispatchEvent /
  autoManageObject 等十几个方法，**没有 getInjector**
正解是类头注入，和该文件里其它 6 个注入（`_siteSystem` / `_heroSystem` / ...）
同一套：
    SiteGamePageWidget:has("_dbgSvc", { is = "r" }):injectWith("DebugBoxService")
类定义锚点是 `class("SiteGamePageWidget", BaseWidget)`（**没有 `, _M`**，
写锚点时别照抄别的文件的写法）。

### 51.7 `Strings:get` 查不到会原样返回 id
`Strings.lua:53-58`：`find(id)` 返回 nil 时 `get` 直接 `return id`。
所以配置项的 title 和下拉项用中文原文即可，**不需要往 Text 表加文案**。
（对照：`initSiteList:285` 和 `:305` 都会走 `Strings:get`。）

### 51.8 已知限制：服务端只有写、没有读
opcode 10032 只实现了 `debugConfig <名> <值>` 和 `debugConfigReset`，
**没有查询接口**。所以面板显示的当前值是本地缓存
（`GameConfigs.DebugCfgValues`，bool 的初值表 `_BOOL_DEFAULT` 必须和
`rrcp_server.py` 里类属性的初值一致，否则显示与服务端实际状态不符）。
代价：**重启 mock 后面板显示是陈旧值**，需要手动切一次。
后续可加一个 `debugConfigQuery` 读接口解决。


## 52. 主线战斗 / 天梯「资源勘探」全链路（r39 ~ r59，12:40 ~ 15:45）

这一段全是"客户端因为服务端少给了某个字段而崩/锁死"的连锁坑。共同教训：
**报错行号和反编译源码行号对不上时，先在反编译源码里找同名函数**，
不要照着 luac:NNN 硬找。

### 52.1 战斗数据缺 `body` -> 召唤必崩（r58）
- 现象：`cannot summon id:DuoLNN_Summoned1`
- 召唤数据不是服务端直接给的，是客户端**现算**的：
  `BattleDataParser:288 fillOtherHeroData(heroData.body, otherData)`
  -> `:292-320` 拿每个 id 去 `getBattleRecordById("Enemy", unitId)` 查配置
  -> 组出单位数据存进 `others`；之后 `special_ops:9-11` 走
  `copySummonData`（`BattlePlayer:72-76` = `self._others[id]`）
- 我们不下发 `body` -> `heroData.body` 是 nil -> `:293` 的
  `if type(unitIds) == "table"` 不成立 -> `others` 恒空 -> assert 崩。
- 修法：`_hero_base()` 加 `body` 参数，取配置表 `ChangeBody` 列
  （Character.tsv / Enemy.tsv 都有）。`DuoLNN_Summoned1/2` 确实是
  Enemy 表的 rowId，所以客户端查得到。**顺带修掉主线 203 关里 45 关的同类隐患。**
- 坑：`ChangeBody`（表）-> `body`（下发）-> `others`（客户端算）-> `copySummonData`
  四层，别只改一层。

### 52.2 `checkMaps` 空表 -> 入口永久灰着（r53/r54）
- 「资源勘探」= `ChapterMapMediator:338-346 openStaris`：
  `if #self._ladderSystem:getCheckMaps() == 0 then 弹"未开放"; return end`
- 取值链 `LadderSystem:231 -> LadderModel:136-138 return self._checkDataMaps`，
  而 `_checkDataMaps` 只在 `LadderModel:synchronize:90-111` 填，来源是
  **`StairsBattleData.checkMaps`**。我们一直在发 `{}` -> 入口永远锁死。
- 形状必须严格对上（否则崩在 `cond`）：
  ```lua
  local cond = v.openCondition
  if cond.currentValue == cond.targetValue then
      local cfg = ConfigReader:getRecordById("CampaignChapter", v.id)
      if cfg.Type == "Stairs" then data[cfg.Order] = {...} end
  ```
  即每项要 `{id=<CampaignChapter 的 Stairs 章 rowId>, openCondition={currentValue,targetValue}}`。
  我们按 `CampaignChapter.tsv` 里 `Type=="Stairs"` 的 24 条（T01~T24）生成。

### 52.3 【重要】Lua 的比较报错方向别搞反（r55 -> r56）
我第一次看到 `attempt to compare string with number` 就断定"配置表 Order 是字符串"，
把 `order` 改成字符串，结果方向反了，变成 `compare number with string`。
- Lua 的 `__lt` 报错格式是 `"%s with %s" % (type(a), type(b))`，**a 是左值**。
- 决定性证据不是那次报错，而是 `LadderModel:initConfigData:52-55`
  在**初始化阶段**就做 `self._T04LastOrder < v`（v 来自 `config.Order`）。
  游戏能正常启动 => `StairsBattle.Order` 是**数字**。
- **教训：判断"某个配置字段是什么类型"要找一条在客户端启动路径上、
  一定会执行到的比较，而不是靠一次线上报错的方向猜。**

### 52.4 r54 的报错根本不在你以为的那一行
`MainBattleViewSystem:88 if data.Order <= order` 两侧都是数字，不可能报类型错。
真凶是 `:86-107`：
```lua
local progress = ""                       -- 字符串初值
if data.Order <= order then progress = #stairsData          -- 数字
else for k,v in pairs(stairsData) do
        if order + 1 == v.Order then progress = k-1; break end -- 数字
     end end
     -- 循环一次没匹配上，progress 还是 ""
...
elseif progress < #stairsData then   -- :107  "" < 数字 -> 崩
```
`order=1` 时章节末层（最大 880）> 1，走 else 分支去找 `Order==2` 的行，找不到就漏成 `""`。
**这条路径以前从没执行过** —— `checkMaps` 为空时 `:77` 就短路了。解锁入口才暴露。
修法：`LADDER_ORDER` 从 1 抬到 9999（> 任何章节层数），第一分支恒成立。

### 52.5 天梯战斗 21001 / 结算 21002（r57/r59）
- `LadderService:2-8` 给出天梯 opcode 表：`21001` LADDER_FIGHT_STAR、
  `21002` LADDER_FIGHT_END、`21003` 挂机英雄、`21004` 自动、`21005` 扫荡。
- 21001 的 `data` 必须是一份完整战斗数据：
  `LadderSystem:1096-1097` 直接 `data.campaignId or data.id` /
  `data.gridBattleId or self:getGridBattleID(campaignId)`，
  id 为 nil 就 `assert(battleData, "battleData:"..id)` 崩（报错就是 `battleData:nil`）。
- 21002 请求体是空的，胜负**完全由我们回什么决定**：
  `LadderSystem:948-989` 只看 `responseData.pass`，
  缺字段就进 `battleFailedView`（打赢被判失败）。
  注意 `withdraw=true` 会让 `:950` 直接 return、连结算页都不出。

### 52.6 14002 请求体不是纯 JSON，且**字段顺序不固定**
- `json.loads` 直接失败（`Invalid control character`）：引号内混着类型标记字节，
  如 `b'"LaJ\x01"\x18y":2,...'` —— 值里带标记（闭引号在 `\x01` 之后）、
  键名带前缀（`"\x18y"` 闭引号在 `y` 之前）。
- 更坑的是**字段顺序会变**（Lua 表遍历序）：实测见过
  `{"campaignId":...,"battleData":{...}}` 和 `{"battleData":{...},"campaignId":...}`。
  所以**不能靠 `'"teams":{'` 定位** —— 那样匹配失败会静默退回默认编队，
  玩家看到的就是"又变回两个默认的了"。改成全 body 扫"引号紧跟的 ASCII 串" +
  `owned` 集合校验 + 键名黑名单。
- **日志必须打完整 body**（之前只打 120 字节，`heroId` 那些字段正好被截掉）。
- 第 2 个以后的队员是紧凑打包的，解不出来；**解出几个用几个，不足时用服务端编队补齐**，
  绝不能让玩家只上场 1 人。

### 52.7 客户端**不发** 29001
编队界面保存走 `TeamMediator:saveEditCallBack:214-221` ->
`TeamsService:requestSetTeams` -> `newRequest(29001, params)`，
但**多关卡日志里 21002/14003 都出现了，29001 一次都没有**。
玩家选的队只出现在 **14002 请求体**里。所以编队持久化的正确做法是
**从 14002 请求解出来后写回 `team_state.json`**，别指望 29001。

### 52.8 「岩-233」是星球名不是关卡号
`Text.tsv` 的 `ChapName_*`：C00/C01/C10 = 星球：岩-233，C02 = 炽-237，
C03/C06/C13/C14 = 蚀-286 ...。编队人数上限按星球查表，不硬编码关卡号。

---

## 53. 同步到内置 Lua + 构建 RL（release）版（15:24 ~ 15:45）

### 53.1 两棵目录树分工不同（别搞混）
- `E:\Test\Temp\yqlr\_out_rrcp`  = **Python mock 服务端**（rrcp_server.py 等）
- `D:\Temp\yqlr\_out_repack`      = **打包树**（build_patched_luac.py / lua/ / *.ps1）
- `build_lua_table.py` 里 `sys.path.insert(0, r'E:\Test\Temp\yqlr\_out_rrcp')`
  再 `import rrcp_server` —— 跨树引用是**设计如此**，不是笔误。
- 完整反编译在 E 盘；`D:\Temp\yqlr\_out_decompile` 只有被补丁过的那十几个文件。

### 53.2 同步三步
```powershell
cd D:\Temp\yqlr\_out_repack
python build_lua_table.py     # 物化 opcode 应答表 -> lua/opcode_table.lua
# 改了 offline_server.lua 的话再跑一次回归：
python test_rsp_offline.py
```
- `opcode_table.lua` 从 72.7 KB 涨到 **160.0 KB**（10001 从 65104 涨到 66465 B：
  ExploreData / EquipData / PrismCoreData / checkMaps 都是这轮加的）。
- opcode 从 13 个涨到 **18 个**：新增 `21001` / `21002` / `21005` / `29001`。
  这几个在 Python 侧是 `build_response` 里分支算的、不在 `opcodes_table.json`，
  所以要在 `build_lua_table.py` 里**单独物化**（见该文件 180-235 行）。

### 53.3 emit_lua 是白名单式输出 —— 加字段必须同步改它
`payload` 字典加了 `ladderPlaceholder` 之类，`emit_lua()` 不会自动输出，
必须显式 `lines.append(...)`。踩过：占位符没进 Lua 表，替换静默不生效。

### 53.4 21001/21005 在 Lua 侧要做占位符替换
构建期物化的是**一份模板**战斗（T24S40），关卡号是占位符：

```python
LADDER_PLACEHOLDER = '__YQLR_LADDER_ID__'
LADDER_GRID_PH      = '__YQLR_LADDER_GRID__'
```
Lua 侧按请求体里的 `T%d%d[SMX]%d%d` 抠出真实 id 再 gsub，
`gridBattleId` 要拼成 `TOWER_<rowId>`（实测 T24S40 -> TOWER_T24S40）。
**和 10001 的 guideData / 主屏助理是同一套占位符机制**（MEMORY 46.2：
应答体是构建期预编码字符串，Lua 侧不能 decode->encode，cjson 会把 `[]` 变成 `{}`）。

### 53.5 release profile 原本**根本不注入**内置服务端
`build_patched_luac.py` 里是 `if IS_DEV and os.environ.get('YQLR_OSRV','1')=='1':`，
注释写着 "dev profile only for now; enable on release once RSA + responses land"。
现在应答层补齐并过了 `test_rsp_offline.py`，已改成只看 `YQLR_OSRV`，
两个 profile 都能内嵌。

### 53.6 RL 版构建命令
```powershell
$env:YQLR_PROFILE = 'release'      # 或 dev
$env:YQLR_OSRV    = '1'
cd D:\Temp\yqlr\_out_repack
python build_patched_luac.py       # -> replacements_v5.json / patch_manifest.json
python rebuild_v5.py               # -> yqlr_v5_offline.apk
& 'E:\lib\android-sdk\build-tools\35.0.0\zipalign.exe' -p -f 4 yqlr_v5_offline.apk yqlr_v5-offline-unsigned.apk
& 'E:\lib\android-sdk\build-tools\35.0.0\apksigner.bat' sign `
    --ks 'C:\Users\Administrator\.android\debug.keystore' `
    --ks-key-alias androiddebugkey --ks-pass pass:android --key-pass pass:android `
    --out signed_v5\yqlr_v5-offline-signed.apk yqlr_v5-offline-unsigned.apk
```
产物：`signed_v5\yqlr_v5-offline-signed.apk`（1720978015 B）。
`rebuild_v5.py` 的后缀映射是 `{"dev":"dev","release":"offline"}`，
但文件名用**下划线**（`yqlr_v5_offline.apk`），签名产物用**连字符**，别找错。

### 53.7 【坑】不能用字符串搜索校验 APK 里有没有注入
`replacements_v5.json` 里存的是 **XXTEA 加密后**的字节
（`build_patched_luac.py:2989 ct = A.encrypt_blob(bc, b7, b8, tbl=TBL)`），
所以 `b'OfflineServer' in data` **永远是 False**，会误判成"没注入"。
- 要按内容校验，先走 `A.decrypt_blob(raw, tbl=TBL)`。
- 或者直接编译 `_patched_src\yq__base__Service.luac.lua` 再搜（未加密）。
- 字节码大小也别当判据：注入后 176 KB = 40 KB 代码 + 136 KB 应答表，数值对得上，
  但和原包条目大小接近，容易看成"没变"。
- 构建管线自带 `往返 PASS` 和 `magic=1b 4c 4a 02` 校验，优先信这两个。

---

## 54. 2026-10-10 把内置 Lua 服务端补到与 Python 全同步

起因：审计发现两边 opcode 数量几乎一样（20 vs 19），但**行为差得很远**。

### 54.1 【方法论】判断两个服务端是否同步，要对拍，不能数 opcode
早期两边都是 19 个 opcode，看着"全同步"，实际上：
- Lua 的 `14002` 只有一份 C00S01 的应答 → 第二关起敌人/站位全是第一关的
- Lua 的 `14003` 是静态应答、无 `d.player` → 主线进度永远不推进
- Lua 的 `21001/21005` 是一份 T24S40 模板 → 每关敌人都是那五个

根因：`opcodes` 里那份 14002 是构建期跑 Python 逻辑跑出来的**某一个** stage，
不是"按请求参数生成"。
→ 新增 `D:\Temp\yqlr\_out_repack\test_lua_parity.py`：同一批请求同时喂给两边逐字段比。
现况 **52 项全部一致**。

### 54.2 【方案】按关卡预编码整份应答，而不是占位符
占位符只能换字符串字段，换不了整个 `data`（敌人/站位/技能逐关不同）。
实测 203 关主线 + 1686 关天梯合计 4.71 MB，生成耗时约 195 s。
相对 1.7 GB 的 APK 完全可忽略，所以直接全量物化：

| 表 | 条数 | 键 | 用途 |
|---|---|---|---|
| `battles` | 1889 | 关卡号 | 14002 / 21001 / 21005 的整份应答 |
| `campaignProgress` | 205 | 关卡号 | 14003 的整份应答 |
| `gacha` | 194 | `gachaId` 或 `gachaId\|10` | 15001 单抽 / 十连 |
| `heroTpl` | 300 | `<cid>#<槽位>` | 我方英雄片段（x/y/attrs 是占位符） |
| `spots` / `attrs` / `tcb` / `terrain` | 各 1888~1889 | 关卡号 | 站位 / 属性 / 友军战功和 / 地形格 |

`opcode_table.lua` 从 160 KB 涨到约 7.3 MB。

### 54.3 【关键】编队能替换的前提：实测同关换队只差 x/y/uid
`build_lua_table.py` 里用改写 `player_team_hero_ids` 的方式，
让**真的** `gen_battle_data` 出战指定 5 人，从而拿到正确的英雄对象 ——
而不是自己拼 `_hero_base()`（那样会把 `apply_hero_config` 的字段规则抄第二份，
将来 Python 加字段就分叉）。
实测结论：同关换编队后敌方、totalCombat、以及每个英雄除 x/y/uid 外的全部字段都不变，
`level/star` 也是全局的。只有 `attrs`（`GridBattle.AttrCoef`）逐关不同，
所以它按关卡单独物化。

### 54.4 【坑】构建期必须隔离状态文件
`build_lua_table.py` 里要把这两个路径指到**不存在的文件**：
```python
Server.TEAM_STATE_PATH     = <tmp>/no_team.json
Server.CAMPAIGN_STATE_PATH = <tmp>/no_campaign.json
```
不隔离的话会读到你上次在真机上编的队 / 打的关，然后固化进表：
- 站位错 → 离线端我方站位和 Python 端对不上
- 进度错 → 刚开局 `branchLastPassed` 就已经是 `C01S09` 了

### 54.5 【坑】天梯关卡 id 有两种形态
`StairsBattle.tsv` 里既有 `T07S13` 也有 `T_FIRE_S001` / `T_LIGHT_S001`。
Python 的 `STAIRS_ID_RE = T\d{2}[SMX]\d{2}` 只认前一种，
导致这几百关在 21001/21005 上完全打不了 —— **这是线上服务端的真 bug**，
不是只有离线端有问题。已改为 `extract_stairs()`：正则捞候选 + 拿 rowId 集合校验。
Lua 侧改成 `find_keyed()`：直接按表反查，对任意 id 形态都成立。
教训：**别用固定正则解析 id，用表反查。**

### 54.6 【坑】C00S01 是有意不走动态生成的
`rrcp_server.py` 的 14002 分支写死了 `camp != 'C00S01'`，
因为那份手写静态响应是唯一在真机从头验通过的
（英雄固定 (2,3)，正好避开该关 `landformSP` 的 1_2 / 2_2 两格，见 `:3166`）。
离线端要跟 Python 一致，就原样照抄 `table['14002']`。

### 54.7 【坑】Lua 侧也要校验地形
玩家在编队界面能摆哪就摆哪，不保证不压地形。
Python 会校验后回退到默认站位，Lua 必须一样 ——
压在 `MapDataId.landformSP` 上时，那个地形技能会拿到 nil 的 target 直接崩
（`SpecialTerrain_XinShouHuiNeng0_4_2.lua:174/176`）。
做法：物化每关的 `terrain` 表，Lua 里玩家给的坐标命中就退回 `spots`。

### 54.8 【坑】编队不足要补齐到 cap
请求里第 2 个以后的队员是紧凑打包的（实测第二成员键是 `"La6\x3f..."` 不是英雄 id），
常常只能解出 1 个。绝不能因此只派一个人上场 —— 用户实测就是"只会上一个角色"。
补位规则照抄 `rrcp_server.gen_battle_data:3254-3281`：
先用"已拥有里非默认"的英雄补，一个都没有才退回服务端编队；
不能拿默认那对来凑（玩家看到的就是"一个默认一个我选的"）。

### 54.9 【坑】emit 出的 Lua 注释必须纯 ASCII
`opcode_table.lua` 按 ascii 编码写出，注释里出现中文会
`UnicodeEncodeError: 'ascii' codec can't encode character`，
而且位置会报在 16 万字节处（中间某个 battles 条目），很难联想到是注释的问题。

### 54.10 【坑】对拍时 Python 侧的返回值是**活引用**
14003 的 `resp['d']['player']` 就是服务端 table 里那个 dict，
之后每次 14003 都会原地改它。直接留引用的话前面取到的"快照"
会被后面的调用改掉，比对结果莫名其妙地漂。
必须 `json.loads(json.dumps(x))` 断开引用。
另外 14003 是有状态的（`campaign_passed` 一直累积），
每个子用例都要用**全新的** Server 实例，且状态文件要重定向到不存在的位置。

### 54.11 剩下 4 项有意保留的差异
| 项 | 原因 |
|---|---|
| `10032` | Lua 改开关要重跑 `apply_*()` 读 TSV，做不到。如实返回 `resCode=1` + 说明 |
| `15001` 出货英雄 | 构建期冻住结果，Python 每次重摇。离线端固定结果反而合脚 |
| `14003` 的 `branchLastPassed` | 离线端按"一路打上来"穷举，可能比 Python 当次会话更靠后（含 `CxxExx` 剧情关）。对拍时按 `campaign_order_rank` 判定"Lua 更靠后"就不算错 |
| `C00S01` | 见 54.6 |

### 54.12 构建说明文档
`D:\Temp\yqlr\LUA_BUILD.md` —— 链路、预编码约束、表结构、构建命令、
改了 Python 之后要不要重跑、排查手册。

---

## 55. 中文语音 / 设置页 / 关卡解锁 / 注入器（2026-10-10 19:00 ~ 21:30）

### 55.1 中文语音为什么当年做不成，现在做成了
第 33.1 节的结论「中文配音在离线环境下不可能实现（除非把 470 个文件
也打进包，**而我们手上没有它们**）」，前提在这一轮变了：拿到了素材
`D:\System\下载\跃迁旅人-中文配音-原始素材.zip`。

校验（`inject_voice_cn.py`）：**240/240 文件名 + size + MD5 全对**，
且 120 个包全部被 `Audio.tsv` 的 `PkgName` 引用（未引用 0 个），
所以 417 MB 全是真需要的，没有死重量。
文件头 `AFS2` = Wwise SoundBank。

### 55.2 【坑】APK 超过 2^31 时 zipalign / apksigner 双双失败
全量注入语音后 APK = 2,151,504,903 B，`2^31 = 2,147,483,648`，
**超 4,021,255 B（3.83 MB）**：

- `zipalign` → `Unable to open ... as zip archive`
- `apksigner` → `exit=1`，输出文件不完整

根因不是文件大小本身，是**中央目录偏移 2,161,709,620 越过 2^31**，
按 32 位**有符号**解释就变负。
腾空间的手段全部试过且都不够：
- DEFLATE level 9 比 level 6 只多省 0.1 MB（Wwise bank 压不动，92.6%~99.6%）
- `assets.db`（我们自己替换的条目）已经是 DEFLATED，没得压
- `.png@alpha`(142MB) / `.moc3` / `.usm` / `.td` / `.fui` 压缩率 100.0%
- 唯一有肉的是既有 `.awb`（554 MB → 97.3%，省约 15 MB），
  但那会动到**当前正常的 JP 配音和 BGM**，不划算

> 抽样外推会严重失真：只取最大的 12 个文件估「省 49 MB」，
> 实际 level 6 只省了 11.7 MB —— 大文件恰恰最难压。

### 55.3 【坑】游戏只从 `<writablePath>/<real>` 读可写资源
实测三种位置：

| 位置 | 结果 |
|---|---|
| `/data/data/<pkg>/files/release/<md5路径>` | ✅ 能出声 |
| `/sdcard/Android/data/<pkg>/files/release/...` | ❌ |
| `/storage/emulated/0/yqlr/...`（公共目录） | ❌ |

**不是权限问题**（`targetSdk=26` 走 legacy 外部存储、
`READ_EXTERNAL_STORAGE` 已授权）。
游戏有自己的 FileUtils delegate，只认这一个可写位置；
在 `dmAudio` 里加 `addSearchPath` 和绝对路径都插不进去。
判据：设备上那个**空的** `files/release/` 目录，名字正好等于
`assets.db` 里 `real` 字段的格式 `release/<md5[0:2]>/<md5[2:4]>/<md5[4:]>`。

### 55.4 【坑】apktool 不能用来编 manifest
`apktool d` 能把 manifest 解成文本（去掉 `-r`，加了它会保留二进制），
但 `apktool b` **必须经过 aapt2 link**，而本游戏 manifest 里有
`android:theme="@2131689726"`（0x7f…，指向自身资源表），
空 `resources.arsc` 过不了类型校验：

```
error: '@2131689726' is incompatible with attribute theme (attr) reference
```

apktool 没有独立的 AXML 编码器可用。而游戏资源是内容寻址放在 `assets/`
下的（不是标准 `res/` 树），apktool 也认不出来。
→ 只能自己写 AXML 定点修改器（`axml_patch.py` + `inject_documents_provider.py`）。

### 55.5 AXML 定点改 manifest 的四个坑（都踩了）
1. **元素 chunk 是平铺的兄弟节点**，`START` 的 size **只含它自己和属性**，
   不含子节点（实测 `manifest`=196、`<application>`=256，都远小于其子树）。
   **只有根 chunk 的 size 等于文件全长**。一开始去改 `<application>` 的 size，是错的。
2. **`ResXMLTree_node` 里 `prefix` 在 +16、`uri` 在 +20**，拿错整个命名空间就废
   （渲染出 `<android:provider>` 而不是 `<provider>`）。
3. **属性名必须在 RES_MAP 里有 res id**，否则 PackageParser 静默丢弃。
   本 manifest 的 RES_MAP 只有 41 项，`permission` 不在里面，
   得把 RES_MAP 扩到 150 项（补 109 个 0 占位）并填 `0x01010006`。
4. **AXML 里属性存的是本地名**（`name`），`android:` 前缀走 namespace；
   搜 `android:name` 会误判成"缺"。

另外：**元素 chunk 的 ns 必须是 -1**，只有属性用 android 的 uri，
否则元素名会被渲染成 `ns0:provider`。

### 55.6 【坑】漏写回条目，zipalign 静默通过、apksigner 才报错
重打包时写了
```python
if i.filename in ('AndroidManifest.xml', dexname): continue
```
结果新 manifest **从没被写回去**，包里直接少了这个条目。
`zipalign` 照样 `rc=0`（它不检查条目完整性），
最后是 `apksigner` 报 `Missing AndroidManifest.xml`。

→ **打包后必须逐条点名关键条目 + 比对 manifest 长度**，
不能指望任何工具替你发现。

### 55.7 校验步骤抓到的 bug（值不值钱看这个）
`pyaxmlparser` 把新旧 manifest 都解析成树、去掉新增 provider 后
**逐字符比对**，靠它抓出了 55.5 的第 2 条。
最终结果：`除新增 <provider> 外，其余内容逐字符一致`（8333 = 8333 字符）。

### 55.8 注入文件提供器（DocumentsProvider）
开源实现：`github.com/AbdurazaaqMohammed/InjectDocumentsProvider`
（原作者注明思路来自 MT 管理器作者 Lin Jin Bin）。
`a.dex` 9,380 B → 加为 `classes3.dex`；manifest 加 `<provider>`。

装完实测生效：
```
Provider{39dfc9c com.biubiux2.theleaper.aligames/bin.mt.file.content.MTDataFilesProvider}
content query --uri content://<pkg>.MTDataFilesProvider/root
  → Row: 0 root_id=<pkg>, title=跃迁旅人
```
用途：**无 root** 也能把语音放进 app 私有目录。
注意 `content query` 只能查 `/root`，深层遍历要走真实 SAF 客户端
（DocumentsUI），CLI 构造不出那种 URI。

### 55.9 【坑】Lua 不支持 `\uXXXX` 转义
在 Lua 源码里写 `'\u4e2d\u6587'` 会
`invalid escape sequence near '...'`。
Lua 只有 `\ddd` 十进制转义，中文要**直接写**（文件本身是 UTF-8，没问题）。

### 55.10 【坑】`GameConfigs.DebugCfgValues` 是惰性初始化的
设置页崩：
```
SiteGamePageWidget.luac:400: attempt to index field 'DebugCfgValues' (a nil value)
```
我们插进设置页的 bool 开关，`initFunc` 直接索引
`GameConfigs.DebugCfgValues[...]`，但那张表是
`_YQLR_CFG_VALUES()` 里 `or {默认值}` **惰性**建的，
玩家刚进页面还没点过任何开关 → nil。
→ `initFunc` 必须走 `_YQLR_CFG_VALUES()["name"]`。
（int 档位那类读的是独立的 `_YQLR_CFG_INDEX`，自带默认值，所以没事。）

### 55.11 【重大】14003 请求体里**没有 campaignId**
实测只有 **15 B**（第 52 节 3017 行早就记了，一直没被重视）。

Python 侧靠记忆兜底：
```python
camp = self.extract_campaign(body) or self.last_campaign
```
离线端早期只 `find_keyed(body, campaignProgress)` → 15 B 里根本没有关卡号
→ 查表落空 → 走静态兜底 → `lastPassed` 不推进
→ **「关卡打过了但下一关不解锁」**。

修：14002/21001/21005 命中时写 `_state.last_stage`，
14003 查表落空时用它兜底。

> **为什么对拍测试没抓到**：我在合成的 14003 请求体里**塞了** campaignId，
> 而真客户端不发。**测试用例本身掩盖了 bug**。
> 已补回归用例：先发 14002，再发**空 body** 的 14003。
> → 对拍数据要照抄真机抓包的字节，不能自己想当然。

### 55.12 【坑】`adb reverse` 会占住设备 8888，RL 包必须清
RL 的服务端在**应用内**监听 127.0.0.1:8888，
而 `adb reverse tcp:8888 tcp:8888` 会在**设备端**占住同一个端口
→ `bind` 直接失败。
第 50.8 节那套流程是给 **dev 包**（Python mock 跑在宿主）用的，RL 包必须跳过。
设备上 11:06/11:15/11:18 那三条历史 `bind 失败` 记录就是这个原因。

### 55.13 【坑】`$env:` 不跨工具调用传递
在一条命令里设了 `$env:YQLR_PROFILE='release'`，下一条命令跑
`rebuild_v5.py` 时读不到，退回默认 `dev`，产物写进了 `yqlr_v5_dev.apk`，
而我却拿 15:42 的旧包去对齐签名 —— 装上去后 19 个替换条目里**缺 11 个**。

→ `build_patched_luac.py` / `rebuild_v5.py` / zipalign / apksigner
**必须在同一条命令里跑**，或者干脆用 `deploy_dev.ps1`。

### 55.14 【坑】`install -r` 之后必须重推 `files/assets.db`
第 50.8 节的老坑，本轮又踩了一次。顺序固定：
```
build -> rebuild -> zipalign -> apksigner -> install
-> adb root -> patch_runtime_db.py -> adb unroot
-> adb reverse（仅 dev 包）-> 启动
```

### 55.15 挂起中
- **资源勘探从负数层级开始**：`apply_explore_config`（rrcp_server.py:1146）
  下发的 `chainMap` / `finishChainMap` / `finishObjects` / `checkMap`
  **全是空表**，而 `Explore.tsv` 里明明有 `TaskChainId` / `TaskId` / `MapID`。
  查过 `ExploreModel:synchronize`（70 行全文）确认它只做 `valueReplace`
  合并、**不计算层级**，所以层级是视图层推出来的，
  确切定义**还没定位到** → 不凭猜测填字段（填错会让
  `ExploreSystem:264` 的 `arrChainMap[data.Id]` 取到 nil 然后崩）。
  等 Python 侧修好后，`ExploreData` 在 10001 里，
  **重跑 `build_lua_table.py` 会自动带上**，不需要动 Lua。
- **关卡进度冷启动丢失**：方案见 `D:\Temp\yqlr\CAMPAIGN_PERSIST_PLAN.md`。
  注意这条**不会**因为 Python 修好而自动生效 —— 离线端是静态快照，没有状态机。
  → **已于 2026-10-10 22:20 实施并装包**，细节见第 56 节。

---

## 56. 关卡进度持久化（2026-10-10 21:45 ~ 22:20）

按 `D:\Temp\yqlr\CAMPAIGN_PERSIST_PLAN.md` 实施。方案全文在那个文档里，
这里只记**实施时踩到、和方案本身不一致**的东西。

### 56.1 【坑】一个变量不能承担两个角色
初版方案让 `_state.last_stage` 同时表示「本次 14002 打的关」和
「已通关的最远那关」。真实链路立刻坏：

```
14002(C01S02) -> last_stage = C01S02
14003(空body) -> cid = last_stage = C01S02
              -> campaign_farther(C01S02, C01S02)  <- 自己跟自己比
              -> 永远不落盘
```

**已拆成 `last_stage`（内存态，14003 兜底用）和
`saved_stage`（落盘态，10001 用）**，比较用 `campaign_farther(cid, saved_stage)`。
→ 凡是「临时上下文」和「持久状态」沾边的，都要拆成两个变量。

### 56.2 【坑·会发坏包】占位符必须有兜底，哨兵绝不能到客户端
哨兵 `__YQLR_CD__` 是**字符串**，而 `CampaignData` 必须是**对象**。
初版方案的替换条件是 `if ... and _state.last_stage then`，
于是**冷启动且无落盘时替换被整个跳过**，哨兵原样发给客户端：

```json
"CampaignData":"__YQLR_CD__"    <- string 而不是 table，一装新包就进不了主线
```

→ 构建期额外产出 `campaignCDDefault`（`Campaign.tsv` 第一行 `C00S01`），
运行时 `stage = saved_stage or campaign_cd_default`，
再兜一层 `"CampaignData":{}`。**任何路径都不让哨兵流到客户端。**

→ 凡是往预编码应答里埋占位符，都要问一句：
**"这个占位符没被替换时会怎样？"** 只在"有落盘时才替换"是不够的。

### 56.3 【坑】`campaign_order_rank` 有大量并列，不能当排序键
实测 **205 关只有 178 个不同的 rank** —— `C00S01` 和 `C00M01`
这类剧情关共用同一个 rank。用 `n > o` 比会**打平**，
于是「打完 C00M01 再打 C00S01」这种正常推进不更新落盘值，
冷启动反而拿 C00M01 的快照。

→ 改用 **`Campaign.tsv` 行序**（1..205，205 关全不并列）。
它同时也是 `campaignProgress` 快照的累加顺序
（`gen_campaign_progress` 按它逐行 `campaign_passed.add`），
所以「行序更大」==「快照包含更多关卡」，语义天然对齐。

→ **选排序键前先看并列情况**：`len(set(values))` 对比 `len(values)`。

### 56.4 【坑】深拷贝 `datas`，否则 205 条进度应答全被污染
`build_lua_table.py` 里 `resp['data']['player']` 和
`table['10001']['data']['player']` **是同一个对象**（原 194-196 行就警告过）。
写标量（`guideData` / `mainScreenHeroId`）无所谓，写完立刻 `json.dumps`。
但 `CampaignData` 会被后面的 `gen_campaign_progress()` 通过 `s2.table`
读到并 `cd.update(...)`。

直接写 `p['datas']['CampaignData'] = 哨兵` 会让
**205 条预编码进度应答里的 CampaignData 全变成那个字符串**。

→ 换哨兵前 `copy.deepcopy(datas)` 再赋回去。

### 56.5 【坑】别拿正则在生成好的 Lua 表上数条目
自检用 `\n        \["..."\] = ` 数 `campaignProgress`，205 条只数出 **204** ——
外层正则把第一条前的 `\n` 吃掉了，第一条匹配不上。
一度以为生成少了 1 条。

→ 按行 `splitlines()` 再逐行匹配，别在换行处省字符。

### 56.6 产物与规模
```
campaignCD        205 条   76 KB   （CampaignData 子对象，与 progress 逐字节一致）
campaignOrder     205 条   1..205
campaignCDDefault          C00S01
opcode_table.lua  7427.3 KB（原 7327.1 KB，+100 KB）
APK 条目 20333   rebuild_v5.py 总体: PASS
签名后 1,727,294,147 B
```

### 56.7 设备实测（冷启动、无落盘）
```
22:20:35 campaign state: 无落盘，10001 用初值快照
22:20:35 campaign state: saved=nil default=C00S01 cd=205 order=205
22:20:41 10001 CampaignData 用 C00S01 替换（初值快照）
22:20:41 -> RESP #1 opcode=10001 body=68410 B
```

### 56.8 打包环境备忘（本轮重新踩）
- build-tools 不在 `%LOCALAPPDATA%\Android\Sdk`，在
  **`E:\lib\android-sdk\build-tools\35.0.0`**
- keystore 不在 `_out_repack`，在
  **`C:\Users\Administrator\.android\debug.keystore`**
- 这两个路径在 `inject_documents_provider.py` 里能看到（`KS = ...`）

→ 顺手把 `Remove-Item $aligned $signed` 写在找 build-tools **之前**，
把上一个签名包删了才发现路径不对。**先确认路径，再删旧产物。**

### 56.9 provider 注入叠加到持久化版本上（22:28）
`inject_documents_provider.py` 默认吃的是**未签名**的 `yqlr_v5_offline.apk`，
所以在跑完持久化构建后直接重跑即可，不用改脚本：

```
manifest      16944 -> 18088 B (+1144)
校验           除新增 <provider> 外，其余内容逐字符一致 (8333 = 8333)
新增            classes3.dex (9380 B)   已有 classes.dex / classes2.dex
zipalign rc=0   apksigner rc=0   verify rc=0
产出            yqlr_v5_offline_provider-signed.apk (1647.29 MB)
```

注意：provider 注入**不经过** `build_patched_luac.py`，
所以顺序永远是「先构建 → 再注入」，反过来会把上一轮的 Lua 白注入掉。
`rebuild_v5.py` 不会自动注入 provider。

设备实测：
```
Provider Resolver Table:
  android.content.action.DOCUMENTS_PROVIDER:
  5f72eae com.biubiux2.../bin.mt.file.content.MTDataFilesProvider
```

`content query --uri content://...MTDataFilesProvider/root` 报
```
SecurityException: requires that you obtain access using ACTION_OPEN_DOCUMENT
```
**这是正确行为**，不是故障 —— manifest 里加了
`android:permission="android.permission.MANAGE_DOCUMENTS"`，
必须走真实 SAF 客户端（DocumentsUI）。见 55.8。

### 56.10 关卡进度持久化 + provider 在设备上的联合验证
```
/sdcard/campaign_state.json          {"stage":"C00S04"}      22:23 写入
22:29:17 campaign state loaded: C00S04
22:29:17 campaign state: saved=C00S04 default=C00S01 cd=205 order=205
22:29:22 10001 CampaignData 用 C00S04 替换（落盘进度）
```

即：`install -r` 重装（换成 provider 版）之后进度**没丢**，
10001 下发的是 C00S04 的快照而不是构建期初值 —— 持久化链路闭环。




