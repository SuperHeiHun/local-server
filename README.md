# 构建步骤

## 依赖

- Python 3 + `cryptography`（仅 `build_lua_table.py` 需要，用来物化应答数据）
- LuaJIT（编译客户端 Lua）
- Android SDK build-tools（`zipalign` / `apksigner`）
- adb + 一台已 root 的设备（`patch_runtime_db.py` 的自愈审计需要 root）

## 目录

```
python-server/   rrcp_server.py  opcodes_table.json  start_mock_detached.ps1
lua-server/      offline_server.lua  opcode_table.lua(生成物)  build_lua_table.py
build/           build_patched_luac.py  rebuild_v5.py  patch_runtime_db.py
                 test_rsp_offline.py  test_lua_parity.py
docs/            MEMORY.md  LUA_BUILD.md  CAMPAIGN_PERSIST_PLAN.md
```

客户端文件（反编译 Lua 源码、配置表、原版 APK）需自行从你持有的 APK 中提取，
放到构建脚本引用的位置；本仓库不提供。

## 一、Python 服务端（调试用）

```powershell
cd python-server
python rrcp_server.py --port 8888 --algo 0 --table opcodes_table.json --out ./capture
adb reverse tcp:8888 tcp:8888
```

## 二、内置 Lua 服务端（随 APK 发行）

```powershell
# 1) 从 Python 服务端物化应答数据 -> lua-server/opcode_table.lua
cd lua-server
python build_lua_table.py

# 2) 编译客户端 Lua，并把内置服务端 + 应答表内联进 Service.luac
cd ../build
$env:YQLR_PROFILE = 'release'   # dev = 带调试探针；release = 干净
$env:YQLR_OSRV    = '1'         # 1 = 注入内置服务端
python build_patched_luac.py

# 3) 重打 APK
python rebuild_v5.py            # -> yqlr_v5_offline.apk

# 4) 同步运行时资源库到设备（必须在第 3 步之后）
adb root
python patch_runtime_db.py

# 5) 对齐 + 签名
zipalign -f -p 4 yqlr_v5_offline.apk yqlr_v5_offline-aligned.apk
apksigner sign --ks <你的keystore> --ks-pass pass:<密码> --out yqlr_v5-offline-signed.apk yqlr_v5_offline-aligned.apk

adb install -r yqlr_v5-offline-signed.apk
```

顺序不能换：`patch_runtime_db.py` 以刚产出的 APK 为准做校验与悬空自愈，
放在 `rebuild_v5.py` 之前会校验到上一个包。

## 三、改了配置之后

配置（角色等级/突破/星级/跃升/好感、资源数量、天梯类型、空间背景、引导进度）
由游戏自己的配置表推导，开关与上限集中在 `rrcp_server.py` 顶部常量。

改完必须重跑，否则内置服务端用的还是旧数据：

```powershell
cd lua-server && python build_lua_table.py
```

## 四、应答层自测

不用连设备，也不用重新打包：

```powershell
cd build
python test_rsp_offline.py     # 应答层，含关卡进度持久化回归
python test_lua_parity.py      # Python ↔ Lua 对拍，要求零差异
```

`LUA_BUILD.md` 记录了预编码约束、占位符清单、
落盘状态格式和构建命令；
`CAMPAIGN_PERSIST_PLAN.md` 是关卡进度持久化的设计与实施记录。

## 产物

`yqlr_v5-*.apk` 不随本仓库分发。