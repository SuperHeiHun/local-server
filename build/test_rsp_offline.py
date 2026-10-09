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

-- 未知 opcode 走 default
local r2 = OfflineServer.build_response({ req_id = 9, opcode = 99999 })
print('  default rsp total = ' .. #r2 .. ' body=' .. r2:sub(25))
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