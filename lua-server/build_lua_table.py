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
import io
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, r'E:\Test\Temp\yqlr\_out_rrcp')

import rrcp_server  # noqa: E402

# 10001 里 guideData 的占位符；Lua 端做一次 gsub 替换。
GUIDE_PLACEHOLDER = '__YQLR_GUIDEDATA__'

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
    lines.append('    opcodes = {')
    for opcode in sorted(payload['opcodes']):
        lines.append('        [%s] = %s,' % (lua_str(opcode),
                                           lua_str(payload['opcodes'][opcode])))
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
    try:
        cfg = _Cfg(tmp)
        srv = rrcp_server.Server(cfg)

        # guide_data() 在 GUIDE_SKIP_STORY=True 时返回固定映射，不读状态文件；
        # 仍然先塞一个空 _guide_seen，避免它去碰磁盘上的引导状态。
        srv._guide_seen = {}
        guide = srv.guide_data() or {}
        guide_json = json.dumps(guide, ensure_ascii=True, separators=(',', ':'))

        table = srv.table
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
                else:
                    raise SystemExit('10001 的 data.player 不存在，无法放 guideData 占位符')

            encoded[opcode] = json.dumps(resp, ensure_ascii=True,
                                         separators=(',', ':'))

        payload = {
            '_note': 'materialized by build_lua_table.py; bodies are PRE-ENCODED json strings',
            'opcodes': encoded,
            'guideDataJson': guide_json,
            'serverTimeTarget': rrcp_server.Server.SERVER_TIME_TARGET,
            'guidePlaceholder': GUIDE_PLACEHOLDER,
            'codeVersion': rrcp_server.CODE_VERSION,
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
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    main()