#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""patch_runtime_db.py -- 改设备上真正的运行时资源清单

**这是之前一直踩空的地方。**

APK 里的 assets/32/assets.db 与 assets/64/assets.db 不是运行时真正读的库。
游戏首次启动时会把它们合并，生成：

    /data/data/<pkg>/files/assets.db   （8 MB，三张表）

      assets   (logic, version) 主键，合并视图，20541 行
      versions ver_name -> (version, mapping)，如 v57 -> m_57、current -> m_57
      m_57     当前版本的资源表，主键 (logic)

这个文件被长期缓存：只要版本标识没变，重新安装 APK 也**不会**重建它。
所以改了 APK 里的 assets.db 却不改这里，运行时就完全看不到新资源，
表现为 `module 'xxx' not found`（require 找不到，且报错里只有 lua/so 搜索路径，
不会出现 release/xx/yy 路径 —— 因为压根没查到记录）。

用法:
    python patch_runtime_db.py                 # 用最新 replacements_*.json 里的记录
    python patch_runtime_db.py --show          # 只看当前设备状态
"""
import argparse
import json
import os
import sqlite3
import subprocess
import sys
import tempfile

ADB = r'E:\Test\ADB\adb_tool\adb.exe'
DEV = '127.0.0.1:5555'
PKG = 'com.biubiux2.theleaper.aligames'
REMOTE_DB = '/data/data/%s/files/assets.db' % PKG
UID = 10062          # u0_a62
GID = 10062
TMP_LOCAL = r'C:\Users\ADMINI~1\AppData\Local\Temp\opencode\rt_assets.db'


def tail(r):
    """adb 把进度写 stderr，stdout 常为空"""
    for s in (r.stdout, r.stderr):
        s = (s or '').strip()
        if s:
            return s.splitlines()[-1]
    return '(无输出)'


def adb(*args, **kw):
    return subprocess.run([ADB, '-s', DEV] + list(args),
                          capture_output=True, text=True, **kw)


def tables(c):
    return [r[0] for r in c.execute("select name from sqlite_master where type='table'")]


def version_tables(c):
    """versions 里映射到的所有版本表 + assets 视图"""
    t = ['assets']
    try:
        maps = [r[0] for r in c.execute('select mapping from versions')]
    except sqlite3.Error:
        maps = []
    for m in maps:
        if m and m not in t and m in tables(c):
            t.append(m)
    return t


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--json', default=r'D:\Temp\yqlr\_out_repack\replacements_v5.json')
    ap.add_argument('--show', action='store_true')
    cfg = ap.parse_args()

    if not cfg.show:
        # 从 replacements 里提取 (logic, real, size, md5)，按逻辑路径配对
        data = json.load(open(cfg.json, encoding='utf-8'))
        print('replacements: %d 条' % len(data))
        dbs = [k for k in data if k.endswith('assets.db')]
        luacs = {k: data[k] for k in data if k.endswith('.luac')}
        print('  清单条目 %s' % dbs)
        print('  资源条目 %d 个' % len(luacs))
        for k in luacs:
            print('    %s (%d B)' % (k, len(luacs[k]) // 2))

    print('\n=== 拉取设备运行时清单 ===')
    r = adb('pull', REMOTE_DB, TMP_LOCAL)
    if r.returncode != 0:
        print('拉取失败:\n%s' % r.stderr); sys.exit(1)
    print(tail(r))

    c = sqlite3.connect(TMP_LOCAL)
    ts = version_tables(c)
    print('表: %s' % tables(c))
    print('需要同步的表: %s' % ts)
    for r_ in c.execute('select ver_name,version,mapping from versions'):
        print('  versions: %s' % (r_,))

    watch = ['sdk/SDKHelper.luac', 'yq/launch/login/view/LoginMediator.luac']
    print('\n=== 当前设备记录 ===')
    for logic in watch:
        for t in ts:
            rows = list(c.execute('select real,size,hash from %s where logic=?' % t, (logic,)))
            for real, size, hsh in rows:
                print('  [%s] %-40s %8d %s' % (t, real.split('/')[-1], size, hsh))

    if cfg.show:
        c.close()
        return

# 新值直接读构建产物，不硬编码（之前硬编码过一次，改了构建脚本就悄悄对不上）
    mf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'patch_manifest.json')
    manifest = json.load(open(mf_path, encoding='utf-8'))
    NEW = {}
    for logic, info in manifest.items():
        md5, size = info['md5'], info['size']
        real = info.get('real') or ('release/%s/%s/%s.luac' % (md5[0:2], md5[2:4], md5[4:32]))
        NEW[logic] = (md5, size, real)
    print('从 patch_manifest.json 读到 %d 条记录' % len(NEW))

    # ------------------------------------------------------------------
    # 悬空路径自愈：内容寻址下 real 是 md5 决定的路径，把某个 logic 从
    # JOBS 里移除后，APK 里就不再生成它的新条目，但本地 DB 仍指向那个
    # 已经不存在的路径 -> 运行时报
    #     module 'yq.base.view.DmViewMediator' not found
    # 所以这里扫一遍全表：凡是 real 指向的文件不在 APK 里的行，
    # 一律用原始 APK 的 pristine DB 里的值还原。
    # ------------------------------------------------------------------
    import zipfile, shutil, tempfile
    # [PROFILE] 产物名带 profile 后缀，必须跟着变；
    # 否则 os.path.exists() 为 False，下面整段"悬空路径自愈"会被**静默跳过**。
    _PROFILE = os.environ.get('YQLR_PROFILE', 'dev').strip().lower()
    _SUFFIX = {'dev': 'dev', 'release': 'offline'}[_PROFILE]
    apk_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            'yqlr_v5_%s.apk' % _SUFFIX)
    orig_apk = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            'yqlr_2.2.2_9game.apk')
    print('\n[profile] %s -> 参考 APK: %s（存在=%s）'
          % (_PROFILE, os.path.basename(apk_path), os.path.exists(apk_path)))
    if not os.path.exists(apk_path) and os.path.exists(orig_apk):
        apk_path = orig_apk
        print('[profile] 回退到原始 APK 作为参考')
    if os.path.exists(apk_path) and os.path.exists(orig_apk):
        zn = set(zipfile.ZipFile(apk_path).namelist())
        tmpd = tempfile.mkdtemp()
        # 必须取 assets/**64**/assets.db 作为原版来源：APK 内置的 32/64 两份 DB
        # 对同一个 logic 指向**不同的 blob**（实测 DmViewMediator：
        #   assets/32 -> release/a6/91/b32b9876...  flags byte 0x00
        #   assets/64 -> release/68/2c/a3c82e46...  flags byte 0x08）
        # 目标设备是 x86_64 模拟器，用 32 位那份会被 LuaJIT 判成
        # "cannot load incompatible bytecode"。
        pris = os.path.join(tmpd, 'a64.db')
        with zipfile.ZipFile(apk_path).open('assets/64/assets.db') as s, \
                open(pris, 'wb') as d:
            shutil.copyfileobj(s, d)
        pc = sqlite3.connect(pris)

        # 32 位原版只用于**识别**"这行是不是被误写成 32 位变体"
        pris32 = os.path.join(tmpd, 'a32.db')
        with zipfile.ZipFile(apk_path).open('assets/32/assets.db') as s, \
                open(pris32, 'wb') as d:
            shutil.copyfileobj(s, d)
        pc32 = sqlite3.connect(pris32)

        dangling = []
        for t in ts:
            for logic, real, size, hsh in c.execute(
                    'select logic, real, size, hash from %s' % t):
                # 只管 .luac 模块：只有它们走"内容寻址 + 由 JOBS 决定是否重打包"
                # 这条链路。语音等资源是**按需下载**的，APK 里本来就没有
                # （实测 APK 只带 207 个 .acb，DB 里有大量 voice 行），
                # 用"文件是否在 APK 里"判断它们必然误报。
                if logic in NEW or not logic.endswith('.luac'):
                    continue
                row = pc.execute('select real,size,hash from assets where logic=?',
                                 (logic,)).fetchone()
                if not row:
                    continue
                r32 = pc32.execute('select real,size,hash from assets where logic=?',
                                   (logic,)).fetchone()
                p32 = r32 if r32 else None
                # 两种情况要还原：
                #  a) real 指向的文件不在 APK 里 —— 把 logic 从 JOBS 移除后
                #     APK 不再生成该条目，本地 DB 还指着旧路径，
                #     运行时 module not found。
                #  b) 值等于 32 位原版、且与 64 位原版不同 —— 说明被误写成
                #     32 位变体，设备是 64 位，会被判成
                #     cannot load incompatible bytecode。
                bad_path = ('assets/' + (real or '')) not in zn
                cur = (real, size, hsh)
                is_32bit = (cur == p32) if p32 else False
                bad_variant = is_32bit and (cur != (row[0], row[1], row[2]))
                if bad_path or bad_variant:
                    why = '路径不在APK' if bad_path else '误用32位变体'
                    dangling.append((t, logic, why))
        seen = set()
        fixed = 0
        for t, logic, why in dangling:
            if logic in seen:
                continue
            seen.add(logic)
            row = pc.execute('select real,size,hash from assets where logic=?',
                             (logic,)).fetchone()
            if not row:
                continue
            for tt in ts:
                c.execute('update %s set real=?, size=?, hash=? where logic=?' % tt,
                          (row[0], row[1], row[2], logic))
            ok = ('assets/' + row[0]) in zn
            print('  !! 已还原64位原版 [%s] %s (%s) -> %s  APK内存在=%s'
                  % (t, logic, why, row[0], ok))
            fixed += 1
        pc.close()
        pc32.close()
        shutil.rmtree(tmpd, ignore_errors=True)
        if fixed:
            c.commit()
        print('原版对齐: %d 个 logic' % fixed)
    else:
        print('（跳过悬空路径检查：找不到 %s 或 %s）' % (apk_path, orig_apk))

    print('\n=== 写入新记录 ===')
    n = 0
    for logic, (md5, size, real) in NEW.items():
        for t in ts:
            cur = c.execute('select count(*) from %s where logic=?' % t,
                            (logic,)).fetchone()[0]
            if not cur:
                print('  [%s] %s 无记录，跳过' % (t, logic))
                continue
            c.execute('update %s set real=?, size=?, hash=? where logic=?' % t,
                      (real, size, md5, logic))
            print('  [%s] %-40s <- %s' % (t, logic.split('/')[-1],
                                          real.split('/')[-1]))
            n += cur
    c.commit()

    print('\n=== 校验 ===')
    ok = True
    for logic, (md5, size, _r) in NEW.items():
        for t in ts:
            for real, s, h in c.execute('select real,size,hash from %s where logic=?' % t, (logic,)):
                good = (h == md5 and s == size)
                ok &= good
                print('  [%s] %-40s %s' % (t, real.split('/')[-1], 'PASS' if good else 'FAIL'))
    c.execute('vacuum')
    c.close()
    print('\n总体: %s' % ('PASS' if ok else 'FAIL'))
    if not ok:
        sys.exit(2)

    print('\n=== 推回设备 ===')
    r = adb('push', TMP_LOCAL, REMOTE_DB)
    print(tail(r))
    # 关键：必须还原属主/权限，否则 app（u0_a62）读不到
    for cmd in ['chown %d:%d %s' % (UID, GID, REMOTE_DB),
                'chmod 600 %s' % REMOTE_DB]:
        rr = adb('shell', cmd)
        print('  %s -> %s' % (cmd, 'ok' if rr.returncode == 0 else rr.stderr.strip()))
    r = adb('shell', 'ls', '-la', REMOTE_DB)
    print(tail(r))

if __name__ == '__main__':
    main()
