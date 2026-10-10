import json, os, time, zipfile
SRC = r"D:\Temp\yqlr\yqlr_2.2.2_9game.apk"
import os as _os
_PROFILE = _os.environ.get("YQLR_PROFILE", "dev").strip().lower()
_SUFFIX = {"dev": "dev", "release": "offline"}[_PROFILE]
DST = r"D:\Temp\yqlr\_out_repack\yqlr_v5_%s.apk" % _SUFFIX
print("[profile] %s -> %s" % (_PROFILE, DST))
R   = r"D:\Temp\yqlr\_out_repack"
V   = r"D:\Temp\yqlr\_out_vms\patched"

rep = {"assets/custom_conf.json": open(os.path.join(V,"custom_conf.vms.enc"),"rb").read()}
e = json.load(open(os.path.join(R,"replacements_v5.json"),encoding="utf-8"))
for k,v in e.items(): rep[k]=bytes.fromhex(v)
print("待替换/新增 %d 条:" % len(rep))
for k,v in rep.items(): print("  %-62s %9d B" % (k,len(v)))

if os.path.exists(DST): os.remove(DST)
t0=time.time()
zin=zipfile.ZipFile(SRC)
existing = {i.filename for i in zin.infolist()}
zout=zipfile.ZipFile(DST,"w",allowZip64=True); done=set(); n=0
for i in zin.infolist():
    data = rep[i.filename] if i.filename in rep else zin.read(i.filename)
    if i.filename in rep: done.add(i.filename)
    ni=zipfile.ZipInfo(i.filename,date_time=i.date_time)
    ni.compress_type=i.compress_type; ni.external_attr=i.external_attr
    ni.internal_attr=i.internal_attr; ni.create_system=i.create_system; ni.comment=i.comment
    zout.writestr(ni,data); n+=1
    if n%6000==0: print("    %d/%d (%.0fs)"%(n,len(zin.infolist()),time.time()-t0))

# 关键：原包不存在的新条目必须显式追加，否则永远不会进 ZIP
added=0
for k,v in rep.items():
    if k not in existing:
        ni=zipfile.ZipInfo(k, date_time=(2023,11,21,0,0,0))
        ni.compress_type=zipfile.ZIP_STORED
        zout.writestr(ni, v); added+=1
        print("  新增条目: %s (%d B)" % (k, len(v)))

# ------------------------------------------------------------------
# 可选：注入 db 里有、但原包缺的语音包（sound/voice_cn，240 个 / 417 MB）
#
# cn/en 语音是可选下载语言包，音频文件根本没打进原 APK，所以当年把
# GameDefaultVoiceLanguage 改成 CN 会导致"配音直接没声"（见 MEMORY 31~33）。
# inject_voice_cn.py 生成清单，这里流式读取追加，不落中间文件。
#
# 用 ZIP_STORED：Wwise bank 本身已压缩，deflate 几乎压不动，
# 而且 417 MB 再过一遍 deflate 要多花好几分钟。
# ------------------------------------------------------------------
voice_manifest = os.path.join(R, "voice_cn_manifest.json")
voice_added = 0
voice_bytes = 0
if os.environ.get("YQLR_VOICE_CN", "0") == "1" and os.path.exists(voice_manifest):
    vman = json.load(open(voice_manifest, encoding="utf-8"))
    print("注入 voice_cn：%d 条" % len(vman))
    vzf = zipfile.ZipFile(r"D:\System\下载\跃迁旅人-中文配音-原始素材.zip")
    vinfo = dict((os.path.basename(i.filename), i) for i in vzf.infolist()
                 if not i.is_dir())
    t1 = time.time()
    for k in sorted(vman):
        meta = vman[k]
        data = vzf.read(vinfo[meta["base"]])
        if k not in existing:
            ni = zipfile.ZipInfo(k, date_time=(2023, 11, 21, 0, 0, 0))
            # 必须 DEFLATE，不能 STORED。
            #   STORED 时 APK = 2,163,784,229 B，中央目录偏移 2,161,709,620
            #   越过 2^31，zipalign 按 32 位有符号解释偏移直接变负 ->
            #   "Unable to open as zip archive"。实测 Wwise bank 压不动
            #   （92.6%~99.6%），但 417 MB 基数大，总共能省约 49 MB，
            #   刚好把偏移拉回 2^31 以内。
            ni.compress_type = zipfile.ZIP_DEFLATED
            zout.writestr(ni, data, compresslevel=6)
            voice_added += 1
            voice_bytes += len(data)
            if voice_added % 40 == 0:
                print("    voice %d/%d  %.1f MB  %.0fs"
                      % (voice_added, len(vman), voice_bytes / 1048576.0,
                         time.time() - t1))
    vzf.close()
    print("  voice_cn 注入完成：%d 条 / 原始 %.1f MB / %.0fs"
          % (voice_added, voice_bytes / 1048576.0, time.time() - t1))

zout.comment=zin.comment; zout.close(); zin.close()
print("完成 %d 条(原样) + %d 条(新增) + %d 条(voice) , %.0fs"
      % (n, added, voice_added, time.time()-t0))
print("APK 大小 = %d B  (2^31 = 2147483648, %s)"
      % (os.path.getsize(DST),
         "OK" if os.path.getsize(DST) < 2147483648 else "!!! 超过 2GB，zipalign 会失败 !!!"))
print("未处理:", set(rep)-done-{"__new__"} or "无")

ok=True
with zipfile.ZipFile(DST) as z:
    names=set(z.namelist())
    for k,v in rep.items():
        g = k in names and z.read(k)==v
        ok&=g; print("  校验 %-62s %s"%(k,"PASS" if g else "FAIL"))
    if voice_added:
        # 语音包太大，不逐条 read 全量比对，只抽查首尾各 3 条 + 计数
        vman = json.load(open(voice_manifest, encoding="utf-8"))
        sample = sorted(vman)
        probe = sample[:3] + sample[-3:] + [sample[len(sample)//2]]
        for k in probe:
            g = k in names and len(z.read(k)) == vman[k]["size"]
            ok &= g
            print("  抽校 %-62s %s" % (k, "PASS" if g else "FAIL"))
        cnt = len([n for n in sample if n in names])
        print("  voice 条目数 = %d (期望 %d)" % (cnt, len(vman)))
    print("条目总数 %d (原 %d)" % (len(z.infolist()), len(existing)))
print("总体:","PASS" if ok else "FAIL")

