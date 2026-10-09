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
zout.comment=zin.comment; zout.close(); zin.close()
print("完成 %d 条(原样) + %d 条(新增), %.0fs"%(n,added,time.time()-t0))
print("未处理:", set(rep)-done-{"__new__"} or "无")

ok=True
with zipfile.ZipFile(DST) as z:
    names=set(z.namelist())
    for k,v in rep.items():
        g = k in names and z.read(k)==v
        ok&=g; print("  校验 %-62s %s"%(k,"PASS" if g else "FAIL"))
    print("条目总数 %d (原 %d)" % (len(z.infolist()), len(existing)))
print("总体:","PASS" if ok else "FAIL")

