# -*- coding: utf-8 -*-
"""
MiBandHealth 客户端构建与版本管理脚本
======================================
用法（建议在虚拟环境中执行）：
  python build.py                # patch 递增并构建：1.0.0 -> 1.0.1
  python build.py --bump minor   # minor 递增：1.0.1 -> 1.1.0
  python build.py --bump major   # major 递增：1.1.0 -> 2.0.0
  python build.py --no-bump      # 不递增版本，用当前版本重新构建
  python build.py --changes "说明文字"   # 附加本次变更说明

流程：
  读取当前版本 -> 递增 -> 更新 app.py -> PyInstaller 打包 ->
  产物命名 MiBandHealth_vX.Y.Z.exe -> 计算 SHA256 ->
  更新 versions.json / CHANGELOG.md -> 清理中间产物
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
APP_PY = os.path.join(ROOT, "app.py")
DIST_DIR = os.path.join(ROOT, "dist")
BUILD_DIR = os.path.join(ROOT, "build")
OUT_DIR = os.path.join(ROOT, "客户端构建")
VERSIONS_FILE = os.path.join(OUT_DIR, "versions.json")
CHANGELOG_FILE = os.path.join(OUT_DIR, "CHANGELOG.md")
EXE_NAME = "MiBandHealth"


def log(msg):
    print(f"[build] {msg}", flush=True)


def read_version():
    src = open(APP_PY, encoding="utf-8").read()
    m = re.search(r'APP_VERSION = "(\d+)\.(\d+)\.(\d+)"', src)
    if not m:
        raise RuntimeError("app.py 中找不到 APP_VERSION")
    return [int(x) for x in m.groups()]


def write_version(v):
    src = open(APP_PY, encoding="utf-8").read()
    new = f'APP_VERSION = "{v[0]}.{v[1]}.{v[2]}"'
    src2 = re.sub(r'APP_VERSION = "\d+\.\d+\.\d+"', new, src)
    if src2 == src:
        raise RuntimeError("版本号写入失败")
    open(APP_PY, "w", encoding="utf-8").write(src2)


def bump(v, kind):
    if kind == "major":
        return [v[0] + 1, 0, 0]
    if kind == "minor":
        return [v[0], v[1] + 1, 0]
    return [v[0], v[1], v[2] + 1]


def load_versions():
    if os.path.exists(VERSIONS_FILE):
        try:
            return json.load(open(VERSIONS_FILE, encoding="utf-8"))
        except (OSError, ValueError):
            pass
    return {"current": "1.0.0", "history": []}


def save_versions(data):
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(VERSIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def update_changelog(version, date, changes):
    os.makedirs(OUT_DIR, exist_ok=True)
    head = f"# MiBandHealth 更新日志\n\n"
    entry = f"## v{version}（{date}）\n" + "".join(f"- {c}\n" for c in changes) + "\n"
    if os.path.exists(CHANGELOG_FILE):
        old = open(CHANGELOG_FILE, encoding="utf-8").read()
        body = re.sub(r"^# MiBandHealth 更新日志\s*\n*", "", old)
        content = head + entry + body
    else:
        content = head + entry
    with open(CHANGELOG_FILE, "w", encoding="utf-8") as f:
        f.write(content)


def build_exe():
    sep = os.pathsep  # Windows 为 ';'
    index_src = os.path.join(ROOT, "index.html")
    echarts_src = os.path.join(ROOT, "echarts.min.js")
    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile",
           "--name", EXE_NAME,
           "--add-data", f"{index_src}{sep}.",
           "--add-data", f"{echarts_src}{sep}.",
           APP_PY]
    log("执行: " + " ".join(cmd[:8]) + " ...")
    rc = subprocess.call(cmd, cwd=ROOT)
    if rc != 0:
        raise RuntimeError(f"PyInstaller 打包失败 rc={rc}")
    exe = os.path.join(ROOT, "dist", EXE_NAME + ".exe")
    if not os.path.exists(exe):
        raise RuntimeError("未找到打包产物")
    return exe


def cleanup():
    for d in (os.path.join(ROOT, "dist"), os.path.join(ROOT, "build")):
        shutil.rmtree(d, ignore_errors=True)
    for spec in (os.path.join(ROOT, EXE_NAME + ".spec"),):
        if os.path.exists(spec):
            os.remove(spec)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bump", choices=["patch", "minor", "major"], default="patch")
    ap.add_argument("--no-bump", action="store_true", help="不递增版本")
    ap.add_argument("--changes", nargs="*", default=None, help="本次变更说明")
    args = ap.parse_args()

    ver = read_version()
    old_ver = ".".join(str(x) for x in ver)
    if args.no_bump:
        new_ver = old_ver
        log(f"当前版本 {old_ver}（不递增，重新构建）")
    else:
        ver = bump(ver, args.bump)
        new_ver = ".".join(str(x) for x in ver)
        write_version(ver)
        log(f"版本更迭: {old_ver} -> {new_ver}")

    date = time.strftime("%Y-%m-%d %H:%M")
    changes = args.changes or [f"基于 v{old_ver} 的新构建"]

    log("开始打包...")
    t0 = time.time()
    exe_path = build_exe()
    log(f"打包完成（{int(time.time() - t0)}s）: {exe_path}")

    out_exe = os.path.join(OUT_DIR, f"MiBandHealth_v{new_ver}.exe")
    os.makedirs(OUT_DIR, exist_ok=True)
    shutil.copy2(exe_path, out_exe)
    digest = sha256(out_exe)
    size_mb = round(os.path.getsize(out_exe) / (1024 * 1024), 1)
    log(f"产物: {out_exe}（{size_mb} MB）")
    log(f"SHA256: {digest}")

    data = load_versions()
    data["current"] = new_ver
    data["history"].insert(0, {
        "version": new_ver, "date": date, "changes": changes,
        "file": os.path.basename(out_exe), "sha256": digest, "size_mb": size_mb,
    })
    save_versions(data)
    update_changelog(new_ver, date, changes)
    log("版本台账已更新: versions.json / CHANGELOG.md")

    cleanup()
    log("构建完成")


if __name__ == "__main__":
    main()
