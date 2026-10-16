# -*- coding: utf-8 -*-
"""
小米手环云端健康数据看板 — 本地后端服务
============================================
- 通用登录：任意小米账号（密码登录 + 固定设备指纹免 2FA），登录态存内存，密码不落盘
- 数据接口：每日聚合（步数/睡眠/心率/血氧/卡路里/强度/站立）+ 逐点明细（心率/血氧/压力）+ 运动记录
- 导出：CSV / JSON 自定义下载
- 监听 127.0.0.1（仅本机可访问）

运行：python app.py   →   http://127.0.0.1:8000
依赖：flask、requests（RC4/签名算法为内嵌纯标准库实现，无其他加密依赖）
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import secrets
import struct
import sys
import threading
import time
import uuid
import webbrowser

# 依赖本地化：优先从应用目录 vendor/ 加载 flask/requests 等，离线可用
_VENDOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor")
if os.path.isdir(_VENDOR) and _VENDOR not in sys.path:
    sys.path.insert(0, _VENDOR)

import requests
from flask import Flask, Response, jsonify, request, send_from_directory

# ============================ 应用信息与路径 ============================

APP_NAME = "小米手环健康客户端"
APP_NAME_EN = "MiBandHealth"
APP_VERSION = "1.0.1"

if getattr(sys, "frozen", False):
    # PyInstaller 打包运行：exe 所在目录为数据目录；页面资源在 _MEIPASS
    BASE_DIR = os.path.dirname(sys.executable)
    RES_DIR = getattr(sys, "_MEIPASS", BASE_DIR)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    RES_DIR = BASE_DIR

SESSION_FILE = os.path.join(BASE_DIR, "session.json")
DATA_DIR = os.path.join(BASE_DIR, "数据")
EXPORT_DIR = os.path.join(DATA_DIR, "导出")
LOG_DIR = os.path.join(DATA_DIR, "logs")
for _d in (DATA_DIR, EXPORT_DIR, LOG_DIR):
    try:
        os.makedirs(_d, exist_ok=True)
    except OSError:
        pass

app = Flask(__name__, static_folder=RES_DIR, static_url_path="")

# ============================ 小米加密算法（内嵌，源自 huami-token/mi_crypto） ============================

class RC4:
    """RC4 流密码（drop 1024 由 _make_rc4 处理）。"""

    def __init__(self, key: bytes) -> None:
        self.S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i % len(key)]) & 0xFF
            self.S[i], self.S[j] = self.S[j], self.S[i]
        self.i = 0
        self.j = 0

    def crypt(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        for idx, b in enumerate(data):
            self.i = (self.i + 1) & 0xFF
            self.j = (self.j + self.S[self.i]) & 0xFF
            self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
            out[idx] = b ^ self.S[(self.S[self.i] + self.S[self.j]) & 0xFF]
        return bytes(out)


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def derive_rc4_key(ssecurity_b64: str, nonce_b64: str) -> str:
    combined = _b64d(ssecurity_b64) + _b64d(nonce_b64)
    return base64.b64encode(hashlib.sha256(combined).digest()).decode()


def generate_nonce(time_diff_ms: int = 0) -> str:
    random_part = secrets.token_bytes(8)
    time_minutes = int((int(time.time() * 1000) + time_diff_ms) / 60000)
    time_part = struct.pack(">i", time_minutes)
    return base64.b64encode(random_part + time_part).decode()


def _sha1_sign(method: str, url_path: str, params: dict, rc4_key_b64: str) -> str:
    parts: list[str] = []
    if method:
        parts.append(method.upper())
    if url_path:
        parts.append(url_path)
    if params:
        for k in sorted(params.keys()):
            parts.append(f"{k}={params[k]}")
    parts.append(rc4_key_b64)
    signing_string = "&".join(parts)
    digest = hashlib.sha1(signing_string.encode("utf-8")).digest()
    return base64.b64encode(digest).decode()


def _make_rc4(key_b64: str) -> RC4:
    rc4 = RC4(_b64d(key_b64))
    rc4.crypt(b"\x00" * 1024)
    return rc4


def mi_encrypt_params(method: str, signing_path: str, params: dict, nonce_b64: str, ssecurity_b64: str) -> dict:
    """加密请求参数：RC4 加密 + SHA1 签名（i42.c 模式）。"""
    rc4_key_b64 = derive_rc4_key(ssecurity_b64, nonce_b64)
    plaintext_sorted = dict(sorted(params.items()))
    rc4_hash = _sha1_sign(method, signing_path, plaintext_sorted, rc4_key_b64)
    plaintext_sorted["rc4_hash__"] = rc4_hash
    plaintext_sorted = dict(sorted(plaintext_sorted.items()))
    rc4 = _make_rc4(rc4_key_b64)
    encrypted_sorted: dict[str, str] = {}
    for k in sorted(plaintext_sorted.keys()):
        encrypted_bytes = rc4.crypt(plaintext_sorted[k].encode("utf-8"))
        encrypted_sorted[k] = base64.b64encode(encrypted_bytes).decode()
    signature = _sha1_sign(method, signing_path, encrypted_sorted, rc4_key_b64)
    output = dict(encrypted_sorted)
    output["signature"] = signature
    output["_nonce"] = nonce_b64
    return output


def mi_decrypt_response(body_b64: str, nonce_b64: str, ssecurity_b64: str) -> str:
    rc4_key_b64 = derive_rc4_key(ssecurity_b64, nonce_b64)
    rc4 = _make_rc4(rc4_key_b64)
    return rc4.crypt(base64.b64decode(body_b64)).decode("utf-8")


def _parse_xiaomi_json(text: str) -> dict:
    prefix = "&&&START&&&"
    if text.startswith(prefix):
        text = text[len(prefix):]
    return json.loads(text)


# ============================ 常量 ============================

SID = "miothealth"
def _get_device_id():
    """设备指纹（免 2FA 关键）。开源版：首次运行随机生成并持久化；
    亦可手动改为固定值以保持指纹稳定（换指纹可能触发短信验证）。"""
    try:
        p = os.path.join(BASE_DIR, "device_id.json")
        if os.path.exists(p):
            return json.load(open(p, encoding="utf-8")).get("id", "")
    except OSError:
        pass
    import uuid
    did = "wb_" + str(uuid.uuid4())
    try:
        with open(os.path.join(BASE_DIR, "device_id.json"), "w", encoding="utf-8") as f:
            json.dump({"id": did}, f)
    except OSError:
        pass
    return did


DEVICE_ID = _get_device_id()   # 固定设备指纹（免 2FA 关键，对任意账号通用）
SERVICE_LOGIN = "https://account.xiaomi.com/pass/serviceLogin"
SERVICE_LOGIN_AUTH2 = "https://account.xiaomi.com/pass/serviceLoginAuth2"
LOGIN_UA = ("Mozilla/5.0 (Linux; Android 12; Pixel 4 Build/SP1A.210812.016.C1; wv) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/131.0.6778.200 Mobile Safari/537.36")
API_BASE = "https://hlth.io.mi.com"
API_UA = "Android-16-3.55.0i-google-Pixel 4"
API_REGION = "cn"

_lock = threading.Lock()
_state: dict = {}          # {ssecurity, service_token, uid, cuid, user, device, login_time}


# ============================ 会话持久化（首次登录后免密，退出才清除） ============================

def _save_session():
    """把会话令牌写入 session.json（仅令牌与账号信息，不含密码）。"""
    with _lock:
        try:
            tmp = SESSION_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(_state, f, ensure_ascii=False)
            os.replace(tmp, SESSION_FILE)
        except OSError:
            pass


def _clear_session():
    with _lock:
        _state.clear()
        try:
            if os.path.exists(SESSION_FILE):
                os.remove(SESSION_FILE)
        except OSError:
            pass


def _load_session() -> bool:
    """启动/刷新时恢复会话；令牌失效则清除并返回 False。"""
    with _lock:
        if _state:
            return True
        if not os.path.exists(SESSION_FILE):
            return False
        try:
            with open(SESSION_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return False
        if not all(k in data for k in ("ssecurity", "service_token", "uid", "cuid")):
            return False
        _state.update(data)
    # 轻量验证令牌是否仍有效（取设备列表）
    try:
        _api(_state, "POST", "/app/v1/source/get_source_list", {"page_size": 1, "status": 1})
        return True
    except ApiError:
        _clear_session()
        return False


# ============================ 小米账号登录（通用） ============================

def _login(username: str, password: str) -> dict:
    """任意小米账号密码登录。返回会话密钥；需要验证码/异常时抛错并给出原因。"""
    s = requests.Session()
    s.headers.update({"User-Agent": LOGIN_UA, "Content-Type": "application/x-www-form-urlencoded"})
    s.cookies.set("deviceId", DEVICE_ID, domain=".account.xiaomi.com")

    r = s.get(SERVICE_LOGIN, params={"_json": "true", "sid": SID, "_locale": "en_US"},
              cookies={"userId": username}, timeout=15)
    d1 = _parse_xiaomi_json(r.text)

    r2 = s.post(SERVICE_LOGIN_AUTH2,
                data={"qs": d1.get("qs", ""), "callback": d1.get("callback", ""), "_json": "true",
                      "_sign": d1.get("_sign", ""), "user": username,
                      "hash": hashlib.md5(password.encode()).hexdigest().upper(),
                      "sid": SID, "_locale": "en_US"},
                allow_redirects=False, timeout=15)
    d2 = _parse_xiaomi_json(r2.text)
    ssec = d2.get("ssecurity")
    loc2 = d2.get("location")
    if not (ssec and loc2):
        code = d2.get("code")
        desc = d2.get("description") or d2.get("info") or ""
        if str(code) in ("87001", "87002", "70016", "70002"):
            raise LoginError("账号或密码错误")
        if "captcha" in json.dumps(d2, ensure_ascii=False).lower():
            raise LoginError("需要图形验证码，请先在小米账号官网或小米运动 App 登录一次后重试")
        raise LoginError(f"登录被拒绝（code={code}）: {desc}")

    r3 = s.get(loc2, allow_redirects=False, timeout=20)   # STS：返回 userId/cUserId/serviceToken

    def _sts_cookie(name: str):
        # 精确取 sts-hlth.io.mi.com 域 cookie，避免多域同名冲突
        for c in s.cookies:
            if c.name == name and "sts-hlth" in (c.domain or ""):
                return c.value
        return None

    svc = _sts_cookie("serviceToken") or _sts_cookie("yetAnotherServiceToken")
    uid = _sts_cookie("userId")        # 从 STS 动态取，支持任意账号
    cuid = _sts_cookie("cUserId")
    if not (svc and uid and cuid):
        raise LoginError("登录会话未建立（STS 未返回令牌），可能是新设备需要短信验证，请在小米运动 App 中登录一次后再试")
    return {"ssecurity": ssec, "service_token": svc, "uid": uid, "cuid": cuid}


class LoginError(Exception):
    pass


class ApiError(Exception):
    def __init__(self, code, message):
        super().__init__(f"API error code={code} msg={message}")
        self.code = code
        self.message = message


def _api(state: dict, method: str, path: str, params: dict | None = None):
    """加密签名调用小米健康 API（GET 参数放 URL，POST 放 body）。"""
    if params is None:
        params = {}
    str_params = {"data": json.dumps(params, separators=(",", ":"))}
    nonce = generate_nonce(0)
    enc = mi_encrypt_params(method, path, str_params, nonce, state["ssecurity"])
    cookies = {"cUserId": state["cuid"], "serviceToken": state["service_token"],
               "userId": state["uid"], "locale": "en_us"}
    headers = {"User-Agent": API_UA, "region_tag": API_REGION,
               "Content-Type": "application/x-www-form-urlencoded"}
    url = API_BASE + path
    if method.upper() == "GET":
        resp = requests.get(url, params=enc, cookies=cookies, headers=headers, timeout=30)
    else:
        resp = requests.post(url, data=enc, cookies=cookies, headers=headers, timeout=30)
    if resp.status_code != 200:
        raise ApiError(-1, f"HTTP {resp.status_code} {resp.text[:120]}")
    text = resp.text
    if text.startswith("&&&START&&&"):
        text = text[len("&&&START&&&"):]
    try:
        dec = mi_decrypt_response(text, nonce, state["ssecurity"])
        obj = json.loads(dec)
    except Exception as e:
        raise ApiError(-2, f"解密失败 {type(e).__name__}: {str(e)[:120]}")
    if obj.get("code") != 0:
        raise ApiError(obj.get("code"), obj.get("message", ""))
    return obj.get("result")


def _ts_range(days: int):
    from datetime import datetime, timezone, timedelta
    tz = timezone(timedelta(hours=8))
    now = datetime.now(tz)
    end_d = datetime(now.year, now.month, now.day, 23, 59, 59, tzinfo=tz)
    end = int(end_d.timestamp())
    start = end - 86400 * (days - 1)
    return start, end


# ============================ 数据组装 ============================

AGG_KEYS = ["steps", "sleep", "heart_rate", "spo2", "calories", "intensity", "valid_stand"]


def _fetch_all(state: dict, days: int) -> dict:
    start, end = _ts_range(days)
    uid = state["uid"]
    daily = {}
    for key in AGG_KEYS:
        try:
            res = _api(state, "GET", "/app/v1/data/get_aggregated_fitness_data_by_time",
                       {"relative_uid": uid, "key": key, "tag": "daily_report",
                        "start_time": start, "end_time": end, "limit": max(days, 30)})
            lst = res.get("data_list", []) if isinstance(res, dict) else res
            daily[key] = lst or []
        except ApiError as e:
            daily[key] = []
    return {"start": start, "end": end, "days": days, "daily": daily}


def _fetch_points(state: dict, days: int, keys=("heart_rate", "spo2", "stress")) -> dict:
    end = _ts_range(1)[1]
    out = {}
    for key in keys:
        bucket = []
        for d in range(days):
            s0 = end - 86400 * d
            e0 = s0 + 86400
            try:
                res = _api(state, "GET", "/app/v1/data/get_fitness_data_by_time",
                           {"relative_uid": state["uid"], "key": key,
                            "start_time": s0, "end_time": e0, "limit": 1440})
                lst = res.get("data_list", []) if isinstance(res, dict) else res
                if lst:
                    bucket.extend(lst)
            except ApiError:
                pass
        out[key] = bucket
    return out


def _fetch_workouts(state: dict) -> list:
    wm, workouts = 0, []
    while True:
        try:
            res = _api(state, "GET", "/app/v1/data/get_sport_records_by_watermark",
                       {"relative_uid": state["uid"], "watermark": wm, "limit": 50})
            lst = res.get("sport_records", []) if isinstance(res, dict) else res
            if not lst:
                break
            workouts.extend(lst)
            has_more = res.get("has_more", False) if isinstance(res, dict) else False
            new_wm = max((int(x.get("watermark", 0)) for x in lst if x.get("watermark")), default=0)
            if not has_more or new_wm <= wm:
                break
            wm = new_wm
        except ApiError:
            break
    return workouts


def _fetch_device(state: dict) -> dict | None:
    try:
        res = _api(state, "POST", "/app/v1/source/get_source_list", {"page_size": 50, "status": 1})
        lst = res.get("list", []) if isinstance(res, dict) else res
        if lst:
            d = lst[0]
            detail = d.get("detail", {}) or {}
            return {"name": d.get("name", "").strip(), "model": d.get("model", ""),
                    "mac": detail.get("mac", ""), "fw": detail.get("fw_ver", ""),
                    "sn": detail.get("sn", ""), "bind_time": detail.get("last_bind_time", "")}
    except ApiError:
        pass
    return None


def _fmt_date(unix_sec: int) -> str:
    import datetime
    return datetime.datetime.fromtimestamp(int(unix_sec), datetime.timezone(datetime.timedelta(hours=8))).strftime("%Y-%m-%d")


def _parse_val(rec: dict):
    try:
        return json.loads(rec.get("value", "{}"))
    except Exception:
        return {}


def _build_overview(state: dict, days: int):
    data = _fetch_all(state, days)
    daily = data["daily"]
    # 展开每日
    rows = []
    for key in AGG_KEYS:
        for rec in daily.get(key, []):
            t = int(rec.get("time", 0))
            v = _parse_val(rec)
            row = next((r for r in rows if r["time"] == t), None)
            if row is None:
                row = {"time": t, "date": _fmt_date(t)}
                rows.append(row)
            if key == "steps":
                row.update(steps=v.get("steps"), distance=v.get("distance"),
                           calories_activity=v.get("calories"))
            elif key == "calories":
                row["calories_total"] = v.get("calories")
            elif key == "valid_stand":
                row["stand"] = v.get("count")
            elif key == "sleep":
                row.update(sleep_duration=v.get("total_duration"), sleep_score=v.get("sleep_score"),
                           sleep_deep=v.get("sleep_deep_duration"), sleep_light=v.get("sleep_light_duration"),
                           sleep_awake=v.get("sleep_awake_duration"), sleep_stage=v.get("sleep_stage"))
            elif key == "heart_rate":
                row.update(avg_hr=v.get("avg_hr"), avg_rhr=v.get("avg_rhr"),
                           latest_hr=(v.get("latest_hr") or {}).get("bpm"))
            elif key == "spo2":
                row.update(avg_spo2=v.get("avg_spo2"), max_spo2=v.get("max_spo2"),
                           min_spo2=v.get("min_spo2"))
            elif key == "intensity":
                row["intensity_min"] = v.get("duration")
    rows.sort(key=lambda r: r["time"])
    # 汇总
    days_with_steps = sum(1 for r in rows if r.get("steps") is not None)
    total_steps = sum(r.get("steps") or 0 for r in rows)
    total_distance = sum(r.get("distance") or 0 for r in rows)
    total_calories = sum(r.get("calories_total") or 0 for r in rows)
    sleeps = [r for r in rows if r.get("sleep_score") is not None]
    avg_sleep_score = round(sum(r["sleep_score"] for r in sleeps) / len(sleeps)) if sleeps else None
    hrs = [r for r in rows if r.get("avg_rhr") is not None]
    latest_rhr = hrs[-1]["avg_rhr"] if hrs else None
    spo2s = [r for r in rows if r.get("avg_spo2") is not None]
    latest_spo2 = spo2s[-1]["avg_spo2"] if spo2s else None
    workouts = _fetch_workouts(state)
    summary = {
        "days_with_steps": days_with_steps, "total_steps": total_steps,
        "total_distance_m": total_distance, "total_calories": total_calories,
        "avg_sleep_score": avg_sleep_score, "latest_rhr": latest_rhr, "latest_spo2": latest_spo2,
        "workout_count": len(workouts),
    }
    return {"summary": summary, "rows": rows, "workouts": workouts, "range": [data["start"], data["end"]], "days": days}


# ============================ Flask 路由 ============================

def _ok(data=None):
    return jsonify({"ok": True, "data": data})


def _err(message, code=400):
    return jsonify({"ok": False, "error": message}), code


@app.after_request
def _no_cache(resp):
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/")
def _index():
    return send_from_directory(RES_DIR, "index.html")


@app.route("/api/status")
def _status():
    if not _state and not _load_session():
        return _ok({"logged_in": False, "app": APP_NAME, "version": APP_VERSION})
    with _lock:
        return _ok({"logged_in": True, "user": _state.get("user"),
                    "device": _state.get("device"), "login_time": _state.get("login_time"),
                    "restored": True, "app": APP_NAME, "version": APP_VERSION})


@app.route("/api/login", methods=["POST"])
def _login_route():
    body = request.get_json(force=True, silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not username or not password:
        return _err("请输入账号和密码")
    if len(password) < 6:
        return _err("密码长度不正确")
    try:
        sess = _login(username, password)
    except LoginError as e:
        return _err(str(e), 401)
    except requests.RequestException as e:
        return _err(f"网络错误: {type(e).__name__}", 502)
    device = _fetch_device(sess)
    with _lock:
        _state.clear()
        _state.update(sess)
        _state["user"] = username
        _state["device"] = device
        _state["login_time"] = int(time.time())
    _save_session()   # 持久化：之后启动服务自动恢复登录态
    return _ok({"user": username, "device": device})


@app.route("/api/logout", methods=["POST"])
def _logout_route():
    _clear_session()   # 退出：清除会话并删除 session.json
    return _ok()


def _require_state():
    if not _state and not _load_session():
        raise ApiError(-1, "未登录")
    with _lock:
        return dict(_state)


def _api_err_response(e: ApiError):
    """token 失效（HTTP 401）时清除会话，前端据此回登录屏。"""
    if e.code == -1 or "401" in str(e.message):
        _clear_session()
        return _err("登录已失效，请重新登录", 401)
    return _err(e.message, 500)


@app.route("/api/overview")
def _overview_route():
    try:
        state = _require_state()
        days = min(max(int(request.args.get("days", 30)), 1), 365)
        data = _build_overview(state, days)
        return _ok(data)
    except ApiError as e:
        return _err(e.message, 401 if e.code == -1 else 500)


@app.route("/api/points")
def _points_route():
    try:
        state = _require_state()
        days = min(max(int(request.args.get("days", 3)), 1), 90)
        keys = [k for k in ("heart_rate", "spo2", "stress") if request.args.get(k, "1") == "1"]
        pts = _fetch_points(state, days, tuple(keys))
        return _ok({"days": days, "points": pts})
    except ApiError as e:
        return _err(e.message, 401 if e.code == -1 else 500)


@app.route("/api/workouts")
def _workouts_route():
    try:
        state = _require_state()
        return _ok({"workouts": _fetch_workouts(state)})
    except ApiError as e:
        return _err(e.message, 401 if e.code == -1 else 500)


def _csv_rows(rows: list[dict], cols: list[str]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in rows:
        w.writerow([r.get(c, "") for c in cols])
    return buf.getvalue()


@app.route("/api/export")
def _export_route():
    try:
        state = _require_state()
        days = min(max(int(request.args.get("days", 30)), 1), 365)
        metrics = (request.args.get("metrics") or "daily,points,workouts").split(",")
        fmt = request.args.get("format", "csv")
        data = _build_overview(state, days)
        pts = _fetch_points(state, min(days, 90)) if "points" in metrics else {}
        workouts = data["workouts"] if "workouts" in metrics else []

        if fmt == "json":
            payload = {
                "user": state.get("user"), "uid": state.get("uid"),
                "device": state.get("device"), "range": data["range"], "days": days,
                "daily": data["rows"], "points": pts, "workouts": workouts,
            }
            name = f"mihealth_export_{time.strftime('%Y%m%d')}.json"
            return Response(json.dumps(payload, ensure_ascii=False, indent=1),
                            mimetype="application/json",
                            headers={"Content-Disposition": f"attachment; filename={name}"})

        parts: list[tuple[str, str]] = []
        if "daily" in metrics and data["rows"]:
            cols = ["date", "steps", "distance_m", "calories_activity", "calories_total", "stand",
                    "sleep_duration_min", "sleep_score", "sleep_deep_min", "sleep_light_min",
                    "avg_hr", "avg_rhr", "avg_spo2", "max_spo2", "min_spo2", "intensity_min"]
            rows = []
            for r in data["rows"]:
                rows.append({"date": r.get("date"), "steps": r.get("steps"),
                             "distance_m": r.get("distance"), "calories_activity": r.get("calories_activity"),
                             "calories_total": r.get("calories_total"), "stand": r.get("stand"),
                             "sleep_duration_min": r.get("sleep_duration"),
                             "sleep_score": r.get("sleep_score"), "sleep_deep_min": r.get("sleep_deep"),
                             "sleep_light_min": r.get("sleep_light"), "avg_hr": r.get("avg_hr"),
                             "avg_rhr": r.get("avg_rhr"), "avg_spo2": r.get("avg_spo2"),
                             "max_spo2": r.get("max_spo2"), "min_spo2": r.get("min_spo2"),
                             "intensity_min": r.get("intensity_min")})
            parts.append(("daily.csv", _csv_rows(rows, cols)))
        for key, label in (("heart_rate", "bpm"), ("spo2", "spo2"), ("stress", "stress")):
            if "points" in metrics and pts.get(key):
                rows = [{"time": _fmt_date(r["time"]) + " " + time.strftime("%H:%M", time.localtime(r["time"])),
                         "timestamp": r["time"], label: (_parse_val(r).get(label) or "")} for r in pts[key]]
                parts.append((f"points_{key}.csv", _csv_rows(rows, ["time", "timestamp", label])))
        if "workouts" in metrics and workouts:
            rows = []
            for w in workouts:
                v = _parse_val(w)
                rows.append({"type": w.get("key", w.get("category", "")),
                             "start_time": _fmt_date(w.get("time", 0)),
                             "duration_min": round((v.get("duration") or 0) / 60, 1),
                             "distance_m": v.get("distance"), "calories": v.get("calories"),
                             "avg_hr": v.get("avg_hrm"), "max_hr": v.get("max_hrm")})
            parts.append(("workouts.csv", _csv_rows(rows, ["type", "start_time", "duration_min", "distance_m", "calories", "avg_hr", "max_hr"])))

        if not parts:
            return _err("没有可导出的数据", 404)
        if len(parts) == 1:
            fname = f"mihealth_{time.strftime('%Y%m%d')}_{parts[0][0]}"
            content = parts[0][1]
        else:
            import zipfile
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                for fn, c in parts:
                    z.writestr(fn, c)
            fname = f"mihealth_export_{time.strftime('%Y%m%d')}.zip"
            content = buf.getvalue()

        # save 模式：写入 数据/导出/ 并返回保存路径（客户端体验，不依赖浏览器下载）
        if request.args.get("save", "1") == "1":
            try:
                path = os.path.join(EXPORT_DIR, fname)
                with open(path, "wb") as f:
                    f.write(content if isinstance(content, bytes) else content.encode("utf-8"))
                return _ok({"saved": True, "path": path, "file": fname})
            except OSError as e:
                return _err(f"导出写入失败: {e}", 500)
        if isinstance(content, str):
            return Response(content, mimetype="text/csv; charset=utf-8",
                            headers={"Content-Disposition": f"attachment; filename={fname}"})
        return Response(content, mimetype="application/zip",
                        headers={"Content-Disposition": f"attachment; filename={fname}"})
    except ApiError as e:
        return _err(e.message, 401 if e.code == -1 else 500)


# ============================ 客户端启动 ============================

def _find_free_port(preferred: int = 8000) -> int:
    """端口占用自检：preferred 被占则自动递增寻找空闲端口。"""
    import socket
    for p in range(preferred, preferred + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    return preferred


def _net_ok() -> bool:
    """网络可达性自检：小米健康服务器是否可达。"""
    try:
        r = requests.get(API_BASE, timeout=6)
        return True
    except requests.RequestException:
        return False


def _log(msg: str):
    try:
        with open(os.path.join(LOG_DIR, "startup.log"), "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except OSError:
        pass
    print(msg, flush=True)


def main():
    args = sys.argv[1:]
    web_only = "--web-only" in args          # 强制浏览器模式（网页版）
    port = _find_free_port(int(os.environ.get("PORT", "8000")))

    _log("=" * 50)
    _log(f"{APP_NAME} {APP_VERSION} 启动")
    _log(f"模式: {'网页版(浏览器)' if web_only else '客户端(桌面窗口)'}  端口: {port}")
    _log(f"数据目录: {BASE_DIR}")
    _log("环境自检: 依赖 OK")

    # 网络自检（后台，不阻塞启动）
    def _net_check():
        ok = _net_ok()
        _log(f"环境自检: 小米服务器 {'可达' if ok else '不可达(登录/数据需联网)'}")
    threading.Thread(target=_net_check, daemon=True).start()

    # 启动本地服务（后台线程）
    def _serve():
        app.run(host="127.0.0.1", port=port, debug=False, threaded=True, use_reloader=False)
    server_thread = threading.Thread(target=_serve, daemon=True)
    server_thread.start()
    _log(f"本地服务已启动: http://127.0.0.1:{port}")

    url = f"http://127.0.0.1:{port}"
    if not web_only:
        try:
            import webview  # pywebview：桌面窗口（脱离浏览器）
            window = webview.create_window(
                f"{APP_NAME} v{APP_VERSION}", url,
                width=1240, height=820, min_size=(980, 680),
                background_color="#F5F5F7")
            _log("桌面窗口已创建（pywebview）")
            webview.start()
            _log("窗口已关闭，客户端退出")
            return
        except Exception as e:
            _log(f"桌面窗口不可用，降级为浏览器模式: {type(e).__name__}: {e}")

    _log("浏览器模式：自动打开页面")
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
