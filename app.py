# -*- coding: utf-8 -*-
# ==============================================================
# LP-TOOL KEY SERVER — Render.com Edition
# Full: Key Auth + Bảo Trì + Kích Hoạt + Thông Báo + Update Tool
# Admin: Thiên Phú - Minh Lâm - Duy
# ==============================================================

from __future__ import annotations
import os, sqlite3, time, random, json
from functools import wraps
from flask import Flask, request, jsonify, render_template_string

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "LpToolAdmin@2026")
DB_PATH = os.environ.get("DB_PATH", "keys.db")
app = Flask(__name__)

# ==============================================================
# STATE
# ==============================================================
MAINTENANCE = {"enabled": False, "content": "", "enabled_at": None}
ACTIVATION = {
    "required": False, "activated": False,
    "message": "Vui lòng nhấn KÍCH HOẠT để bắt đầu sử dụng tool",
    "activated_at": None, "activated_by": None,
}
ANNOUNCEMENT = {
    "enabled": False, "content": "",
    "updated_at": None, "updated_by": None,
}

# ==============================================================
# DATABASE
# ==============================================================
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL, type TEXT NOT NULL,
        duration_hours INTEGER NOT NULL,
        created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        active INTEGER DEFAULT 1, created_by TEXT, note TEXT,
        device_id TEXT, device_fingerprint TEXT, last_ip TEXT,
        last_seen INTEGER, first_used_at INTEGER,
        use_count INTEGER DEFAULT 0, banned_reason TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT,
        action TEXT NOT NULL, device_id TEXT, ip TEXT,
        info TEXT, created_at INTEGER NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS tool_code (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        version TEXT NOT NULL, code TEXT NOT NULL,
        uploaded_at INTEGER NOT NULL, uploaded_by TEXT,
        note TEXT, is_active INTEGER DEFAULT 1)""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_keys_key ON keys(key)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_logs_key ON logs(key)")
    conn.commit(); conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def log_action(key, action, device_id=None, ip=None, info=None):
    try:
        conn = get_db(); c = conn.cursor()
        c.execute("INSERT INTO logs (key, action, device_id, ip, info, created_at) VALUES (?,?,?,?,?,?)",
                  (key, action, device_id, ip, json.dumps(info or {}), int(time.time() * 1000)))
        conn.commit(); conn.close()
    except Exception as e:
        print(f"log_action: {e}")

# ==============================================================
# KEY GENERATOR
# ==============================================================
CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
def rand_str(n): return "".join(random.choice(CHARS) for _ in range(n))

def generate_key(kt):
    if kt == "VIP1":  return f"LPTOOL_VIP1_{rand_str(5)}_{rand_str(4)}_{rand_str(4)}"
    if kt == "VIP3":  return f"LPTOOL_VIP3_{rand_str(2)}_{rand_str(5)}_{rand_str(4)}_{rand_str(6)}"
    if kt == "SUPER": return f"LPTOOL_PRENIUM_{rand_str(5)}_{rand_str(5)}_{rand_str(4)}_{rand_str(3)}_{rand_str(3)}_{rand_str(3)}"
    if kt == "ADMIN":
        return (f"LPTOOL_ADMIN_{rand_str(6)}_{rand_str(7)}_{rand_str(3)}_{rand_str(5)}_"
                f"{rand_str(3)}_{rand_str(3)}_{rand_str(5)}_{rand_str(4)}_{rand_str(4)}_{rand_str(6)}")
    raise ValueError("Invalid")

def require_admin(f):
    @wraps(f)
    def wrapper(*a, **kw):
        auth = request.headers.get("Authorization", "")
        if auth.replace("Bearer ", "").strip() != ADMIN_SECRET:
            return jsonify({"ok": False, "error": "Unauthorized"}), 401
        return f(*a, **kw)
    return wrapper

# ==============================================================
# API: VALIDATE
# ==============================================================
@app.route("/api/validate", methods=["POST", "OPTIONS"])
def api_validate():
    if request.method == "OPTIONS": return "", 200
    data = request.get_json(silent=True) or {}
    key_str = (data.get("key") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    fp = data.get("fingerprint")
    ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr

    if not key_str or not device_id:
        return jsonify({"ok": False, "error": "Thiếu key/device_id"}), 400

    conn = get_db(); c = conn.cursor()
    row = c.execute("SELECT * FROM keys WHERE key=?", (key_str,)).fetchone()
    if not row:
        conn.close(); return jsonify({"ok": False, "error": "Key không tồn tại"}), 404

    row = dict(row); now = int(time.time() * 1000)

    if not row["active"]:
        conn.close(); log_action(key_str, "validate_fail_inactive", device_id, ip)
        return jsonify({"ok": False, "error": "Key đã bị thu hồi"}), 403

    if row["expires_at"] < now and row["type"] != "ADMIN":
        conn.close(); log_action(key_str, "validate_fail_expired", device_id, ip)
        return jsonify({"ok": False, "error": "Key đã hết hạn"}), 403

    if not row["device_id"]:
        c.execute("""UPDATE keys SET device_id=?, device_fingerprint=?, first_used_at=?,
                     last_seen=?, last_ip=?, use_count=1 WHERE id=?""",
                  (device_id, fp, now, now, ip, row["id"]))
        log_action(key_str, "bind_device", device_id, ip, {"fp": fp})
    elif row["device_id"] != device_id:
        conn.close(); log_action(key_str, "validate_fail_wrong_device", device_id, ip)
        return jsonify({"ok": False, "error": "Key đã kích hoạt trên thiết bị khác"}), 403
    else:
        c.execute("UPDATE keys SET last_seen=?, last_ip=?, use_count=use_count+1 WHERE id=?",
                  (now, ip, row["id"]))

    conn.commit(); log_action(key_str, "validate_ok", device_id, ip); conn.close()
    return jsonify({
        "ok": True, "key_type": row["type"],
        "duration_hours": row["duration_hours"],
        "expires_at": row["expires_at"],
        "is_admin": row["type"] == "ADMIN",
        "created_by": row["created_by"],
    })

# ==============================================================
# API: HEARTBEAT
# ==============================================================
@app.route("/api/heartbeat", methods=["POST", "OPTIONS"])
def api_heartbeat():
    if request.method == "OPTIONS": return "", 200
    data = request.get_json(silent=True) or {}
    key_str = (data.get("key") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    if not key_str or not device_id:
        return jsonify({"ok": False, "error": "Thiếu key/device_id"}), 400

    conn = get_db(); c = conn.cursor()
    row = c.execute("SELECT * FROM keys WHERE key=?", (key_str,)).fetchone()
    if not row:
        conn.close(); return jsonify({"ok": False, "error": "Key không tồn tại"}), 404
    row = dict(row); now = int(time.time() * 1000)

    if not row["active"]:
        conn.close(); return jsonify({"ok": False, "error": "Key đã bị thu hồi"}), 403
    if row["expires_at"] < now and row["type"] != "ADMIN":
        conn.close(); return jsonify({"ok": False, "error": "Key đã hết hạn"}), 403
    if row["device_id"] and row["device_id"] != device_id:
        conn.close(); return jsonify({"ok": False, "error": "Key đang dùng thiết bị khác"}), 403

    ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr
    c.execute("UPDATE keys SET last_seen=?, last_ip=? WHERE id=?", (now, ip, row["id"]))
    conn.commit(); conn.close()
    return jsonify({"ok": True})

# ==============================================================
# API: CHECK STATUS
# ==============================================================
@app.route("/api/check_status", methods=["GET", "POST", "OPTIONS"])
def api_check_status():
    if request.method == "OPTIONS": return "", 200
    return jsonify({
        "ok": True,
        "maintenance": MAINTENANCE["enabled"],
        "maintenance_content": MAINTENANCE["content"],
        "need_activation": ACTIVATION["required"],
        "activated": ACTIVATION["activated"],
        "activation_message": ACTIVATION["message"],
        # ⚡ THÔNG BÁO
        "announcement_enabled": ANNOUNCEMENT["enabled"],
        "announcement_content": ANNOUNCEMENT["content"],
        "announcement_updated_at": ANNOUNCEMENT["updated_at"],
        "ts": int(time.time() * 1000),
    })

# ==============================================================
# API: ACTIVATE
# ==============================================================
@app.route("/api/activate", methods=["POST", "OPTIONS"])
def api_activate():
    if request.method == "OPTIONS": return "", 200
    data = request.get_json(silent=True) or {}
    key_str = (data.get("key") or "").strip()
    device_id = (data.get("device_id") or "").strip()

    if not key_str:
        return jsonify({"ok": False, "error": "Thiếu key"}), 400

    conn = get_db(); c = conn.cursor()
    row = c.execute("SELECT * FROM keys WHERE key=?", (key_str,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"ok": False, "error": "Key không tồn tại"}), 404

    if not ACTIVATION["required"]:
        return jsonify({"ok": True, "message": "Không cần kích hoạt", "skip": True})

    ACTIVATION["activated"] = True
    ACTIVATION["activated_at"] = int(time.time() * 1000)
    ACTIVATION["activated_by"] = key_str
    log_action(key_str, "activation_confirmed", device_id)

    return jsonify({
        "ok": True, "message": "✅ Kích hoạt thành công!",
        "activated_at": ACTIVATION["activated_at"],
    })

# ==============================================================
# API: TOOL AUTO-UPDATE
# ==============================================================
@app.route("/tool/version", methods=["GET"])
def tool_version():
    try:
        conn = get_db(); c = conn.cursor()
        row = c.execute(
            "SELECT version, uploaded_at FROM tool_code WHERE is_active=1 ORDER BY id DESC LIMIT 1"
        ).fetchone()
        conn.close()
        if row:
            return jsonify({"ok": True, "version": row["version"], "uploaded_at": row["uploaded_at"]})
        return jsonify({"ok": False, "error": "Chưa có tool"}), 404
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.route("/tool/download", methods=["GET"])
def tool_download():
    try:
        conn = get_db(); c = conn.cursor()
        row = c.execute(
            "SELECT code, version FROM tool_code WHERE is_active=1 ORDER BY id DESC LIMIT 1"
        ).fetchone()
        conn.close()
        if row:
            return row["code"], 200, {
                "Content-Type": "text/plain; charset=utf-8",
                "Cache-Control": "no-cache",
                "X-Version": row["version"],
            }
        return "Tool not found", 404
    except Exception as e:
        return str(e), 500

# ==============================================================
# API: ADMIN
# ==============================================================
@app.route("/api/admin", methods=["POST", "OPTIONS"])
@require_admin
def api_admin():
    if request.method == "OPTIONS": return "", 200
    data = request.get_json(silent=True) or {}
    action = data.get("action")

    conn = get_db(); c = conn.cursor()

    # ============ CREATE KEY ============
    if action == "create":
        kt = data.get("type", "VIP1")
        dh = int(data.get("duration_hours", 24))
        note = data.get("note", ""); cb = data.get("created_by", "admin")
        if kt not in ("VIP1", "VIP3", "SUPER", "ADMIN"):
            conn.close(); return jsonify({"ok": False, "error": "Loại không hợp lệ"}), 400
        if kt == "ADMIN": dh = 36700 * 24
        key_str = generate_key(kt); now = int(time.time() * 1000)
        exp = now + dh * 3600 * 1000
        c.execute("""INSERT INTO keys (key,type,duration_hours,created_at,expires_at,active,created_by,note)
                     VALUES (?,?,?,?,?,1,?,?)""", (key_str, kt, dh, now, exp, cb, note))
        conn.commit()
        log_action(key_str, "create", None, None, {"type": kt, "dh": dh})
        conn.close()
        return jsonify({"ok": True, "key": key_str})

    # ============ LIST ============
    if action == "list":
        rows = c.execute("SELECT * FROM keys ORDER BY created_at DESC").fetchall()
        keys = [dict(r) for r in rows]; conn.close()
        return jsonify({"ok": True, "keys": keys, "total": len(keys)})

    # ============ REVOKE ============
    if action == "revoke":
        key_str = data.get("key"); reason = data.get("reason", "Admin revoked")
        c.execute("UPDATE keys SET active=0, banned_reason=? WHERE key=?", (reason, key_str))
        conn.commit(); log_action(key_str, "revoke", None, None, {"reason": reason})
        conn.close(); return jsonify({"ok": True})

    # ============ REACTIVATE ============
    if action == "reactivate":
        key_str = data.get("key")
        c.execute("UPDATE keys SET active=1, banned_reason=NULL WHERE key=?", (key_str,))
        conn.commit(); log_action(key_str, "reactivate")
        conn.close(); return jsonify({"ok": True})

    # ============ DELETE ============
    if action == "delete":
        key_str = data.get("key")
        c.execute("DELETE FROM keys WHERE key=?", (key_str,))
        conn.commit(); log_action(key_str, "delete")
        conn.close(); return jsonify({"ok": True})

    # ============ RESET DEVICE ============
    if action == "reset_device":
        key_str = data.get("key")
        c.execute("""UPDATE keys SET device_id=NULL, device_fingerprint=NULL,
                     first_used_at=NULL WHERE key=?""", (key_str,))
        conn.commit(); log_action(key_str, "reset_device")
        conn.close(); return jsonify({"ok": True})

    # ============ EXTEND ============
    if action == "extend":
        key_str = data.get("key"); hours = int(data.get("hours", 24))
        row = c.execute("SELECT * FROM keys WHERE key=?", (key_str,)).fetchone()
        if not row:
            conn.close(); return jsonify({"ok": False, "error": "Key không tồn tại"}), 404
        row = dict(row); now = int(time.time() * 1000)
        base = max(row["expires_at"], now)
        new_exp = base + hours * 3600 * 1000
        c.execute("UPDATE keys SET expires_at=?, active=1, duration_hours=duration_hours+? WHERE key=?",
                  (new_exp, hours, key_str))
        conn.commit(); log_action(key_str, "extend", None, None, {"hours": hours})
        conn.close(); return jsonify({"ok": True, "expires_at": new_exp})

    # ============ MAINTENANCE ============
    if action == "maintenance":
        enabled = bool(data.get("enabled", False))
        content = str(data.get("content", "")).strip()
        MAINTENANCE["enabled"] = enabled
        MAINTENANCE["content"] = content
        MAINTENANCE["enabled_at"] = int(time.time() * 1000) if enabled else None
        conn.close()
        log_action(None, "maintenance_" + ("on" if enabled else "off"),
                   None, None, {"content": content})
        return jsonify({"ok": True, "maintenance": MAINTENANCE})

    # ============ ACTIVATION ============
    if action == "activation":
        required = bool(data.get("required", False))
        message = str(data.get("message", "")).strip()
        reset = bool(data.get("reset", False))
        ACTIVATION["required"] = required
        if message: ACTIVATION["message"] = message
        if reset or not required:
            ACTIVATION["activated"] = False
            ACTIVATION["activated_at"] = None
            ACTIVATION["activated_by"] = None
        conn.close()
        log_action(None, "activation_" + ("on" if required else "off"),
                   None, None, {"msg": message})
        return jsonify({"ok": True, "activation": ACTIVATION})

    # ============ ANNOUNCEMENT ============
    if action == "announcement":
        enabled = bool(data.get("enabled", False))
        content = str(data.get("content", "")).strip()
        ANNOUNCEMENT["enabled"] = enabled
        ANNOUNCEMENT["content"] = content
        ANNOUNCEMENT["updated_at"] = int(time.time() * 1000)
        ANNOUNCEMENT["updated_by"] = "admin"
        conn.close()
        log_action(None, "announcement_" + ("on" if enabled else "off"),
                   None, None, {"content": content[:100]})
        return jsonify({"ok": True, "announcement": ANNOUNCEMENT})

    # ============ GET STATUS ============
    if action == "get_status":
        conn.close()
        return jsonify({
            "ok": True,
            "maintenance": MAINTENANCE,
            "activation": ACTIVATION,
            "announcement": ANNOUNCEMENT,
        })

    # ============ STATS ============
    if action == "stats":
        total = c.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
        now = int(time.time() * 1000)
        active = c.execute("SELECT COUNT(*) FROM keys WHERE active=1 AND (expires_at>? OR type='ADMIN')", (now,)).fetchone()[0]
        used = c.execute("SELECT COUNT(*) FROM keys WHERE device_id IS NOT NULL").fetchone()[0]
        revoked = c.execute("SELECT COUNT(*) FROM keys WHERE active=0").fetchone()[0]
        expired = c.execute("SELECT COUNT(*) FROM keys WHERE expires_at<? AND type!='ADMIN'", (now,)).fetchone()[0]
        conn.close()
        return jsonify({"ok": True, "stats": {
            "total": total, "active": active, "used": used,
            "revoked": revoked, "expired": expired,
        }})

    # ============ LOGS ============
    if action == "logs":
        rows = c.execute("SELECT * FROM logs ORDER BY created_at DESC LIMIT 200").fetchall()
        logs = []
        for r in rows:
            d = dict(r); d["ts"] = d.pop("created_at")
            try: d["info"] = json.loads(d.get("info") or "{}")
            except: d["info"] = {}
            logs.append(d)
        conn.close(); return jsonify({"ok": True, "logs": logs})

    # ============ UPLOAD TOOL ============
    if action == "upload_tool":
        version = str(data.get("version", "")).strip()
        code = str(data.get("code", ""))
        note = str(data.get("note", "")).strip()
        if not version or not code:
            conn.close(); return jsonify({"ok": False, "error": "Thiếu version/code"}), 400
        if len(code) < 5000:
            conn.close(); return jsonify({"ok": False, "error": "Code quá ngắn (<5KB)"}), 400
        try:
            compile(code, "tool.py", "exec")
        except SyntaxError as e:
            conn.close()
            return jsonify({"ok": False, "error": f"Code lỗi dòng {e.lineno}: {e.msg}"}), 400
        now_ms = int(time.time() * 1000)
        c.execute("UPDATE tool_code SET is_active=0")
        c.execute("""INSERT INTO tool_code (version, code, uploaded_at, uploaded_by, note, is_active)
                     VALUES (?,?,?,?,?,1)""",
                  (version, code, now_ms, "admin", note))
        conn.commit()
        log_action(None, "tool_upload", None, None, {"version": version, "size": len(code)})
        conn.close()
        return jsonify({"ok": True, "message": f"Đã upload v{version}",
                        "version": version, "size": len(code)})

    # ============ TOOL HISTORY ============
    if action == "tool_history":
        rows = c.execute("""SELECT id, version, uploaded_at, uploaded_by, note,
                            is_active, LENGTH(code) AS size
                            FROM tool_code ORDER BY id DESC LIMIT 20""").fetchall()
        items = [dict(r) for r in rows]
        conn.close()
        return jsonify({"ok": True, "items": items})

    # ============ DELETE TOOL ============
    if action == "delete_tool":
        tool_id = data.get("id")
        if not tool_id:
            conn.close(); return jsonify({"ok": False, "error": "Thiếu id"}), 400
        c.execute("DELETE FROM tool_code WHERE id=?", (int(tool_id),))
        conn.commit(); conn.close()
        log_action(None, "tool_delete", None, None, {"id": tool_id})
        return jsonify({"ok": True})

    conn.close()
    return jsonify({"ok": False, "error": "Action không hợp lệ"}), 400

# ==============================================================
# ADMIN HTML
# ==============================================================
ADMIN_HTML = r"""<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>⚡ LP-TOOL ADMIN ⚡</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:'Segoe UI',Roboto,sans-serif}
:root{--cyan:#00d4ff;--blue:#2563eb;--blue-light:#60a5fa;--green:#00e676;
--yellow:#ffd740;--red:#ff4d6d;--gray:#7a8ca3;--white:#eaf2ff}
body{background:radial-gradient(ellipse at top,#0a1a3a 0%,#050a14 60%);color:var(--white);min-height:100vh;padding:20px}
.container{max-width:1200px;margin:0 auto}
.header{text-align:center;margin-bottom:24px}
.logo{font-size:38px;font-weight:900;background:linear-gradient(135deg,var(--cyan),var(--blue-light),var(--cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:4px}
.subtitle{color:var(--gray);font-size:12px;letter-spacing:2px;text-transform:uppercase}
.card{background:linear-gradient(145deg,rgba(11,26,51,0.85),rgba(5,10,20,0.95));border:1px solid rgba(0,212,255,0.25);border-radius:16px;padding:24px;margin-bottom:20px;box-shadow:0 8px 40px rgba(0,0,0,0.5)}
.card-title{font-size:16px;color:var(--cyan);margin-bottom:16px;padding-bottom:10px;border-bottom:1px solid rgba(0,212,255,0.15);letter-spacing:1px;display:flex;align-items:center;gap:8px}
label{display:block;color:var(--gray);font-size:11px;margin-bottom:6px;text-transform:uppercase;font-weight:600}
input,select,textarea{width:100%;padding:12px 14px;background:rgba(5,10,20,0.8);border:1px solid rgba(0,212,255,0.25);border-radius:8px;color:var(--white);font-size:14px;outline:none;font-family:'Consolas',monospace}
input:focus,select:focus,textarea:focus{border-color:var(--cyan);box-shadow:0 0 0 3px rgba(0,212,255,0.15)}
.grid{display:grid;gap:12px}.grid-3{grid-template-columns:1fr 1fr 1fr}
@media(max-width:700px){.grid-3{grid-template-columns:1fr}}
.btn{padding:12px 20px;border:none;border-radius:8px;font-size:14px;font-weight:700;letter-spacing:1px;cursor:pointer;transition:all 0.2s;text-transform:uppercase}
.btn-primary{background:linear-gradient(135deg,var(--cyan),var(--blue));color:#050a14}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,212,255,0.55)}
.btn-danger{background:linear-gradient(135deg,var(--red),#b91c3c);color:white}
.btn-warn{background:linear-gradient(135deg,var(--yellow),#f59e0b);color:#050a14}
.btn-small{padding:6px 12px;font-size:11px}
.btn-row{display:flex;gap:8px;flex-wrap:wrap}
.key-item{background:rgba(5,10,20,0.6);border:1px solid rgba(0,212,255,0.15);border-radius:10px;padding:12px;margin-bottom:8px}
.key-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;flex-wrap:wrap;gap:6px}
.badge{padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700}
.badge-vip1{background:rgba(0,230,118,0.15);color:var(--green)}
.badge-vip3{background:rgba(96,165,250,0.15);color:var(--blue-light)}
.badge-super{background:rgba(255,215,64,0.15);color:var(--yellow)}
.badge-admin{background:rgba(255,77,109,0.15);color:var(--red)}
.badge-active{background:rgba(0,230,118,0.15);color:var(--green)}
.badge-revoked{background:rgba(255,77,109,0.15);color:var(--red)}
.badge-expired{background:rgba(122,140,163,0.15);color:var(--gray)}
.key-value{font-family:'Consolas',monospace;font-size:12px;color:var(--cyan);background:rgba(0,0,0,0.4);padding:8px 10px;border-radius:6px;word-break:break-all;user-select:all;margin:6px 0}
.key-meta{display:flex;gap:12px;font-size:11px;color:var(--gray);flex-wrap:wrap;margin-top:6px}
.key-meta span{color:var(--white);font-weight:600}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
@media(max-width:700px){.stats{grid-template-columns:1fr 1fr}}
.stat-item{background:rgba(0,212,255,0.05);border:1px solid rgba(0,212,255,0.15);border-radius:10px;padding:14px;text-align:center}
.stat-value{font-size:24px;font-weight:800;color:var(--cyan)}
.stat-label{font-size:11px;color:var(--gray);text-transform:uppercase;margin-top:4px}
.toast{position:fixed;top:20px;right:20px;padding:12px 20px;border-radius:10px;font-size:13px;font-weight:600;z-index:9999;opacity:0;transform:translateX(100%);transition:all 0.3s;max-width:320px}
.toast.show{opacity:1;transform:translateX(0)}
.toast-success{background:linear-gradient(135deg,#00e676,#00b050);color:#050a14}
.toast-error{background:linear-gradient(135deg,#ff4d6d,#b91c3c);color:white}
.login-screen{display:flex;align-items:center;justify-content:center;min-height:70vh}
.login-card{max-width:400px;width:100%}
.hidden{display:none!important}
.mt-10{margin-top:10px}
.filter-row{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}
.toggle-btn{padding:14px 20px;border:none;border-radius:10px;font-size:14px;font-weight:700;cursor:pointer;transition:all 0.2s;width:100%;margin-bottom:8px;text-transform:uppercase;letter-spacing:1px}
.toggle-on{background:linear-gradient(135deg,#ff4d6d,#b91c3c);color:white;box-shadow:0 4px 20px rgba(255,77,109,0.4)}
.toggle-off{background:linear-gradient(135deg,#00e676,#00b050);color:#050a14;box-shadow:0 4px 20px rgba(0,230,118,0.3)}
.status-pill{display:inline-block;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:700;margin-left:8px}
.status-pill.on{background:rgba(0,230,118,0.2);color:var(--green)}
.status-pill.off{background:rgba(122,140,163,0.2);color:var(--gray)}
.status-pill.warn{background:rgba(255,215,64,0.2);color:var(--yellow)}
</style></head><body><div class="container">

<div id="loginScreen" class="login-screen"><div class="card login-card">
<div class="header"><div class="logo">LP KEY</div>
<div class="subtitle">⚡ ADMIN PANEL ⚡</div></div>
<div class="grid"><div><label>🔑 Admin Secret</label>
<input type="password" id="adminSecret" placeholder="Nhập admin secret..."></div>
<button class="btn btn-primary" onclick="doLogin()">🚀 ĐĂNG NHẬP</button>
</div></div></div>

<div id="mainPanel" class="hidden">
<div class="header"><div class="logo">LP KEY ADMIN</div>
<div class="subtitle">⚡ RENDER + SQLITE ⚡</div></div>

<div class="card"><div class="card-title">📊 THỐNG KÊ</div>
<div class="stats">
<div class="stat-item"><div class="stat-value" id="statTotal">-</div><div class="stat-label">Tổng key</div></div>
<div class="stat-item"><div class="stat-value" id="statActive" style="color:var(--green)">-</div><div class="stat-label">Hoạt động</div></div>
<div class="stat-item"><div class="stat-value" id="statUsed" style="color:var(--cyan)">-</div><div class="stat-label">Đã dùng</div></div>
<div class="stat-item"><div class="stat-value" id="statRevoked" style="color:var(--red)">-</div><div class="stat-label">Thu hồi</div></div>
</div></div>

<div class="card">
<div class="card-title">🔧 BẢO TRÌ <span class="status-pill off" id="mtPill">OFF</span></div>
<div><label>Nội dung thông báo</label>
<textarea id="mtContent" rows="3" placeholder="Server đang nâng cấp, quay lại sau..."></textarea></div>
<button class="toggle-btn toggle-on" id="mtBtn" onclick="toggleMaintenance()">🔧 BẬT BẢO TRÌ</button>
<div style="font-size:11px;color:var(--gray);margin-top:8px">💡 Khi bật, tool đang chạy sẽ tự động thoát và hiện thông báo.</div>
</div>

<!-- ⚡ THÔNG BÁO MỚI -->
<div class="card">
<div class="card-title">📢 THÔNG BÁO <span class="status-pill off" id="anPill">OFF</span></div>
<div><label>Nội dung thông báo cho user</label>
<textarea id="anContent" rows="3" placeholder="VD: Bảo trì lúc 20h tối nay, quay lại sau!"></textarea></div>
<button class="toggle-btn toggle-on" id="anBtn" onclick="toggleAnnouncement()">📢 BẬT THÔNG BÁO</button>
<div style="font-size:11px;color:var(--gray);margin-top:8px">💡 Khi bật, tool của user sẽ hiện thông báo này ngay.</div>
</div>

<div class="card">
<div class="card-title">⚡ YÊU CẦU KÍCH HOẠT <span class="status-pill off" id="acPill">OFF</span></div>
<div><label>Nội dung yêu cầu user</label>
<input type="text" id="acMessage" value="Vui lòng nhấn KÍCH HOẠT để bắt đầu sử dụng tool"></div>
<button class="toggle-btn toggle-on" id="acBtn" onclick="toggleActivation()">⚡ BẬT YÊU CẦU KÍCH HOẠT</button>
</div>

<div class="card">
<div class="card-title">🚀 UPDATE TOOL <span class="status-pill off" id="toolPill">—</span></div>
<div style="display:grid;grid-template-columns:1fr 2fr;gap:8px;margin-bottom:8px">
<div><label>Version</label><input type="text" id="toolVersion" placeholder="1.0.1"></div>
<div><label>Ghi chú</label><input type="text" id="toolNote" placeholder="VD: fix lỗi AI"></div>
</div>
<div><label>Code tool</label>
<textarea id="toolCode" rows="10" placeholder="Paste toàn bộ plptoolv4.py..." style="font-family:monospace;font-size:11px"></textarea></div>
<div class="btn-row mt-10">
<button class="btn btn-primary" onclick="uploadTool()">🚀 UPLOAD</button>
<button class="btn btn-warn" onclick="loadToolHistory()">📜 Lịch sử</button>
</div>
<div id="toolHistory" class="mt-10" style="max-height:250px;overflow-y:auto"></div>
</div>

<div class="card"><div class="card-title">🎁 TẠO KEY MỚI</div>
<div class="grid grid-3">
<div><label>Loại key</label><select id="newType">
<option value="VIP1">🔓 VIP 1</option><option value="VIP3">🔐 VIP 3</option>
<option value="SUPER">👑 SUPER</option><option value="ADMIN">⚡ ADMIN</option>
</select></div>
<div><label>Thời hạn</label><select id="newDuration">
<option value="24">1 ngày</option><option value="72">3 ngày</option>
<option value="168">1 tuần</option><option value="720">1 tháng</option>
<option value="880800">Vĩnh viễn</option></select></div>
<div><label>Ghi chú</label><input type="text" id="newNote" placeholder="VD: khách A"></div>
</div>
<button class="btn btn-primary mt-10" onclick="createKey()">⚡ TẠO KEY</button>
<div id="newKeyResult" class="hidden mt-10">
<div class="key-value" id="newKeyValue"></div>
<div class="btn-row mt-10">
<button class="btn btn-primary btn-small" onclick="copyKey()">📋 Copy</button>
<button class="btn btn-danger btn-small" onclick="hideNewKey()">✖ Đóng</button>
</div></div></div>

<div class="card"><div class="card-title">📋 DANH SÁCH KEY
<button class="btn btn-primary btn-small" style="margin-left:auto" onclick="loadKeys()">🔄 Refresh</button></div>
<div class="filter-row">
<input type="text" id="filterText" placeholder="🔍 Tìm key..." style="flex:1;min-width:200px" oninput="renderKeys()">
<select id="filterStatus" onchange="renderKeys()" style="width:auto">
<option value="all">Tất cả</option><option value="active">Hoạt động</option>
<option value="used">Đã dùng</option><option value="expired">Hết hạn</option>
<option value="revoked">Thu hồi</option></select>
</div>
<div id="keysList"></div></div>

<div class="card"><div class="card-title">📜 NHẬT KÝ
<button class="btn btn-primary btn-small" style="margin-left:auto" onclick="loadLogs()">🔄 Refresh</button></div>
<div id="logsList" style="max-height:400px;overflow-y:auto"></div></div>

<div class="card" style="text-align:center">
<button class="btn btn-danger" onclick="doLogout()">🚪 ĐĂNG XUẤT</button></div>
</div></div>

<div id="toast" class="toast"></div>
<script>
const API_BASE = window.location.origin;
let adminSecret = '', cachedKeys = [], lastKey = null;
let currentMaintenance = false, currentActivation = false, currentAnnouncement = false;

function toast(msg, type='success'){
  const t = document.getElementById('toast');
  t.textContent = msg; t.className = 'toast show toast-' + type;
  clearTimeout(t._timer);
  t._timer = setTimeout(()=>{ t.className='toast toast-'+type; }, 3000);
}
async function api(action, data={}){
  const r = await fetch(`${API_BASE}/api/admin`,{
    method:'POST',
    headers:{'Content-Type':'application/json','Authorization':'Bearer '+adminSecret},
    body: JSON.stringify({action, ...data})
  });
  const j = await r.json();
  if(!j.ok && j.error === 'Unauthorized'){
    toast('❌ Sai secret!','error'); throw new Error('Unauthorized');
  }
  return j;
}
function doLogin(){
  const s = document.getElementById('adminSecret').value.trim();
  if(!s){ toast('⚠️ Nhập secret!','error'); return; }
  adminSecret = s;
  sessionStorage.setItem('lptool_secret', s);
  toast('✅ Đăng nhập!','success'); showMain();
}
function doLogout(){
  if(!confirm('Đăng xuất?')) return;
  adminSecret = ''; sessionStorage.removeItem('lptool_secret');
  document.getElementById('loginScreen').classList.remove('hidden');
  document.getElementById('mainPanel').classList.add('hidden');
}
function showMain(){
  document.getElementById('loginScreen').classList.add('hidden');
  document.getElementById('mainPanel').classList.remove('hidden');
  loadStats(); loadKeys(); loadLogs(); loadServerStatus(); loadToolHistory();
  setInterval(loadServerStatus, 10000);
}
async function loadServerStatus(){
  try{
    const j = await api('get_status'); if(!j.ok) return;
    currentMaintenance = j.maintenance.enabled;
    currentActivation = j.activation.required;

    const mtPill = document.getElementById('mtPill');
    const mtBtn = document.getElementById('mtBtn');
    const mtContent = document.getElementById('mtContent');
    if(currentMaintenance){
      mtPill.textContent = 'ON'; mtPill.className = 'status-pill on';
      mtBtn.textContent = '✅ TẮT BẢO TRÌ'; mtBtn.className = 'toggle-btn toggle-off';
    } else {
      mtPill.textContent = 'OFF'; mtPill.className = 'status-pill off';
      mtBtn.textContent = '🔧 BẬT BẢO TRÌ'; mtBtn.className = 'toggle-btn toggle-on';
    }
    if(j.maintenance.content && !mtContent.value) mtContent.value = j.maintenance.content;

    const acPill = document.getElementById('acPill');
    const acBtn = document.getElementById('acBtn');
    const acMsg = document.getElementById('acMessage');
    if(currentActivation){
      const activated = j.activation.activated;
      acPill.textContent = activated ? 'ĐÃ KT' : 'CHỜ KT';
      acPill.className = 'status-pill ' + (activated ? 'on' : 'warn');
      acBtn.textContent = '✅ TẮT + RESET'; acBtn.className = 'toggle-btn toggle-off';
    } else {
      acPill.textContent = 'OFF'; acPill.className = 'status-pill off';
      acBtn.textContent = '⚡ BẬT YÊU CẦU KÍCH HOẠT'; acBtn.className = 'toggle-btn toggle-on';
    }
    if(j.activation.message && !acMsg.value) acMsg.value = j.activation.message;

    // ⚡ THÔNG BÁO
    if(j.announcement){
      currentAnnouncement = j.announcement.enabled;
      const anPill = document.getElementById('anPill');
      const anBtn = document.getElementById('anBtn');
      const anContent = document.getElementById('anContent');
      if(currentAnnouncement){
        anPill.textContent = 'ON'; anPill.className = 'status-pill on';
        anBtn.textContent = '✅ TẮT THÔNG BÁO'; anBtn.className = 'toggle-btn toggle-off';
      } else {
        anPill.textContent = 'OFF'; anPill.className = 'status-pill off';
        anBtn.textContent = '📢 BẬT THÔNG BÁO'; anBtn.className = 'toggle-btn toggle-on';
      }
      if(j.announcement.content && !anContent.value) anContent.value = j.announcement.content;
    }
  } catch(e){}
}
async function toggleMaintenance(){
  const content = document.getElementById('mtContent').value.trim();
  if(!currentMaintenance && !content){ toast('⚠️ Nhập nội dung!','error'); return; }
  const newState = !currentMaintenance;
  if(newState && !confirm('BẬT BẢO TRÌ? Tất cả tool sẽ thoát!')) return;
  try{
    const j = await api('maintenance', {enabled:newState, content});
    if(j.ok){ toast(newState?'🔧 Đã BẬT!':'✅ Đã TẮT!','success'); loadServerStatus(); }
  } catch(e){ toast('❌ '+e.message,'error'); }
}
async function toggleActivation(){
  const message = document.getElementById('acMessage').value.trim();
  const newState = !currentActivation;
  if(newState && !message){ toast('⚠️ Nhập nội dung!','error'); return; }
  try{
    const j = await api('activation', {required:newState, message, reset:!newState});
    if(j.ok){ toast(newState?'⚡ Đã BẬT!':'✅ Đã TẮT + reset!','success'); loadServerStatus(); }
  } catch(e){ toast('❌ '+e.message,'error'); }
}
async function toggleAnnouncement(){
  const content = document.getElementById('anContent').value.trim();
  const newState = !currentAnnouncement;
  if(newState && !content){ toast('⚠️ Nhập nội dung!','error'); return; }
  try{
    const j = await api('announcement', {enabled:newState, content});
    if(j.ok){
      toast(newState?'📢 Đã BẬT thông báo!':'✅ Đã TẮT thông báo!','success');
      loadServerStatus();
    }
  } catch(e){ toast('❌ '+e.message,'error'); }
}
async function uploadTool(){
  const version = document.getElementById('toolVersion').value.trim();
  const code = document.getElementById('toolCode').value;
  const note = document.getElementById('toolNote').value.trim();
  if(!version){ toast('⚠️ Nhập version!','error'); return; }
  if(!code || code.length < 5000){ toast('⚠️ Code quá ngắn!','error'); return; }
  const size_kb = (code.length / 1024).toFixed(1);
  if(!confirm(`Upload v${version} (${size_kb} KB)?`)) return;
  try{
    const j = await api('upload_tool', {version, code, note});
    if(j.ok){
      toast(`✅ Đã upload v${version}!`,'success');
      document.getElementById('toolCode').value = '';
      document.getElementById('toolNote').value = '';
      loadToolHistory();
    } else toast('❌ '+j.error,'error');
  } catch(e){ toast('❌ '+e.message,'error'); }
}
async function loadToolHistory(){
  try{
    const j = await api('tool_history'); if(!j.ok) return;
    const box = document.getElementById('toolHistory');
    const pill = document.getElementById('toolPill');
    if(!j.items.length){
      box.innerHTML = '<div style="text-align:center;padding:10px;color:var(--gray)">📭 Chưa có version</div>';
      pill.textContent = '—'; pill.className = 'status-pill off';
      return;
    }
    const active = j.items.find(x => x.is_active);
    if(active){ pill.textContent = 'v' + active.version; pill.className = 'status-pill on'; }
    box.innerHTML = j.items.map(it=>{
      const isActive = it.is_active ? '<span class="badge badge-active">✅ ACTIVE</span>' : '';
      const size_kb = (it.size / 1024).toFixed(1);
      const time = new Date(it.uploaded_at).toLocaleString('vi-VN');
      return `<div class="key-item" style="padding:8px">
        <div class="key-header" style="margin-bottom:4px">
          <div><span class="badge badge-vip3">v${it.version}</span> ${isActive}</div>
          <button class="btn btn-danger btn-small" onclick="deleteTool(${it.id})">🗑️</button>
        </div>
        <div style="font-size:11px;color:var(--gray)">📦 ${size_kb} KB | 🕐 ${time} | 📝 ${it.note || '-'}</div>
      </div>`;
    }).join('');
  } catch(e){}
}
async function deleteTool(id){
  if(!confirm('Xoá version này?')) return;
  try{
    const j = await api('delete_tool', {id});
    if(j.ok){ toast('🗑️ Đã xoá!','success'); loadToolHistory(); }
  } catch(e){}
}
async function createKey(){
  const type = document.getElementById('newType').value;
  const dh = parseInt(document.getElementById('newDuration').value);
  const note = document.getElementById('newNote').value.trim();
  try{
    const j = await api('create', {type, duration_hours:dh, note, created_by:'admin'});
    if(!j.ok){ toast('❌ '+j.error,'error'); return; }
    lastKey = j.key;
    document.getElementById('newKeyValue').textContent = j.key;
    document.getElementById('newKeyResult').classList.remove('hidden');
    toast('🎉 Tạo key OK!','success'); loadStats(); loadKeys();
  } catch(e){ toast('❌ '+e.message,'error'); }
}
function copyKey(){ if(lastKey) navigator.clipboard.writeText(lastKey).then(()=>toast('📋 Copy!','success')); }
function hideNewKey(){ document.getElementById('newKeyResult').classList.add('hidden'); lastKey=null; }
async function loadKeys(){
  try{
    const j = await api('list'); if(!j.ok) return;
    cachedKeys = j.keys || []; renderKeys();
  } catch(e){}
}
function getKeyStatus(k){
  const now = Date.now();
  if(!k.active) return 'revoked';
  if(k.expires_at < now && k.type !== 'ADMIN') return 'expired';
  return 'active';
}
function formatTime(ts){ return ts ? new Date(ts).toLocaleString('vi-VN',{day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'}) : '-'; }
function formatDuration(ms){ if(ms<=0) return 'Hết'; const d=Math.floor(ms/86400000), h=Math.floor((ms%86400000)/3600000); return d>0?`${d}d ${h}h`:`${h}h`; }
function renderKeys(){
  const box = document.getElementById('keysList');
  const ft = (document.getElementById('filterText').value||'').toLowerCase();
  const fs = document.getElementById('filterStatus').value;
  const now = Date.now();
  let list = cachedKeys.filter(k=>{
    if(ft && !k.key.toLowerCase().includes(ft) && !(k.note||'').toLowerCase().includes(ft)) return false;
    const st = getKeyStatus(k);
    if(fs==='active' && st!=='active') return false;
    if(fs==='expired' && st!=='expired') return false;
    if(fs==='revoked' && st!=='revoked') return false;
    if(fs==='used' && !k.device_id) return false;
    return true;
  });
  if(!list.length){
    box.innerHTML='<div style="text-align:center;padding:30px;color:var(--gray)">📭 Không có key</div>';
    return;
  }
  box.innerHTML = list.map(k=>{
    const st = getKeyStatus(k);
    const sb = st==='active'?'<span class="badge badge-active">✅ ACTIVE</span>':st==='expired'?'<span class="badge badge-expired">⏰ HẾT HẠN</span>':'<span class="badge badge-revoked">❌ THU HỒI</span>';
    const tb = {VIP1:'<span class="badge badge-vip1">🔓 VIP1</span>',VIP3:'<span class="badge badge-vip3">🔐 VIP3</span>',SUPER:'<span class="badge badge-super">👑 SUPER</span>',ADMIN:'<span class="badge badge-admin">⚡ ADMIN</span>'}[k.type]||'';
    const remain = k.type==='ADMIN'?'VĨNH VIỄN':formatDuration(k.expires_at-now);
    const dev = k.device_id ? k.device_id.substring(0,16)+'...' : 'chưa dùng';
    return `<div class="key-item">
      <div class="key-header"><div style="display:flex;gap:6px">${tb} ${sb}</div>
      <div style="font-size:11px;color:var(--gray)">🕐 ${formatTime(k.created_at)}</div></div>
      <div class="key-value">${k.key}</div>
      <div class="key-meta">
        <div>⏱️ Còn: <span>${remain}</span></div>
        <div>👤 <span>${k.created_by||'-'}</span></div>
        <div>📱 <span>${dev}</span></div>
        <div>🔢 <span>${k.use_count||0} lần</span></div>
        ${k.note?`<div>📝 <span>${k.note}</span></div>`:''}
      </div>
      <div class="btn-row mt-10">
        <button class="btn btn-primary btn-small" onclick="copyAny('${k.key}')">📋 Copy</button>
        ${st==='active'?`<button class="btn btn-warn btn-small" onclick="revokeKey('${k.key}')">🚫 Thu hồi</button>`:''}
        ${st==='revoked'?`<button class="btn btn-primary btn-small" onclick="reactivateKey('${k.key}')">✅ Bật lại</button>`:''}
        ${k.device_id?`<button class="btn btn-warn btn-small" onclick="resetDevice('${k.key}')">📱 Reset</button>`:''}
        <button class="btn btn-primary btn-small" onclick="extendKey('${k.key}')">➕ Gia hạn</button>
        <button class="btn btn-danger btn-small" onclick="deleteKey('${k.key}')">🗑️ Xoá</button>
      </div></div>`;
  }).join('');
}
function copyAny(k){ navigator.clipboard.writeText(k).then(()=>toast('📋 Copy!','success')); }
async function revokeKey(key){ const reason=prompt('Lý do?','Admin revoked'); if(reason===null) return; const j=await api('revoke',{key,reason}); if(j.ok){ toast('🚫 Đã thu hồi','success'); loadKeys(); loadStats(); } }
async function reactivateKey(key){ const j=await api('reactivate',{key}); if(j.ok){ toast('✅ Đã bật lại','success'); loadKeys(); loadStats(); } }
async function resetDevice(key){ if(!confirm('Reset device?')) return; const j=await api('reset_device',{key}); if(j.ok){ toast('📱 Đã reset','success'); loadKeys(); } }
async function extendKey(key){ const h=prompt('Gia hạn bao nhiêu giờ?','24'); if(!h) return; const j=await api('extend',{key,hours:parseInt(h)}); if(j.ok){ toast('➕ Đã gia hạn','success'); loadKeys(); loadStats(); } }
async function deleteKey(key){ if(!confirm('XOÁ VĨNH VIỄN?')) return; const j=await api('delete',{key}); if(j.ok){ toast('🗑️ Đã xoá','success'); loadKeys(); loadStats(); } }
async function loadStats(){
  const j = await api('stats'); if(!j.ok) return;
  document.getElementById('statTotal').textContent = j.stats.total;
  document.getElementById('statActive').textContent = j.stats.active;
  document.getElementById('statUsed').textContent = j.stats.used;
  document.getElementById('statRevoked').textContent = j.stats.revoked;
}
async function loadLogs(){
  const j = await api('logs'); if(!j.ok) return;
  const box = document.getElementById('logsList');
  if(!j.logs.length){ box.innerHTML='<div style="text-align:center;padding:20px;color:var(--gray)">📭 Chưa có log</div>'; return; }
  box.innerHTML = j.logs.map(l=>{
    const time = new Date(l.ts).toLocaleString('vi-VN');
    const color = {create:'var(--green)',validate_ok:'var(--cyan)',bind_device:'var(--yellow)',revoke:'var(--red)',delete:'var(--red)',extend:'var(--green)',maintenance_on:'var(--red)',maintenance_off:'var(--green)',activation_on:'var(--yellow)',activation_off:'var(--green)',announcement_on:'var(--yellow)',announcement_off:'var(--green)',tool_upload:'var(--cyan)',tool_delete:'var(--red)'}[l.action]||'var(--white)';
    return `<div style="padding:8px;border-bottom:1px solid rgba(0,212,255,0.1);font-size:12px">
      <span style="color:${color};font-weight:700">${l.action}</span>
      <span style="color:var(--gray);margin-left:8px">${time}</span>
      <div style="color:var(--cyan);font-family:monospace;margin-top:4px;word-break:break-all">${l.key||''}</div>
    </div>`;
  }).join('');
}
(function init(){
  const saved = sessionStorage.getItem('lptool_secret');
  if(saved){ adminSecret = saved; showMain(); }
  document.getElementById('adminSecret').addEventListener('keypress', e=>{ if(e.key==='Enter') doLogin(); });
  document.getElementById('newType').addEventListener('change', e=>{
    const d = document.getElementById('newDuration');
    if(e.target.value==='ADMIN') d.value='880800'; else if(d.value==='880800') d.value='24';
  });
})();
</script></body></html>"""

@app.route("/admin")
def admin_page(): return render_template_string(ADMIN_HTML)

@app.route("/")
def index():
    return '''<!DOCTYPE html><html><head><meta charset="UTF-8"><title>LP KEY</title>
<style>body{background:#050a14;color:#eaf2ff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center}
h1{color:#00d4ff;font-size:48px;letter-spacing:6px;margin:0 0 10px}p{color:#7a8ca3}
a{display:inline-block;margin-top:20px;padding:12px 30px;background:linear-gradient(135deg,#00d4ff,#2563eb);color:#050a14;text-decoration:none;border-radius:8px;font-weight:700}
</style></head><body><div><h1>LP KEY</h1><p>Server đang chạy</p><a href="/admin">🚀 VÀO ADMIN</a></div></body></html>'''

init_db()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
