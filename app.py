# -*- coding: utf-8 -*-
# PLP KEY SERVER — Full Edition (Menu 3 gạch)
# Bao gồm: Key VIP + Key FREE + Bảo trì + Kích hoạt + Thông báo + Xuất file + Nhật ký
from __future__ import annotations
import os, sqlite3, time, random, json
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, Response

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "LpToolAdmin@2026")
DB_PATH = os.environ.get("DB_PATH", "keys.db")
app = Flask(__name__)

MAINTENANCE = {"enabled": False, "content": "", "enabled_at": None}
ACTIVATION = {"required": False, "activated": False,
              "message": "Vui lòng nhấn KÍCH HOẠT để bắt đầu sử dụng tool",
              "activated_at": None, "activated_by": None}
ANNOUNCEMENT = {"enabled": False, "content": "", "updated_at": None, "updated_by": None}


def init_db():
    conn = sqlite3.connect(DB_PATH); c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE NOT NULL,
        type TEXT NOT NULL, duration_hours INTEGER NOT NULL,
        created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        active INTEGER DEFAULT 1, created_by TEXT, note TEXT,
        device_id TEXT, device_fingerprint TEXT, last_ip TEXT,
        last_seen INTEGER, first_used_at INTEGER,
        use_count INTEGER DEFAULT 0, banned_reason TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT,
        action TEXT NOT NULL, device_id TEXT, ip TEXT,
        info TEXT, created_at INTEGER NOT NULL)""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_keys_key ON keys(key)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_keys_device ON keys(device_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_logs_key ON logs(key)")
    conn.commit(); conn.close()


def get_db():
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row
    return conn


def log_action(key, action, device_id=None, ip=None, info=None):
    try:
        conn = get_db(); c = conn.cursor()
        c.execute("INSERT INTO logs (key, action, device_id, ip, info, created_at) VALUES (?,?,?,?,?,?)",
                  (key, action, device_id, ip, json.dumps(info or {}), int(time.time()*1000)))
        conn.commit(); conn.close()
    except Exception as e: print(f"log_action: {e}")


CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
FREE_CHARS = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def rand_str(n): return "".join(random.choice(CHARS) for _ in range(n))
def gen_free_key(): return "".join(random.choice(FREE_CHARS) for _ in range(7))


def generate_key(t):
    if t == "VIP1": return f"LPTOOL_VIP1_{rand_str(5)}_{rand_str(4)}_{rand_str(4)}"
    if t == "VIP3": return f"LPTOOL_VIP3_{rand_str(2)}_{rand_str(5)}_{rand_str(4)}_{rand_str(6)}"
    if t == "SUPER": return f"LPTOOL_PRENIUM_{rand_str(5)}_{rand_str(5)}_{rand_str(4)}_{rand_str(3)}_{rand_str(3)}_{rand_str(3)}"
    if t == "ADMIN":
        return (f"LPTOOL_ADMIN_{rand_str(6)}_{rand_str(7)}_{rand_str(3)}_{rand_str(5)}_"
                f"{rand_str(3)}_{rand_str(3)}_{rand_str(5)}_{rand_str(4)}_{rand_str(4)}_{rand_str(6)}")
    if t == "FREE": return gen_free_key()
    raise ValueError("Invalid")


def require_admin(f):
    @wraps(f)
    def w(*a, **kw):
        auth = request.headers.get("Authorization", "")
        if auth.replace("Bearer ", "").strip() != ADMIN_SECRET:
            return jsonify({"ok": False, "error": "Unauthorized"}), 401
        return f(*a, **kw)
    return w


# ===== CHECK STATUS =====
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
        "announcement_enabled": ANNOUNCEMENT["enabled"],
        "announcement_content": ANNOUNCEMENT["content"],
        "announcement_updated_at": ANNOUNCEMENT["updated_at"],
        "ts": int(time.time()*1000),
    })


# ===== ACTIVATE =====
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
    ACTIVATION["activated_at"] = int(time.time()*1000)
    ACTIVATION["activated_by"] = key_str
    log_action(key_str, "activation_confirmed", device_id)
    return jsonify({"ok": True, "message": "✅ Kích hoạt thành công!"})


# ===== VALIDATE =====
@app.route("/api/validate", methods=["POST", "OPTIONS"])
def api_validate():
    if request.method == "OPTIONS": return "", 200
    data = request.get_json(silent=True) or {}
    key_str = (data.get("key") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    fingerprint = data.get("fingerprint") or None
    ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr
    if not key_str or not device_id:
        return jsonify({"ok": False, "error": "Thiếu key/device_id"}), 400
    conn = get_db(); c = conn.cursor()
    row = c.execute("SELECT * FROM keys WHERE key=?", (key_str,)).fetchone()
    if not row:
        conn.close(); return jsonify({"ok": False, "error": "Key không tồn tại"}), 404
    row = dict(row); now_ms = int(time.time()*1000)

    if not row["active"]:
        log_action(key_str, "validate_failed_inactive", device_id, ip)
        conn.close()
        return jsonify({"ok": False, "error": "Key chưa Active, Vui lòng báo Admin",
                        "need_activation": True}), 403

    if not row["first_used_at"]:
        new_expires = now_ms + int(row["duration_hours"]) * 3600 * 1000
        c.execute("""UPDATE keys SET first_used_at=?, expires_at=?, device_id=?,
                     device_fingerprint=?, last_seen=?, last_ip=?, use_count=1 WHERE id=?""",
                  (now_ms, new_expires, device_id, fingerprint, now_ms, ip, row["id"]))
        conn.commit()
        log_action(key_str, "first_use_start_timer", device_id, ip,
                   {"duration_hours": row["duration_hours"], "expires_at": new_expires})
        conn.close()
        return jsonify({"ok": True, "key_type": row["type"],
                        "duration_hours": row["duration_hours"],
                        "expires_at": new_expires,
                        "is_admin": row["type"] == "ADMIN",
                        "is_free": row["type"] == "FREE",
                        "created_by": row["created_by"],
                        "message": "Kích hoạt lần đầu thành công"})

    if row["expires_at"] < now_ms and row["type"] != "ADMIN":
        log_action(key_str, "validate_failed_expired", device_id, ip)
        conn.close()
        return jsonify({"ok": False, "error": "Key đã hết hạn",
                        "expired_at": row["expires_at"]}), 403

    if not row["device_id"]:
        c.execute("""UPDATE keys SET device_id=?, device_fingerprint=?, last_seen=?,
                     last_ip=?, use_count=use_count+1 WHERE id=?""",
                  (device_id, fingerprint, now_ms, ip, row["id"]))
        log_action(key_str, "bind_device", device_id, ip)
    elif row["device_id"] != device_id:
        log_action(key_str, "validate_failed_wrong_device", device_id, ip,
                   {"bound_device": row["device_id"]})
        conn.close()
        return jsonify({"ok": False, "error": "Key đã kích hoạt trên thiết bị khác",
                        "hint": "Liên hệ admin để reset device"}), 403
    else:
        c.execute("UPDATE keys SET last_seen=?, last_ip=?, use_count=use_count+1 WHERE id=?",
                  (now_ms, ip, row["id"]))

    conn.commit()
    log_action(key_str, "validate_ok", device_id, ip)
    conn.close()
    return jsonify({"ok": True, "key_type": row["type"],
                    "duration_hours": row["duration_hours"],
                    "expires_at": row["expires_at"],
                    "is_admin": row["type"] == "ADMIN",
                    "is_free": row["type"] == "FREE",
                    "created_by": row["created_by"],
                    "message": "Xác thực thành công"})


# ===== HEARTBEAT =====
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
    row = dict(row); now_ms = int(time.time()*1000)
    if not row["active"]:
        conn.close(); return jsonify({"ok": False, "error": "Key chưa Active"}), 403
    if row["expires_at"] < now_ms and row["type"] != "ADMIN":
        conn.close(); return jsonify({"ok": False, "error": "Key đã hết hạn"}), 403
    if row["device_id"] and row["device_id"] != device_id:
        conn.close(); return jsonify({"ok": False, "error": "Key đang dùng ở thiết bị khác"}), 403
    ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr
    c.execute("UPDATE keys SET last_seen=?, last_ip=? WHERE id=?", (now_ms, ip, row["id"]))
    conn.commit(); conn.close()
    return jsonify({"ok": True, "message": "Heartbeat OK"})


# ===== ADMIN =====
@app.route("/api/admin", methods=["POST", "OPTIONS"])
@require_admin
def api_admin():
    if request.method == "OPTIONS": return "", 200
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    conn = get_db(); c = conn.cursor()

    if action == "create":
        kt = data.get("type", "VIP1")
        dh = int(data.get("duration_hours", 24))
        note = data.get("note", "")
        cb = data.get("created_by", "admin")
        try: qty = int(data.get("quantity", 1))
        except: qty = 1
        qty = max(1, min(qty, 100))
        if kt not in ("VIP1", "VIP3", "SUPER", "ADMIN"):
            conn.close(); return jsonify({"ok": False, "error": "Loại không hợp lệ"}), 400
        if kt == "ADMIN": dh = 36700 * 24
        now_ms = int(time.time()*1000)
        exp = now_ms + dh * 3600 * 1000
        created = []
        for _ in range(qty):
            for _a in range(10):
                ks = generate_key(kt)
                if not c.execute("SELECT 1 FROM keys WHERE key=?", (ks,)).fetchone(): break
            try:
                c.execute("""INSERT INTO keys (key,type,duration_hours,created_at,expires_at,
                             active,created_by,note) VALUES (?,?,?,?,?,0,?,?)""",
                          (ks, kt, dh, now_ms, exp, cb, note))
                created.append(ks)
            except sqlite3.IntegrityError: continue
        conn.commit()
        for k in created: log_action(k, "create", None, None, {"type": kt, "batch": qty})
        conn.close()
        return jsonify({"ok": True, "keys": created, "quantity": len(created)})

    if action == "gen_free_key":
        try: dh = int(data.get("duration_hours", 24))
        except: dh = 24
        dh = max(1, min(dh, 720))
        note = data.get("note", "")
        try: qty = int(data.get("quantity", 1))
        except: qty = 1
        qty = max(1, min(qty, 100))
        now_ms = int(time.time()*1000)
        exp = now_ms + dh * 3600 * 1000
        created = []
        for _ in range(qty):
            for _a in range(15):
                ks = gen_free_key()
                if not c.execute("SELECT 1 FROM keys WHERE key=?", (ks,)).fetchone(): break
            try:
                c.execute("""INSERT INTO keys (key,type,duration_hours,created_at,expires_at,
                             active,created_by,note) VALUES (?,'FREE',?,?,?,1,'admin',?)""",
                          (ks, dh, now_ms, exp, note))
                created.append(ks)
            except sqlite3.IntegrityError: continue
        conn.commit()
        for k in created: log_action(k, "gen_free_key", None, None, {"duration": dh})
        conn.close()
        return jsonify({"ok": True, "keys": created, "quantity": len(created), "duration_hours": dh})

    if action == "list":
        rows = c.execute("SELECT * FROM keys ORDER BY created_at DESC").fetchall()
        keys = [dict(r) for r in rows]; conn.close()
        return jsonify({"ok": True, "keys": keys, "total": len(keys)})

    if action == "set_active":
        ks = data.get("key"); v = 1 if int(data.get("value", 1)) else 0
        c.execute("UPDATE keys SET active=? WHERE key=?", (v, ks))
        conn.commit(); log_action(ks, "set_active", None, None, {"value": v}); conn.close()
        return jsonify({"ok": True, "active": v})

    if action == "bulk_active":
        keys = data.get("keys") or []; v = 1 if int(data.get("value", 1)) else 0
        for k in keys:
            c.execute("UPDATE keys SET active=? WHERE key=?", (v, k))
            log_action(k, "set_active_bulk", None, None, {"value": v})
        conn.commit(); conn.close()
        return jsonify({"ok": True, "count": len(keys)})

    if action == "revoke":
        ks = data.get("key"); reason = data.get("reason", "Admin revoked")
        c.execute("UPDATE keys SET active=0, banned_reason=? WHERE key=?", (reason, ks))
        conn.commit(); log_action(ks, "revoke", None, None, {"reason": reason}); conn.close()
        return jsonify({"ok": True})

    if action == "reactivate":
        ks = data.get("key")
        c.execute("UPDATE keys SET active=1, banned_reason=NULL WHERE key=?", (ks,))
        conn.commit(); log_action(ks, "reactivate"); conn.close()
        return jsonify({"ok": True})

    if action == "delete":
        ks = data.get("key")
        c.execute("DELETE FROM keys WHERE key=?", (ks,))
        conn.commit(); log_action(ks, "delete"); conn.close()
        return jsonify({"ok": True})

    if action == "reset_device":
        ks = data.get("key")
        c.execute("""UPDATE keys SET device_id=NULL, device_fingerprint=NULL,
                     first_used_at=NULL, expires_at=0 WHERE key=?""", (ks,))
        conn.commit(); log_action(ks, "reset_device"); conn.close()
        return jsonify({"ok": True})

    if action == "extend":
        ks = data.get("key"); hours = int(data.get("hours", 24))
        row = c.execute("SELECT * FROM keys WHERE key=?", (ks,)).fetchone()
        if not row: conn.close(); return jsonify({"ok": False, "error": "Key không tồn tại"}), 404
        row = dict(row); now_ms = int(time.time()*1000)
        base = max(row["expires_at"] or 0, now_ms)
        new_exp = base + hours * 3600 * 1000
        c.execute("""UPDATE keys SET expires_at=?, active=1, duration_hours=duration_hours+?
                     WHERE key=?""", (new_exp, hours, ks))
        conn.commit(); log_action(ks, "extend", None, None, {"hours": hours}); conn.close()
        return jsonify({"ok": True, "expires_at": new_exp})

    if action == "stats":
        total = c.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
        now_ms = int(time.time()*1000)
        used = c.execute("SELECT COUNT(*) FROM keys WHERE first_used_at IS NOT NULL").fetchone()[0]
        not_active = c.execute("SELECT COUNT(*) FROM keys WHERE active=0").fetchone()[0]
        active = c.execute("SELECT COUNT(*) FROM keys WHERE active=1").fetchone()[0]
        running = c.execute("""SELECT COUNT(*) FROM keys WHERE active=1 AND first_used_at IS NOT NULL
                              AND (expires_at > ? OR type='ADMIN')""", (now_ms,)).fetchone()[0]
        by_type = {}
        for t in ("VIP1", "VIP3", "SUPER", "ADMIN", "FREE"):
            by_type[t] = c.execute("SELECT COUNT(*) FROM keys WHERE type=?", (t,)).fetchone()[0]
        conn.close()
        return jsonify({"ok": True, "stats": {"total": total, "active": active,
                        "notActive": not_active, "used": used, "running": running, "byType": by_type}})

    if action == "logs":
        rows = c.execute("SELECT * FROM logs ORDER BY created_at DESC LIMIT 200").fetchall()
        logs = []
        for r in rows:
            d = dict(r); d["ts"] = d.pop("created_at")
            try: d["info"] = json.loads(d.get("info") or "{}")
            except: d["info"] = {}
            logs.append(d)
        conn.close(); return jsonify({"ok": True, "logs": logs})

    if action == "export":
        mode = (data.get("mode") or "all").strip().lower()
        filename = (data.get("filename") or "").strip()
        if not filename: filename = f"keys_{mode}_{int(time.time())}.txt"
        if not filename.endswith(".txt"): filename += ".txt"
        if mode == "active":
            rows = c.execute("SELECT key,type,expires_at,first_used_at FROM keys WHERE active=1 ORDER BY created_at DESC").fetchall()
        elif mode == "not_active":
            rows = c.execute("SELECT key,type,expires_at,first_used_at FROM keys WHERE active=0 ORDER BY created_at DESC").fetchall()
        elif mode == "free":
            rows = c.execute("SELECT key,type,expires_at,first_used_at FROM keys WHERE type='FREE' ORDER BY created_at DESC").fetchall()
        elif mode == "vip":
            rows = c.execute("SELECT key,type,expires_at,first_used_at FROM keys WHERE type!='FREE' ORDER BY created_at DESC").fetchall()
        else:
            rows = c.execute("SELECT key,type,expires_at,first_used_at FROM keys ORDER BY created_at DESC").fetchall()
        conn.close()
        lines = []
        for r in rows:
            r = dict(r); exp = r["expires_at"] or 0
            if r["type"] == "ADMIN": exp_str = "NEVER"
            elif exp == 0: exp_str = "NOT_STARTED"
            else: exp_str = datetime.fromtimestamp(exp/1000).strftime("%Y-%m-%d %H:%M:%S")
            lines.append(f"{r['key']} | {r['type']} | EXP: {exp_str}")
        content = "\n".join(lines)
        log_action(None, "export", None, None, {"mode": mode, "count": len(lines)})
        return Response(content, mimetype="text/plain",
                        headers={"Content-Disposition": f'attachment; filename="{filename}"',
                                 "X-Filename": filename, "X-Count": str(len(lines))})

    if action == "maintenance":
        en = bool(data.get("enabled", False))
        content = str(data.get("content", "")).strip()
        MAINTENANCE["enabled"] = en; MAINTENANCE["content"] = content
        MAINTENANCE["enabled_at"] = int(time.time()*1000) if en else None
        conn.close(); log_action(None, "maintenance_" + ("on" if en else "off"), None, None, {"content": content})
        return jsonify({"ok": True, "maintenance": MAINTENANCE})

    if action == "activation":
        req = bool(data.get("required", False))
        msg = str(data.get("message", "")).strip()
        reset = bool(data.get("reset", False))
        ACTIVATION["required"] = req
        if msg: ACTIVATION["message"] = msg
        if reset or not req:
            ACTIVATION["activated"] = False; ACTIVATION["activated_at"] = None
            ACTIVATION["activated_by"] = None
        conn.close(); log_action(None, "activation_" + ("on" if req else "off"), None, None, {"msg": msg})
        return jsonify({"ok": True, "activation": ACTIVATION})

    if action == "announcement":
        en = bool(data.get("enabled", False))
        content = str(data.get("content", "")).strip()
        ANNOUNCEMENT["enabled"] = en; ANNOUNCEMENT["content"] = content
        ANNOUNCEMENT["updated_at"] = int(time.time()*1000); ANNOUNCEMENT["updated_by"] = "admin"
        conn.close(); log_action(None, "announcement_" + ("on" if en else "off"), None, None, {"content": content[:100]})
        return jsonify({"ok": True, "announcement": ANNOUNCEMENT})

    if action == "get_status":
        conn.close()
        return jsonify({"ok": True, "maintenance": MAINTENANCE,
                        "activation": ACTIVATION, "announcement": ANNOUNCEMENT})

    conn.close()
    return jsonify({"ok": False, "error": "Action không hợp lệ"}), 400


ADMIN_HTML = r"""<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>⚡ PLP KEY ADMIN ⚡</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:'Segoe UI',Roboto,sans-serif}
:root{--cyan:#00d4ff;--blue:#2563eb;--blue-light:#60a5fa;--green:#00e676;
--yellow:#ffd740;--red:#ff4d6d;--purple:#a855f7;--gray:#7a8ca3;--white:#eaf2ff}
body{background:radial-gradient(ellipse at top,#0a1a3a,#050a14 60%);color:var(--white);min-height:100vh}
/* Sidebar */
#sidebar{position:fixed;top:0;left:-280px;width:280px;height:100vh;
background:linear-gradient(180deg,#0b1a33,#050a14);border-right:2px solid var(--cyan);
transition:left .3s;z-index:1000;overflow-y:auto;padding:20px 0}
#sidebar.open{left:0}
#sidebar .brand{padding:16px 20px;font-size:22px;font-weight:900;color:var(--cyan);
letter-spacing:3px;border-bottom:1px solid rgba(0,212,255,.2);margin-bottom:12px}
#sidebar .item{padding:14px 22px;cursor:pointer;color:var(--white);font-weight:600;
font-size:14px;transition:all .2s;border-left:3px solid transparent}
#sidebar .item:hover{background:rgba(0,212,255,.08);border-left-color:var(--cyan)}
#sidebar .item.active{background:rgba(0,212,255,.15);border-left-color:var(--cyan);color:var(--cyan)}
#sidebar .item.free{border-left-color:var(--purple)}
#sidebar .item.free:hover{background:rgba(168,85,247,.1)}
#sidebar .item.danger{color:var(--red);border-left-color:var(--red)}
#sidebar .item.danger:hover{background:rgba(255,77,109,.1)}
#overlay{position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:999;display:none}
#overlay.open{display:block}
/* Topbar */
.topbar{position:sticky;top:0;background:rgba(5,10,20,.95);backdrop-filter:blur(8px);
border-bottom:1px solid rgba(0,212,255,.2);padding:14px 20px;display:flex;
align-items:center;gap:14px;z-index:100}
.hamburger{background:transparent;border:1px solid rgba(0,212,255,.4);border-radius:8px;
width:42px;height:42px;cursor:pointer;display:flex;flex-direction:column;
justify-content:center;align-items:center;gap:5px;transition:all .2s}
.hamburger:hover{background:rgba(0,212,255,.1)}
.hamburger span{display:block;width:20px;height:2px;background:var(--cyan);border-radius:2px}
.topbar-title{color:var(--cyan);font-size:18px;font-weight:800;letter-spacing:2px}
/* Main */
.container{max-width:1200px;margin:0 auto;padding:20px}
.section{display:none}
.section.active{display:block}
.card{background:linear-gradient(145deg,rgba(11,26,51,.85),rgba(5,10,20,.95));
border:1px solid rgba(0,212,255,.25);border-radius:16px;padding:24px;
margin-bottom:20px;box-shadow:0 8px 40px rgba(0,0,0,.5)}
.card.free{border-color:rgba(168,85,247,.35)}
.card.warn{border-color:rgba(255,215,64,.35)}
.card.danger{border-color:rgba(255,77,109,.35)}
.card-title{font-size:16px;color:var(--cyan);margin-bottom:16px;padding-bottom:10px;
border-bottom:1px solid rgba(0,212,255,.15);letter-spacing:1px;
display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.card.free .card-title{color:var(--purple);border-bottom-color:rgba(168,85,247,.2)}
.card.warn .card-title{color:var(--yellow);border-bottom-color:rgba(255,215,64,.2)}
.card.danger .card-title{color:var(--red);border-bottom-color:rgba(255,77,109,.2)}
label{display:block;color:var(--gray);font-size:11px;margin-bottom:6px;
text-transform:uppercase;font-weight:600}
input,select,textarea{width:100%;padding:12px 14px;background:rgba(5,10,20,.8);
border:1px solid rgba(0,212,255,.25);border-radius:8px;color:var(--white);
font-size:14px;outline:none;font-family:'Consolas',monospace}
input:focus,select:focus,textarea:focus{border-color:var(--cyan);
box-shadow:0 0 0 3px rgba(0,212,255,.15)}
.grid{display:grid;gap:12px}
.grid-4{grid-template-columns:1fr 1fr 1fr 1fr}
.grid-3{grid-template-columns:1fr 1fr 1fr}
.grid-2{grid-template-columns:1fr 1fr}
@media(max-width:700px){.grid-4,.grid-3,.grid-2{grid-template-columns:1fr}}
.btn{padding:12px 20px;border:none;border-radius:8px;font-size:14px;font-weight:700;
letter-spacing:1px;cursor:pointer;transition:all .2s;text-transform:uppercase}
.btn-primary{background:linear-gradient(135deg,var(--cyan),var(--blue));color:#050a14}
.btn-primary:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,212,255,.55)}
.btn-danger{background:linear-gradient(135deg,var(--red),#b91c3c);color:#fff}
.btn-danger:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(255,77,109,.55)}
.btn-warn{background:linear-gradient(135deg,var(--yellow),#f59e0b);color:#050a14}
.btn-warn:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(255,215,64,.55)}
.btn-green{background:linear-gradient(135deg,var(--green),#00b050);color:#050a14}
.btn-purple{background:linear-gradient(135deg,var(--purple),#7c3aed);color:#fff}
.btn-purple:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(168,85,247,.55)}
.btn-small{padding:6px 12px;font-size:11px}
.btn-row{display:flex;gap:8px;flex-wrap:wrap}
.key-item{background:rgba(5,10,20,.6);border:1px solid rgba(0,212,255,.15);
border-radius:10px;padding:12px;margin-bottom:8px}
.key-item.free{border-color:rgba(168,85,247,.3)}
.key-item.running{border-color:rgba(0,230,118,.35)}
.key-item.not-active{border-color:rgba(255,77,109,.35)}
.key-header{display:flex;justify-content:space-between;align-items:center;
margin-bottom:8px;flex-wrap:wrap;gap:6px}
.badge{padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700;display:inline-block}
.badge-vip1{background:rgba(0,230,118,.15);color:var(--green)}
.badge-vip3{background:rgba(96,165,250,.15);color:var(--blue-light)}
.badge-super{background:rgba(255,215,64,.15);color:var(--yellow)}
.badge-admin{background:rgba(255,77,109,.15);color:var(--red)}
.badge-free{background:rgba(168,85,247,.2);color:var(--purple)}
.badge-active{background:rgba(0,212,255,.15);color:var(--cyan)}
.badge-running{background:rgba(0,230,118,.2);color:var(--green)}
.badge-not-active{background:rgba(255,77,109,.15);color:var(--red)}
.badge-expired{background:rgba(122,140,163,.15);color:var(--gray)}
.badge-on{background:rgba(255,77,109,.2);color:var(--red)}
.badge-off{background:rgba(0,230,118,.2);color:var(--green)}
.key-value{font-family:'Consolas',monospace;font-size:12px;color:var(--cyan);
background:rgba(0,0,0,.4);padding:8px 10px;border-radius:6px;
word-break:break-all;user-select:all;margin:6px 0}
.key-item.free .key-value{color:var(--purple)}
.key-meta{display:flex;gap:12px;font-size:11px;color:var(--gray);flex-wrap:wrap;margin-top:6px}
.key-meta span{color:var(--white);font-weight:600}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}
@media(max-width:700px){.stats{grid-template-columns:1fr 1fr}}
.stat-item{background:rgba(0,212,255,.05);border:1px solid rgba(0,212,255,.15);
border-radius:10px;padding:14px;text-align:center}
.stat-value{font-size:24px;font-weight:800;color:var(--cyan)}
.stat-label{font-size:11px;color:var(--gray);text-transform:uppercase;margin-top:4px}
.toast{position:fixed;top:20px;right:20px;padding:12px 20px;border-radius:10px;
font-size:13px;font-weight:600;z-index:9999;opacity:0;transform:translateX(100%);
transition:all .3s;max-width:320px}
.toast.show{opacity:1;transform:translateX(0)}
.toast-success{background:linear-gradient(135deg,#00e676,#00b050);color:#050a14}
.toast-error{background:linear-gradient(135deg,#ff4d6d,#b91c3c);color:#fff}
.toast-info{background:linear-gradient(135deg,#00d4ff,#2563eb);color:#050a14}
.login-screen{display:flex;align-items:center;justify-content:center;min-height:70vh}
.login-card{max-width:400px;width:100%}
.hidden{display:none!important}
.mt-10{margin-top:10px}
.filter-row{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}
.keys-created-list{background:rgba(0,0,0,.4);border-radius:8px;padding:10px;
max-height:240px;overflow-y:auto;margin-top:8px;font-family:'Consolas',monospace;
font-size:12px;color:var(--cyan)}
.keys-created-list div{padding:3px 0;border-bottom:1px dashed rgba(0,212,255,.15);user-select:all}
.card.free .keys-created-list{color:var(--purple)}
.card.free .keys-created-list div{border-bottom-color:rgba(168,85,247,.2)}
</style></head><body>

<div id="overlay" onclick="closeSidebar()"></div>

<div id="sidebar">
  <div class="brand">⚡ PLP KEY</div>
  <div class="item active" id="nav-dashboard" onclick="nav('dashboard')">📊 Dashboard</div>
  <div class="item" id="nav-vip" onclick="nav('vip')">💎 Key VIP</div>
  <div class="item free" id="nav-free" onclick="nav('free')">🧪 Key FREE</div>
  <div class="item warn" id="nav-maintenance" onclick="nav('maintenance')">🔧 Bảo trì</div>
  <div class="item warn" id="nav-activation" onclick="nav('activation')">⚡ Kích hoạt</div>
  <div class="item warn" id="nav-announce" onclick="nav('announce')">📢 Thông báo</div>
  <div class="item" id="nav-export" onclick="nav('export')">📥 Xuất file</div>
  <div class="item" id="nav-list" onclick="nav('list')">📋 Danh sách key</div>
  <div class="item" id="nav-logs" onclick="nav('logs')">📜 Nhật ký</div>
  <div class="item danger" onclick="doLogout()">🚪 Đăng xuất</div>
</div>

<div id="loginScreen" class="login-screen">
  <div class="card login-card">
    <div style="text-align:center;margin-bottom:20px">
      <div style="font-size:38px;font-weight:900;background:linear-gradient(135deg,#00d4ff,#60a5fa,#00d4ff);
      -webkit-background-clip:text;-webkit-text-fill-color:transparent;letter-spacing:4px">PLP KEY</div>
      <div style="color:var(--gray);font-size:12px;letter-spacing:2px">⚡ ADMIN PANEL ⚡</div>
    </div>
    <div class="grid">
      <div><label>🔑 Admin Secret</label>
        <input type="password" id="adminSecret" placeholder="Nhập admin secret..."></div>
      <button class="btn btn-primary" onclick="doLogin()">🚀 ĐĂNG NHẬP</button>
    </div>
  </div>
</div>

<div id="mainPanel" class="hidden">
  <div class="topbar">
    <button class="hamburger" onclick="toggleSidebar()"><span></span><span></span><span></span></button>
    <div class="topbar-title" id="topbarTitle">📊 Dashboard</div>
  </div>

  <div class="container">
    <!-- DASHBOARD -->
    <div class="section active" id="sec-dashboard">
      <div class="card">
        <div class="card-title">📊 THỐNG KÊ</div>
        <div class="stats">
          <div class="stat-item"><div class="stat-value" id="statTotal">-</div><div class="stat-label">Tổng key</div></div>
          <div class="stat-item"><div class="stat-value" id="statActive" style="color:var(--cyan)">-</div><div class="stat-label">Đã Active</div></div>
          <div class="stat-item"><div class="stat-value" id="statRunning" style="color:var(--green)">-</div><div class="stat-label">Đang dùng</div></div>
          <div class="stat-item"><div class="stat-value" id="statNotActive" style="color:var(--yellow)">-</div><div class="stat-label">Chưa Active</div></div>
          <div class="stat-item"><div class="stat-value" id="statUsed" style="color:var(--cyan)">-</div><div class="stat-label">Đã kích hoạt</div></div>
        </div>
      </div>
      <div class="card">
        <div class="card-title">📈 THEO LOẠI</div>
        <div class="stats" style="grid-template-columns:repeat(5,1fr)">
          <div class="stat-item"><div class="stat-value" id="tVip1">-</div><div class="stat-label">VIP1</div></div>
          <div class="stat-item"><div class="stat-value" id="tVip3">-</div><div class="stat-label">VIP3</div></div>
          <div class="stat-item"><div class="stat-value" id="tSuper">-</div><div class="stat-label">SUPER</div></div>
          <div class="stat-item"><div class="stat-value" id="tAdmin">-</div><div class="stat-label">ADMIN</div></div>
          <div class="stat-item"><div class="stat-value" id="tFree" style="color:var(--purple)">-</div><div class="stat-label">FREE</div></div>
        </div>
      </div>
    </div>

    <!-- VIP -->
    <div class="section" id="sec-vip">
      <div class="card">
        <div class="card-title">💎 TẠO KEY VIP</div>
        <div class="grid grid-4">
          <div><label>Loại key</label>
            <select id="newType">
              <option value="VIP1">🔓 VIP 1</option>
              <option value="VIP3">🔐 VIP 3</option>
              <option value="SUPER">👑 SUPER</option>
              <option value="ADMIN">⚡ ADMIN</option>
            </select></div>
          <div><label>Thời hạn</label>
            <select id="newDuration">
              <option value="24">1 ngày</option>
              <option value="72">3 ngày</option>
              <option value="168">1 tuần</option>
              <option value="720">1 tháng</option>
              <option value="880800">Vĩnh viễn</option>
            </select></div>
          <div><label>Số lượng (1-100)</label>
            <input type="number" id="newQuantity" value="1" min="1" max="100"></div>
          <div><label>Ghi chú</label>
            <input type="text" id="newNote" placeholder="VD: khách A"></div>
        </div>
        <button class="btn btn-primary mt-10" onclick="createKey()">⚡ TẠO KEY VIP</button>
        <div id="newKeyResult" class="hidden mt-10">
          <label>✅ Đã tạo <span id="newKeyCount">0</span> key (chưa Active)</label>
          <div class="keys-created-list" id="newKeysList"></div>
          <div class="btn-row mt-10">
            <button class="btn btn-primary btn-small" onclick="copyNewKeys()">📋 Copy tất cả</button>
            <button class="btn btn-green btn-small" onclick="activateNewKeys()">✅ Bật Active tất cả</button>
            <button class="btn btn-danger btn-small" onclick="hideNewKey()">✖ Đóng</button>
          </div>
        </div>
      </div>
    </div>

    <!-- FREE -->
    <div class="section" id="sec-free">
      <div class="card free">
        <div class="card-title">🧪 SINH KEY FREE (Không qua Link4m)</div>
        <div class="grid grid-3">
          <div><label>Thời hạn</label>
            <select id="freeDuration">
              <option value="1">1 giờ</option>
              <option value="6">6 giờ</option>
              <option value="12">12 giờ</option>
              <option value="24" selected>1 ngày</option>
              <option value="72">3 ngày</option>
              <option value="168">1 tuần</option>
            </select></div>
          <div><label>Số lượng (1-100)</label>
            <input type="number" id="freeQuantity" value="1" min="1" max="100"></div>
          <div><label>Ghi chú</label>
            <input type="text" id="freeNote" placeholder="VD: test key free"></div>
        </div>
        <button class="btn btn-purple mt-10" onclick="genFreeKey()">🧪 SINH KEY FREE</button>
        <div id="freeKeyResult" class="hidden mt-10">
          <label>✅ Đã sinh <span id="freeKeyCount">0</span> key FREE</label>
          <div class="keys-created-list" id="freeKeysList"></div>
          <div class="btn-row mt-10">
            <button class="btn btn-primary btn-small" onclick="copyFreeKeys()">📋 Copy tất cả</button>
            <button class="btn btn-green btn-small" onclick="activateFreeKeys()">✅ Active sẵn</button>
            <button class="btn btn-danger btn-small" onclick="hideFreeKey()">✖ Đóng</button>
          </div>
        </div>
      </div>
    </div>

    <!-- MAINTENANCE -->
    <div class="section" id="sec-maintenance">
      <div class="card warn">
        <div class="card-title">🔧 BẢO TRÌ <span id="mtPill" class="badge badge-off">OFF</span></div>
        <div><label>Nội dung thông báo</label>
          <textarea id="mtContent" rows="3" placeholder="Server đang nâng cấp..."></textarea></div>
        <button class="btn btn-warn mt-10" id="mtBtn" style="width:100%" onclick="toggleMaintenance()">🔧 BẬT BẢO TRÌ</button>
        <div class="mt-10" style="font-size:11px;color:var(--gray)">
          💡 Bật bảo trì → tool đang chạy sẽ hiện thông báo và tự thoát (trừ chế độ treo 24/7).
        </div>
      </div>
    </div>

    <!-- ACTIVATION -->
    <div class="section" id="sec-activation">
      <div class="card warn">
        <div class="card-title">⚡ YÊU CẦU KÍCH HOẠT <span id="acPill" class="badge badge-off">OFF</span></div>
        <div><label>Nội dung yêu cầu user</label>
          <input type="text" id="acMessage" value="Vui lòng nhấn KÍCH HOẠT để bắt đầu sử dụng tool"></div>
        <button class="btn btn-warn mt-10" id="acBtn" style="width:100%" onclick="toggleActivation()">⚡ BẬT YÊU CẦU KÍCH HOẠT</button>
        <div class="mt-10" style="font-size:11px;color:var(--gray)">
          💡 Bật → user phải nhấn ENTER trên tool để xác nhận kích hoạt trước khi dùng.
        </div>
      </div>
    </div>

    <!-- ANNOUNCEMENT -->
    <div class="section" id="sec-announce">
      <div class="card warn">
        <div class="card-title">📢 THÔNG BÁO <span id="anPill" class="badge badge-off">OFF</span></div>
        <div><label>Nội dung thông báo cho user</label>
          <textarea id="anContent" rows="3" placeholder="VD: Bảo trì lúc 20h tối nay!"></textarea></div>
        <button class="btn btn-warn mt-10" id="anBtn" style="width:100%" onclick="toggleAnnouncement()">📢 BẬT THÔNG BÁO</button>
        <div class="mt-10" style="font-size:11px;color:var(--gray)">
          💡 Bật → tool hiện thông báo này trong panel THÔNG BÁO TỪ WEB.
        </div>
      </div>
    </div>

    <!-- EXPORT -->
    <div class="section" id="sec-export">
      <div class="card">
        <div class="card-title">📥 XUẤT FILE KEY</div>
        <div class="grid grid-3">
          <div><label>Loại xuất</label>
            <select id="exportMode">
              <option value="all">📦 Tất cả</option>
              <option value="active">✅ Đã Active</option>
              <option value="not_active">🟡 Chưa Active</option>
              <option value="free">🆓 Key FREE</option>
              <option value="vip">💎 Key VIP</option>
            </select></div>
          <div><label>Tên file (không cần .txt)</label>
            <input type="text" id="exportFilename" placeholder="VD: key_vip_1"></div>
          <div style="display:flex;align-items:flex-end">
            <button class="btn btn-primary" style="width:100%" onclick="exportKeys()">📥 XUẤT FILE</button></div>
        </div>
        <div class="mt-10" style="font-size:11px;color:var(--gray)">
          💡 Format: <code style="color:var(--cyan)">KEY | TYPE | EXP: YYYY-MM-DD HH:MM:SS</code>
        </div>
      </div>
    </div>

    <!-- LIST -->
    <div class="section" id="sec-list">
      <div class="card">
        <div class="card-title">📋 DANH SÁCH KEY
          <button class="btn btn-primary btn-small" style="margin-left:auto" onclick="loadKeys()">🔄 Refresh</button></div>
        <div class="filter-row">
          <input type="text" id="filterText" placeholder="🔍 Tìm key..." style="flex:1;min-width:200px" oninput="renderKeys()">
          <select id="filterStatus" onchange="renderKeys()" style="width:auto">
            <option value="all">Tất cả</option>
            <option value="running">Đang dùng</option>
            <option value="active">Đã Active (chưa dùng)</option>
            <option value="not_active">Chưa Active</option>
            <option value="used">Đã kích hoạt</option>
            <option value="expired">Hết hạn</option>
            <option value="free">🆓 FREE</option>
            <option value="vip">💎 VIP</option>
          </select>
        </div>
        <div id="keysList"></div>
      </div>
    </div>

    <!-- LOGS -->
    <div class="section" id="sec-logs">
      <div class="card">
        <div class="card-title">📜 NHẬT KÝ
          <button class="btn btn-primary btn-small" style="margin-left:auto" onclick="loadLogs()">🔄 Refresh</button></div>
        <div id="logsList" style="max-height:500px;overflow-y:auto"></div>
      </div>
    </div>
  </div>
</div>

<div id="toast" class="toast"></div>

<script>
const API_BASE = window.location.origin;
let adminSecret = '', cachedKeys = [], lastNewKeys = [], lastFreeKeys = [];
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

// ===== SIDEBAR =====
function toggleSidebar(){
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('overlay').classList.toggle('open');
}
function closeSidebar(){
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('overlay').classList.remove('open');
}
const SECTION_TITLES = {
  dashboard:'📊 Dashboard', vip:'💎 Key VIP', free:'🧪 Key FREE',
  maintenance:'🔧 Bảo trì', activation:'⚡ Kích hoạt', announce:'📢 Thông báo',
  export:'📥 Xuất file', list:'📋 Danh sách key', logs:'📜 Nhật ký'
};
function nav(sec){
  document.querySelectorAll('.section').forEach(s=>s.classList.remove('active'));
  document.querySelectorAll('#sidebar .item').forEach(i=>i.classList.remove('active'));
  const el = document.getElementById('sec-'+sec);
  if(el) el.classList.add('active');
  const navEl = document.getElementById('nav-'+sec);
  if(navEl) navEl.classList.add('active');
  document.getElementById('topbarTitle').textContent = SECTION_TITLES[sec] || 'Admin';
  closeSidebar();
  if(sec === 'dashboard') loadStats();
  if(sec === 'list') loadKeys();
  if(sec === 'logs') loadLogs();
  if(sec === 'maintenance' || sec === 'activation' || sec === 'announce') loadServerStatus();
}

// ===== LOGIN =====
function doLogin(){
  const s = document.getElementById('adminSecret').value.trim();
  if(!s){ toast('⚠️ Nhập secret!','error'); return; }
  adminSecret = s;
  sessionStorage.setItem('lptool_admin_secret', s);
  toast('✅ Đăng nhập!','success'); showMain();
}
function doLogout(){
  if(!confirm('Đăng xuất?')) return;
  adminSecret = ''; sessionStorage.removeItem('lptool_admin_secret');
  document.getElementById('loginScreen').classList.remove('hidden');
  document.getElementById('mainPanel').classList.add('hidden');
}
function showMain(){
  document.getElementById('loginScreen').classList.add('hidden');
  document.getElementById('mainPanel').classList.remove('hidden');
  loadStats();
  setInterval(loadServerStatus, 10000);
}

// ===== CREATE KEY VIP =====
async function createKey(){
  const type = document.getElementById('newType').value;
  const duration = parseInt(document.getElementById('newDuration').value);
  const quantity = parseInt(document.getElementById('newQuantity').value) || 1;
  const note = document.getElementById('newNote').value.trim();
  try{
    const j = await api('create', {type, duration_hours:duration, quantity, note, created_by:'admin'});
    if(!j.ok){ toast('❌ ' + j.error, 'error'); return; }
    lastNewKeys = j.keys || [];
    document.getElementById('newKeyCount').textContent = j.quantity;
    document.getElementById('newKeysList').innerHTML = lastNewKeys.map(k=>`<div>${k}</div>`).join('');
    document.getElementById('newKeyResult').classList.remove('hidden');
    toast(`🎉 Tạo ${j.quantity} key VIP!`,'success');
    loadStats();
  } catch(e){ toast('❌ '+e.message,'error'); }
}
function copyNewKeys(){
  if(!lastNewKeys.length) return;
  navigator.clipboard.writeText(lastNewKeys.join('\n'))
    .then(()=>toast(`📋 Đã copy ${lastNewKeys.length} key!`,'success'));
}
async function activateNewKeys(){
  if(!lastNewKeys.length) return;
  if(!confirm(`Bật Active cho ${lastNewKeys.length} key?`)) return;
  const j = await api('bulk_active', {keys:lastNewKeys, value:1});
  if(j.ok){ toast(`✅ Đã Active ${j.count} key`,'success'); loadStats(); }
}
function hideNewKey(){
  document.getElementById('newKeyResult').classList.add('hidden');
  lastNewKeys = [];
}

// ===== SINH KEY FREE =====
async function genFreeKey(){
  const duration = parseInt(document.getElementById('freeDuration').value);
  const quantity = parseInt(document.getElementById('freeQuantity').value) || 1;
  const note = document.getElementById('freeNote').value.trim();
  if(quantity < 1 || quantity > 100){ toast('⚠️ Số lượng 1-100','error'); return; }
  try{
    const j = await api('gen_free_key', {duration_hours:duration, quantity, note});
    if(!j.ok){ toast('❌ '+j.error,'error'); return; }
    lastFreeKeys = j.keys || [];
    document.getElementById('freeKeyCount').textContent = j.quantity;
    document.getElementById('freeKeysList').innerHTML = lastFreeKeys.map(k=>`<div>${k}</div>`).join('');
    document.getElementById('freeKeyResult').classList.remove('hidden');
    toast(`🧪 Đã sinh ${j.quantity} key FREE!`,'success');
    loadStats();
  } catch(e){ toast('❌ '+e.message,'error'); }
}
function copyFreeKeys(){
  if(!lastFreeKeys.length) return;
  navigator.clipboard.writeText(lastFreeKeys.join('\n'))
    .then(()=>toast(`📋 Đã copy ${lastFreeKeys.length} key FREE!`,'success'));
}
function activateFreeKeys(){
  toast('ℹ️ Key FREE mặc định đã Active sẵn','info');
}
function hideFreeKey(){
  document.getElementById('freeKeyResult').classList.add('hidden');
  lastFreeKeys = [];
}

// ===== MAINTENANCE / ACTIVATION / ANNOUNCEMENT =====
async function loadServerStatus(){
  try{
    const j = await api('get_status'); if(!j.ok) return;
    currentMaintenance = j.maintenance.enabled;
    currentActivation = j.activation.required;
    currentAnnouncement = j.announcement.enabled;

    const mtPill = document.getElementById('mtPill');
    const mtBtn = document.getElementById('mtBtn');
    const mtContent = document.getElementById('mtContent');
    if(currentMaintenance){
      mtPill.textContent = 'ON'; mtPill.className = 'badge badge-on';
      mtBtn.textContent = '✅ TẮT BẢO TRÌ'; mtBtn.className = 'btn btn-green mt-10';
      mtBtn.style.width = '100%';
    } else {
      mtPill.textContent = 'OFF'; mtPill.className = 'badge badge-off';
      mtBtn.textContent = '🔧 BẬT BẢO TRÌ'; mtBtn.className = 'btn btn-warn mt-10';
      mtBtn.style.width = '100%';
    }
    if(j.maintenance.content && !mtContent.value) mtContent.value = j.maintenance.content;

    const acPill = document.getElementById('acPill');
    const acBtn = document.getElementById('acBtn');
    const acMsg = document.getElementById('acMessage');
    if(currentActivation){
      acPill.textContent = j.activation.activated ? 'ĐÃ KT' : 'CHỜ KT';
      acPill.className = 'badge badge-on';
      acBtn.textContent = '✅ TẮT + RESET'; acBtn.className = 'btn btn-green mt-10';
      acBtn.style.width = '100%';
    } else {
      acPill.textContent = 'OFF'; acPill.className = 'badge badge-off';
      acBtn.textContent = '⚡ BẬT YÊU CẦU KÍCH HOẠT'; acBtn.className = 'btn btn-warn mt-10';
      acBtn.style.width = '100%';
    }
    if(j.activation.message && !acMsg.value) acMsg.value = j.activation.message;

    const anPill = document.getElementById('anPill');
    const anBtn = document.getElementById('anBtn');
    const anContent = document.getElementById('anContent');
    if(currentAnnouncement){
      anPill.textContent = 'ON'; anPill.className = 'badge badge-on';
      anBtn.textContent = '✅ TẮT THÔNG BÁO'; anBtn.className = 'btn btn-green mt-10';
      anBtn.style.width = '100%';
    } else {
      anPill.textContent = 'OFF'; anPill.className = 'badge badge-off';
      anBtn.textContent = '📢 BẬT THÔNG BÁO'; anBtn.className = 'btn btn-warn mt-10';
      anBtn.style.width = '100%';
    }
    if(j.announcement.content && !anContent.value) anContent.value = j.announcement.content;
  } catch(e){}
}
async function toggleMaintenance(){
  const content = document.getElementById('mtContent').value.trim();
  const newState = !currentMaintenance;
  if(newState && !content){ toast('⚠️ Nhập nội dung!','error'); return; }
  if(newState && !confirm('BẬT BẢO TRÌ? Tool sẽ thoát!')) return;
  const j = await api('maintenance', {enabled:newState, content});
  if(j.ok){ toast(newState?'🔧 Đã BẬT!':'✅ Đã TẮT!','success'); loadServerStatus(); }
}
async function toggleActivation(){
  const message = document.getElementById('acMessage').value.trim();
  const newState = !currentActivation;
  if(newState && !message){ toast('⚠️ Nhập nội dung!','error'); return; }
  const j = await api('activation', {required:newState, message, reset:!newState});
  if(j.ok){ toast(newState?'⚡ Đã BẬT!':'✅ Đã TẮT + reset!','success'); loadServerStatus(); }
}
async function toggleAnnouncement(){
  const content = document.getElementById('anContent').value.trim();
  const newState = !currentAnnouncement;
  if(newState && !content){ toast('⚠️ Nhập nội dung!','error'); return; }
  const j = await api('announcement', {enabled:newState, content});
  if(j.ok){ toast(newState?'📢 Đã BẬT!':'✅ Đã TẮT!','success'); loadServerStatus(); }
}

// ===== EXPORT =====
async function exportKeys(){
  const mode = document.getElementById('exportMode').value;
  let filename = document.getElementById('exportFilename').value.trim();
  if(!filename){
    const d = new Date();
    filename = `keys_${mode}_${d.getFullYear()}${String(d.getMonth()+1).padStart(2,'0')}${String(d.getDate()).padStart(2,'0')}`;
  }
  try{
    const r = await fetch(`${API_BASE}/api/admin`,{
      method:'POST',
      headers:{'Content-Type':'application/json','Authorization':'Bearer '+adminSecret},
      body: JSON.stringify({action:'export', mode, filename})
    });
    if(!r.ok){ toast('❌ Lỗi xuất file','error'); return; }
    const blob = await r.blob();
    const finalName = r.headers.get('X-Filename') || (filename+'.txt');
    const count = r.headers.get('X-Count') || '0';
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = finalName;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
    toast(`📥 Đã xuất ${count} key → ${finalName}`,'success');
  } catch(e){ toast('❌ '+e.message,'error'); }
}

// ===== LIST =====
async function loadKeys(){
  try{
    const j = await api('list');
    if(!j.ok) return;
    cachedKeys = j.keys || []; renderKeys();
  } catch(e){ toast('❌ '+e.message,'error'); }
}
function getKeyStatus(k){
  const now = Date.now();
  if(!k.active) return 'not_active';
  if(!k.first_used_at) return 'active';
  if(k.expires_at && k.expires_at < now && k.type !== 'ADMIN') return 'expired';
  return 'running';
}
function formatTime(ts){
  if(!ts) return '-';
  return new Date(ts).toLocaleString('vi-VN',{day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'});
}
function formatDuration(ms){
  if(ms <= 0) return 'Đã hết';
  const d = Math.floor(ms/86400000), h = Math.floor((ms%86400000)/3600000);
  if(d > 0) return `${d}d ${h}h`;
  return `${h}h`;
}
function renderKeys(){
  const box = document.getElementById('keysList');
  const ft = (document.getElementById('filterText').value||'').toLowerCase();
  const fs = document.getElementById('filterStatus').value;
  const now = Date.now();
  let list = cachedKeys.filter(k=>{
    if(ft && !k.key.toLowerCase().includes(ft) && !(k.note||'').toLowerCase().includes(ft)) return false;
    if(fs === 'free' && k.type !== 'FREE') return false;
    if(fs === 'vip' && k.type === 'FREE') return false;
    const st = getKeyStatus(k);
    if(fs === 'active' && st !== 'active') return false;
    if(fs === 'not_active' && st !== 'not_active') return false;
    if(fs === 'running' && st !== 'running') return false;
    if(fs === 'expired' && st !== 'expired') return false;
    if(fs === 'used' && !k.first_used_at) return false;
    return true;
  });
  if(!list.length){
    box.innerHTML = '<div style="text-align:center;padding:30px;color:var(--gray)">📭 Không có key</div>';
    return;
  }
  box.innerHTML = list.map(k=>{
    const st = getKeyStatus(k);
    const sb = st === 'running' ? '<span class="badge badge-running">🟢 ĐANG DÙNG</span>'
      : st === 'active' ? '<span class="badge badge-active">🔵 ĐÃ ACTIVE (chưa dùng)</span>'
      : st === 'not_active' ? '<span class="badge badge-not-active">🔴 CHƯA ACTIVE</span>'
      : '<span class="badge badge-expired">⏰ HẾT HẠN</span>';
    const tb = {
      VIP1:'<span class="badge badge-vip1">🔓 VIP1</span>',
      VIP3:'<span class="badge badge-vip3">🔐 VIP3</span>',
      SUPER:'<span class="badge badge-super">👑 SUPER</span>',
      ADMIN:'<span class="badge badge-admin">⚡ ADMIN</span>',
      FREE:'<span class="badge badge-free">🆓 FREE</span>'
    }[k.type] || '';
    let remain;
    if(k.type === 'ADMIN') remain = 'VĨNH VIỄN';
    else if(!k.first_used_at) remain = 'Chưa bắt đầu';
    else remain = formatDuration(k.expires_at - now);
    const dev = k.device_id ? k.device_id.substring(0,16)+'...' : 'chưa dùng';
    const cls = k.type === 'FREE' ? 'key-item free' : st === 'running' ? 'key-item running'
      : st === 'not_active' ? 'key-item not-active' : 'key-item';
    return `<div class="${cls}">
      <div class="key-header">
        <div style="display:flex;gap:6px">${tb} ${sb}</div>
        <div style="font-size:11px;color:var(--gray)">🕐 ${formatTime(k.created_at)}</div>
      </div>
      <div class="key-value">${k.key}</div>
      <div class="key-meta">
        <div>⏱️ Còn: <span>${remain}</span></div>
        <div>👤 <span>${k.created_by||'-'}</span></div>
        <div>📱 <span>${dev}</span></div>
        <div>🔢 <span>${k.use_count||0} lần</span></div>
        ${k.note?`<div>📝 <span>${k.note}</span></div>`:''}
      </div>
      <div class="btn-row mt-10">
        <button class="btn btn-primary btn-small" onclick="copyAnyKey('${k.key}')">📋 Copy</button>
        ${k.active==1?`<button class="btn btn-warn btn-small" onclick="setActive('${k.key}',0)">⏸️ Tắt Active</button>`
                    :`<button class="btn btn-green btn-small" onclick="setActive('${k.key}',1)">✅ Bật Active</button>`}
        ${k.first_used_at?`<button class="btn btn-warn btn-small" onclick="resetDevice('${k.key}')">📱 Reset</button>`:''}
        <button class="btn btn-primary btn-small" onclick="extendKey('${k.key}')">➕ Gia hạn</button>
        <button class="btn btn-danger btn-small" onclick="deleteKey('${k.key}')">🗑️ Xoá</button>
      </div>
    </div>`;
  }).join('');
}
function copyAnyKey(k){ navigator.clipboard.writeText(k).then(()=>toast('📋 Copy!','success')); }
async function setActive(key, value){
  const j = await api('set_active', {key, value});
  if(j.ok){ toast(value===1?'✅ Đã bật Active':'⏸️ Đã tắt Active','success'); loadKeys(); loadStats(); }
}
async function resetDevice(key){
  if(!confirm('Reset device + hạn?')) return;
  const j = await api('reset_device', {key});
  if(j.ok){ toast('📱 Đã reset','success'); loadKeys(); loadStats(); }
}
async function extendKey(key){
  const h = prompt('Gia hạn bao nhiêu giờ?','24');
  if(!h) return;
  const j = await api('extend', {key, hours:parseInt(h)});
  if(j.ok){ toast('➕ Đã gia hạn','success'); loadKeys(); loadStats(); }
}
async function deleteKey(key){
  if(!confirm('XOÁ VĨNH VIỄN?')) return;
  const j = await api('delete', {key});
  if(j.ok){ toast('🗑️ Đã xoá','success'); loadKeys(); loadStats(); }
}

// ===== STATS =====
async function loadStats(){
  const j = await api('stats'); if(!j.ok) return;
  document.getElementById('statTotal').textContent = j.stats.total;
  document.getElementById('statActive').textContent = j.stats.active;
  document.getElementById('statRunning').textContent = j.stats.running;
  document.getElementById('statNotActive').textContent = j.stats.notActive;
  document.getElementById('statUsed').textContent = j.stats.used;
  const bt = j.stats.byType || {};
  document.getElementById('tVip1').textContent = bt.VIP1 || 0;
  document.getElementById('tVip3').textContent = bt.VIP3 || 0;
  document.getElementById('tSuper').textContent = bt.SUPER || 0;
  document.getElementById('tAdmin').textContent = bt.ADMIN || 0;
  document.getElementById('tFree').textContent = bt.FREE || 0;
}

// ===== LOGS =====
async function loadLogs(){
  const j = await api('logs'); if(!j.ok) return;
  const box = document.getElementById('logsList');
  if(!j.logs.length){
    box.innerHTML = '<div style="text-align:center;padding:20px;color:var(--gray)">📭 Chưa có log</div>';
    return;
  }
  box.innerHTML = j.logs.map(l=>{
    const time = new Date(l.ts).toLocaleString('vi-VN');
    const colors = {
      create:'var(--green)', validate_ok:'var(--cyan)', bind_device:'var(--yellow)',
      first_use_start_timer:'var(--green)', gen_free_key:'var(--purple)',
      set_active:'var(--cyan)', set_active_bulk:'var(--cyan)', export:'var(--yellow)',
      validate_failed_not_active:'var(--red)', reset_device:'var(--yellow)',
      delete:'var(--red)', extend:'var(--green)', revoke:'var(--red)',
      maintenance_on:'var(--red)', maintenance_off:'var(--green)',
      activation_on:'var(--yellow)', activation_off:'var(--green)',
      activation_confirmed:'var(--green)',
      announcement_on:'var(--yellow)', announcement_off:'var(--green)'
    };
    const color = colors[l.action] || 'var(--white)';
    return `<div style="padding:8px;border-bottom:1px solid rgba(0,212,255,.1);font-size:12px">
      <span style="color:${color};font-weight:700">${l.action}</span>
      <span style="color:var(--gray);margin-left:8px">${time}</span>
      <div style="color:var(--cyan);font-family:monospace;margin-top:4px;word-break:break-all">${l.key||''}</div>
    </div>`;
  }).join('');
}

// ===== INIT =====
(function(){
  const saved = sessionStorage.getItem('lptool_admin_secret');
  if(saved){ adminSecret = saved; showMain(); }
  document.getElementById('adminSecret').addEventListener('keypress', e=>{ if(e.key==='Enter') doLogin(); });
  document.getElementById('newType').addEventListener('change', e=>{
    const d = document.getElementById('newDuration');
    if(e.target.value==='ADMIN') d.value='880800';
    else if(d.value==='880800') d.value='24';
  });
})();
</script></body></html>"""


@app.route("/admin")
def admin_page(): return render_template_string(ADMIN_HTML)


@app.route("/")
def index():
    return """<!DOCTYPE html><html><head><meta charset="UTF-8"><title>PLP KEY SERVER</title>
<style>body{background:#050a14;color:#eaf2ff;font-family:sans-serif;display:flex;
align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center}
h1{color:#00d4ff;font-size:48px;letter-spacing:6px;margin:0 0 10px}p{color:#7a8ca3}
a{display:inline-block;margin-top:20px;padding:12px 30px;
background:linear-gradient(135deg,#00d4ff,#2563eb);color:#050a14;
text-decoration:none;border-radius:8px;font-weight:700}
</style></head><body><div><h1>PLP KEY</h1>
<p>Server đang chạy. Truy cập /admin để quản lý key.</p>
<a href="/admin">🚀 VÀO ADMIN</a></div></body></html>"""


init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
