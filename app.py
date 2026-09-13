# -*- coding: utf-8 -*-
# ==============================================================
# LP-TOOL KEY SERVER v2 — Render.com Edition
# Admin: Thiên Phú - Minh Lâm
# Full features: Create / List / Revoke / Activate / Hide / Delete / Extend / Reset
# ==============================================================

from __future__ import annotations

import os
import sqlite3
import time
import random
import string
import json
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, render_template_string

# ==============================================================
# CONFIG
# ==============================================================

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "LpToolAdmin@2026")
DB_PATH = os.environ.get("DB_PATH", "keys.db")

app = Flask(__name__)

# ==============================================================
# DATABASE
# ==============================================================

def init_db():
    """Khởi tạo database + migration."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Bảng keys
    c.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            type TEXT NOT NULL,
            duration_hours INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            active INTEGER DEFAULT 1,
            hidden INTEGER DEFAULT 0,
            created_by TEXT,
            note TEXT,
            device_id TEXT,
            device_fingerprint TEXT,
            last_ip TEXT,
            last_seen INTEGER,
            first_used_at INTEGER,
            use_count INTEGER DEFAULT 0,
            banned_reason TEXT
        )
    """)

    # Migration: thêm cột hidden nếu DB cũ chưa có
    try:
        c.execute("ALTER TABLE keys ADD COLUMN hidden INTEGER DEFAULT 0")
    except Exception:
        pass  # Đã có cột rồi

    # Bảng logs
    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT,
            action TEXT NOT NULL,
            device_id TEXT,
            ip TEXT,
            info TEXT,
            created_at INTEGER NOT NULL
        )
    """)

    # Index
    c.execute("CREATE INDEX IF NOT EXISTS idx_keys_key ON keys(key)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_keys_device ON keys(device_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_logs_key ON logs(key)")

    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def log_action(key: str, action: str, device_id: str = None,
               ip: str = None, info: dict = None):
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute(
            "INSERT INTO logs (key, action, device_id, ip, info, created_at) VALUES (?,?,?,?,?,?)",
            (key, action, device_id, ip, json.dumps(info or {}), int(time.time() * 1000))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"log_action error: {e}")


# ==============================================================
# KEY GENERATOR
# ==============================================================

CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

def rand_str(n: int) -> str:
    return "".join(random.choice(CHARS) for _ in range(n))


def generate_key(key_type: str) -> str:
    if key_type == "VIP1":
        return f"LPTOOL_VIP1_{rand_str(5)}_{rand_str(4)}_{rand_str(4)}"
    if key_type == "VIP3":
        return f"LPTOOL_VIP3_{rand_str(2)}_{rand_str(5)}_{rand_str(4)}_{rand_str(6)}"
    if key_type == "SUPER":
        return f"LPTOOL_PRENIUM_{rand_str(5)}_{rand_str(5)}_{rand_str(4)}_{rand_str(3)}_{rand_str(3)}_{rand_str(3)}"
    if key_type == "ADMIN":
        return (f"LPTOOL_ADMIN_{rand_str(6)}_{rand_str(7)}_{rand_str(3)}_{rand_str(5)}_"
                f"{rand_str(3)}_{rand_str(3)}_{rand_str(5)}_{rand_str(4)}_{rand_str(4)}_{rand_str(6)}")
    raise ValueError("Invalid key type")


# ==============================================================
# ADMIN AUTH DECORATOR
# ==============================================================

def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth.replace("Bearer ", "").strip()
        if token != ADMIN_SECRET:
            return jsonify({"ok": False, "error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper


# ==============================================================
# API: VALIDATE (Tool gọi)
# ==============================================================

@app.route("/api/validate", methods=["POST", "OPTIONS"])
def api_validate():
    if request.method == "OPTIONS":
        return "", 200

    data = request.get_json(silent=True) or {}
    key_str = (data.get("key") or "").strip()
    device_id = (data.get("device_id") or "").strip()
    fingerprint = data.get("fingerprint") or None
    ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr

    if not key_str or not device_id:
        return jsonify({"ok": False, "error": "Thiếu key hoặc device_id"}), 400

    conn = get_db()
    c = conn.cursor()
    row = c.execute("SELECT * FROM keys WHERE key = ?", (key_str,)).fetchone()

    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Key không tồn tại"}), 404

    row = dict(row)
    now_ms = int(time.time() * 1000)

    # Check active
    if not row["active"]:
        log_action(key_str, "validate_failed_inactive", device_id, ip)
        conn.close()
        return jsonify({
            "ok": False,
            "error": "Key đã bị thu hồi",
            "reason": row.get("banned_reason") or "Admin revoked"
        }), 403

    # Check hết hạn
    if row["expires_at"] < now_ms and row["type"] != "ADMIN":
        log_action(key_str, "validate_failed_expired", device_id, ip)
        conn.close()
        return jsonify({
            "ok": False,
            "error": "Key đã hết hạn",
            "expired_at": row["expires_at"]
        }), 403

    # Check device
    if not row["device_id"]:
        # Bind device lần đầu
        c.execute("""
            UPDATE keys SET device_id=?, device_fingerprint=?, first_used_at=?,
                            last_seen=?, last_ip=?, use_count=1
            WHERE id=?
        """, (device_id, fingerprint, now_ms, now_ms, ip, row["id"]))
        log_action(key_str, "bind_device", device_id, ip, {"fingerprint": fingerprint})
    elif row["device_id"] != device_id:
        log_action(key_str, "validate_failed_wrong_device", device_id, ip,
                   {"bound_device": row["device_id"]})
        conn.close()
        return jsonify({
            "ok": False,
            "error": "Key đã kích hoạt trên thiết bị khác",
            "hint": "Liên hệ admin để reset device"
        }), 403
    else:
        # Cùng device → OK
        c.execute("""
            UPDATE keys SET last_seen=?, last_ip=?, use_count=use_count+1
            WHERE id=?
        """, (now_ms, ip, row["id"]))

    conn.commit()
    log_action(key_str, "validate_ok", device_id, ip)
    conn.close()

    return jsonify({
        "ok": True,
        "key_type": row["type"],
        "duration_hours": row["duration_hours"],
        "expires_at": row["expires_at"],
        "is_admin": row["type"] == "ADMIN",
        "created_by": row["created_by"],
        "message": "Xác thực thành công"
    })


# ==============================================================
# API: HEARTBEAT
# ==============================================================

@app.route("/api/heartbeat", methods=["POST", "OPTIONS"])
def api_heartbeat():
    if request.method == "OPTIONS":
        return "", 200

    data = request.get_json(silent=True) or {}
    key_str = (data.get("key") or "").strip()
    device_id = (data.get("device_id") or "").strip()

    if not key_str or not device_id:
        return jsonify({"ok": False, "error": "Thiếu key hoặc device_id"}), 400

    conn = get_db()
    c = conn.cursor()
    row = c.execute("SELECT * FROM keys WHERE key = ?", (key_str,)).fetchone()

    if not row:
        conn.close()
        return jsonify({"ok": False, "error": "Key không tồn tại"}), 404

    row = dict(row)
    now_ms = int(time.time() * 1000)

    if not row["active"]:
        conn.close()
        return jsonify({"ok": False, "error": "Key đã bị thu hồi"}), 403

    if row["expires_at"] < now_ms and row["type"] != "ADMIN":
        conn.close()
        return jsonify({"ok": False, "error": "Key đã hết hạn"}), 403

    if row["device_id"] and row["device_id"] != device_id:
        conn.close()
        return jsonify({"ok": False, "error": "Key đang dùng ở thiết bị khác"}), 403

    ip = request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr
    c.execute("UPDATE keys SET last_seen=?, last_ip=? WHERE id=?", (now_ms, ip, row["id"]))
    conn.commit()
    conn.close()

    return jsonify({"ok": True, "message": "Heartbeat OK"})


# ==============================================================
# API: ADMIN — Tất cả actions
# ==============================================================

@app.route("/api/admin", methods=["POST", "OPTIONS"])
@require_admin
def api_admin():
    if request.method == "OPTIONS":
        return "", 200

    data = request.get_json(silent=True) or {}
    action = data.get("action")

    conn = get_db()
    c = conn.cursor()

    # ============ CREATE ============
    if action == "create":
        key_type = data.get("type", "VIP1")
        duration_hours = int(data.get("duration_hours", 24))
        note = data.get("note", "")
        created_by = data.get("created_by", "admin")

        if key_type not in ("VIP1", "VIP3", "SUPER", "ADMIN"):
            conn.close()
            return jsonify({"ok": False, "error": "Loại key không hợp lệ"}), 400

        if key_type == "ADMIN":
            duration_hours = 36700 * 24

        key_str = generate_key(key_type)
        now_ms = int(time.time() * 1000)
        expires_at = now_ms + duration_hours * 3600 * 1000

        c.execute("""
            INSERT INTO keys (key, type, duration_hours, created_at, expires_at,
                              active, hidden, created_by, note)
            VALUES (?, ?, ?, ?, ?, 1, 0, ?, ?)
        """, (key_str, key_type, duration_hours, now_ms, expires_at, created_by, note))
        conn.commit()
        log_action(key_str, "create", None, None,
                   {"type": key_type, "duration": duration_hours, "created_by": created_by})
        conn.close()

        return jsonify({
            "ok": True,
            "key": key_str,
            "info": {
                "key": key_str,
                "type": key_type,
                "duration_hours": duration_hours,
                "created_at": now_ms,
                "expires_at": expires_at,
                "active": True,
                "hidden": False,
                "created_by": created_by,
                "note": note,
            }
        })

    # ============ LIST ============
    if action == "list":
        rows = c.execute("SELECT * FROM keys ORDER BY created_at DESC").fetchall()
        keys = [dict(r) for r in rows]
        # Convert hidden boolean cho JS
        for k in keys:
            k["hidden"] = bool(k.get("hidden", 0))
            k["active"] = bool(k.get("active", 1))
        conn.close()
        return jsonify({"ok": True, "keys": keys, "total": len(keys)})

    # ============ REVOKE ============
    if action == "revoke":
        key_str = data.get("key")
        reason = data.get("reason", "Admin revoked")
        c.execute("UPDATE keys SET active=0, banned_reason=? WHERE key=?", (reason, key_str))
        conn.commit()
        log_action(key_str, "revoke", None, None, {"reason": reason})
        conn.close()
        return jsonify({"ok": True, "message": "Đã thu hồi key"})

    # ============ REACTIVATE (ACTIVA) ============
    if action == "reactivate":
        key_str = data.get("key")
        c.execute("UPDATE keys SET active=1, banned_reason=NULL WHERE key=?", (key_str,))
        conn.commit()
        log_action(key_str, "reactivate")
        conn.close()
        return jsonify({"ok": True, "message": "Đã kích hoạt lại key"})

    # ============ TOGGLE HIDE ============
    if action == "toggle_hide":
        key_str = data.get("key")
        row = c.execute("SELECT * FROM keys WHERE key=?", (key_str,)).fetchone()
        if not row:
            conn.close()
            return jsonify({"ok": False, "error": "Key không tồn tại"}), 404
        row = dict(row)
        new_hidden = not bool(row.get("hidden", 0))
        c.execute("UPDATE keys SET hidden=? WHERE key=?",
                  (1 if new_hidden else 0, key_str))
        conn.commit()
        log_action(key_str, "toggle_hide", None, None, {"hidden": new_hidden})
        conn.close()
        return jsonify({
            "ok": True,
            "hidden": new_hidden,
            "message": "Đã ẩn key" if new_hidden else "Đã hiện key"
        })

    # ============ DELETE ============
    if action == "delete":
        key_str = data.get("key")
        row = c.execute("SELECT * FROM keys WHERE key=?", (key_str,)).fetchone()
        if row:
            row = dict(row)
            c.execute("DELETE FROM keys WHERE key=?", (key_str,))
            conn.commit()
            log_action(key_str, "delete", None, None, {"deleted_info": row})
        conn.close()
        return jsonify({"ok": True, "message": "Đã xoá key"})

    # ============ RESET DEVICE ============
    if action == "reset_device":
        key_str = data.get("key")
        c.execute("""
            UPDATE keys SET device_id=NULL, device_fingerprint=NULL, first_used_at=NULL
            WHERE key=?
        """, (key_str,))
        conn.commit()
        log_action(key_str, "reset_device")
        conn.close()
        return jsonify({"ok": True, "message": "Đã reset device"})

    # ============ EXTEND ============
    if action == "extend":
        key_str = data.get("key")
        hours = int(data.get("hours", 24))
        row = c.execute("SELECT * FROM keys WHERE key=?", (key_str,)).fetchone()
        if not row:
            conn.close()
            return jsonify({"ok": False, "error": "Key không tồn tại"}), 404
        row = dict(row)
        now_ms = int(time.time() * 1000)
        base = max(row["expires_at"], now_ms)
        new_exp = base + hours * 3600 * 1000
        c.execute("""
            UPDATE keys SET expires_at=?, active=1, duration_hours=duration_hours+?
            WHERE key=?
        """, (new_exp, hours, key_str))
        conn.commit()
        log_action(key_str, "extend", None, None, {"hours": hours, "new_expires": new_exp})
        conn.close()
        return jsonify({"ok": True, "message": "Đã gia hạn", "expires_at": new_exp})

    # ============ STATS ============
    if action == "stats":
        now_ms = int(time.time() * 1000)
        total = c.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
        hidden_count = c.execute("SELECT COUNT(*) FROM keys WHERE hidden=1").fetchone()[0]
        active = c.execute("""
            SELECT COUNT(*) FROM keys
            WHERE active=1 AND hidden=0 AND (expires_at > ? OR type='ADMIN')
        """, (now_ms,)).fetchone()[0]
        used = c.execute("SELECT COUNT(*) FROM keys WHERE device_id IS NOT NULL").fetchone()[0]
        revoked = c.execute("SELECT COUNT(*) FROM keys WHERE active=0").fetchone()[0]
        expired = c.execute("""
            SELECT COUNT(*) FROM keys WHERE expires_at < ? AND type != 'ADMIN'
        """, (now_ms,)).fetchone()[0]

        by_type = {}
        for t in ("VIP1", "VIP3", "SUPER", "ADMIN"):
            by_type[t] = c.execute("SELECT COUNT(*) FROM keys WHERE type=?", (t,)).fetchone()[0]

        conn.close()
        return jsonify({
            "ok": True,
            "stats": {
                "total": total, "active": active, "used": used,
                "revoked": revoked, "expired": expired,
                "hidden": hidden_count, "byType": by_type
            }
        })

    # ============ LOGS ============
    if action == "logs":
        rows = c.execute("SELECT * FROM logs ORDER BY created_at DESC LIMIT 200").fetchall()
        logs = []
        for r in rows:
            d = dict(r)
            d["ts"] = d.pop("created_at")
            try:
                d["info"] = json.loads(d.get("info") or "{}")
            except Exception:
                d["info"] = {}
            logs.append(d)
        conn.close()
        return jsonify({"ok": True, "logs": logs})

    # ============ AUTO CLEANUP ============
    if action == "cleanup_expired":
        """
        Xoá các key hết hạn > 24h.
        Trả về danh sách key đã xoá để frontend lưu vào lịch sử.
        """
        now_ms = int(time.time() * 1000)
        cutoff_ms = now_ms - 24 * 3600 * 1000  # Hết hạn > 24h

        rows = c.execute("""
            SELECT * FROM keys
            WHERE type != 'ADMIN'
              AND expires_at IS NOT NULL
              AND expires_at < ?
        """, (cutoff_ms,)).fetchall()

        deleted = []
        for r in rows:
            k = dict(r)
            k["hidden"] = bool(k.get("hidden", 0))
            k["active"] = bool(k.get("active", 1))
            deleted.append(k)
            c.execute("DELETE FROM keys WHERE id=?", (k["id"],))
            log_action(k["key"], "auto_cleanup_expired", None, None, {"expires_at": k["expires_at"]})

        conn.commit()
        conn.close()

        return jsonify({
            "ok": True,
            "deleted_count": len(deleted),
            "deleted_keys": deleted
        })

    conn.close()
    return jsonify({"ok": False, "error": "Action không hợp lệ"}), 400


# ==============================================================
# ADMIN WEB UI (giữ nguyên)
# ==============================================================

ADMIN_HTML = r"""
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>⚡ LP-TOOL KEY ADMIN v2 ⚡</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Segoe UI', Roboto, sans-serif; }
  :root {
    --cyan: #00d4ff; --blue: #2563eb; --blue-light: #60a5fa;
    --navy: #0b1a33; --bg: #050a14;
    --green: #00e676; --yellow: #ffd740; --red: #ff4d6d; --gray: #7a8ca3; --white: #eaf2ff;
  }
  body {
    background: radial-gradient(ellipse at top, #0a1a3a 0%, #050a14 60%);
    color: var(--white); min-height: 100vh; padding: 20px;
  }
  .container { max-width: 1200px; margin: 0 auto; }
  .header { text-align: center; margin-bottom: 24px; }
  .logo {
    font-size: 38px; font-weight: 900;
    background: linear-gradient(135deg, var(--cyan), var(--blue-light), var(--cyan));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    letter-spacing: 4px;
  }
  .subtitle { color: var(--gray); font-size: 12px; letter-spacing: 2px; text-transform: uppercase; }
  .card {
    background: linear-gradient(145deg, rgba(11,26,51,0.85), rgba(5,10,20,0.95));
    border: 1px solid rgba(0,212,255,0.25); border-radius: 16px;
    padding: 24px; margin-bottom: 20px;
    box-shadow: 0 8px 40px rgba(0,0,0,0.5);
  }
  .card-title {
    font-size: 16px; color: var(--cyan); margin-bottom: 16px;
    padding-bottom: 10px; border-bottom: 1px solid rgba(0,212,255,0.15);
    letter-spacing: 1px; display: flex; align-items: center; gap: 8px;
  }
  label { display: block; color: var(--gray); font-size: 11px; margin-bottom: 6px; text-transform: uppercase; font-weight: 600; }
  input, select, textarea {
    width: 100%; padding: 12px 14px;
    background: rgba(5,10,20,0.8); border: 1px solid rgba(0,212,255,0.25);
    border-radius: 8px; color: var(--white); font-size: 14px; outline: none;
    font-family: 'Consolas', monospace;
  }
  input:focus, select:focus { border-color: var(--cyan); box-shadow: 0 0 0 3px rgba(0,212,255,0.15); }
  .grid { display: grid; gap: 12px; }
  .grid-3 { grid-template-columns: 1fr 1fr 1fr; }
  @media (max-width: 700px) { .grid-3 { grid-template-columns: 1fr; } }
  .btn {
    padding: 12px 20px; border: none; border-radius: 8px;
    font-size: 14px; font-weight: 700; letter-spacing: 1px;
    cursor: pointer; transition: all 0.2s; text-transform: uppercase;
  }
  .btn-primary { background: linear-gradient(135deg, var(--cyan), var(--blue)); color: #050a14; }
  .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(0,212,255,0.55); }
  .btn-danger { background: linear-gradient(135deg, var(--red), #b91c3c); color: white; }
  .btn-warn { background: linear-gradient(135deg, var(--yellow), #f59e0b); color: #050a14; }
  .btn-info { background: linear-gradient(135deg, #00d4ff, #2563eb); color: #050a14; }
  .btn-info:hover { transform: translateY(-2px); }
  .btn-gray { background: linear-gradient(135deg, #7a8ca3, #4b5563); color: white; }
  .btn-gray:hover { transform: translateY(-2px); }
  .btn-small { padding: 6px 12px; font-size: 11px; }
  .btn-row { display: flex; gap: 8px; flex-wrap: wrap; }
  .key-item {
    background: rgba(5,10,20,0.6); border: 1px solid rgba(0,212,255,0.15);
    border-radius: 10px; padding: 12px; margin-bottom: 8px;
  }
  .key-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; flex-wrap: wrap; gap: 6px; }
  .badge { padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; }
  .badge-vip1 { background: rgba(0,230,118,0.15); color: var(--green); }
  .badge-vip3 { background: rgba(96,165,250,0.15); color: var(--blue-light); }
  .badge-super { background: rgba(255,215,64,0.15); color: var(--yellow); }
  .badge-admin { background: rgba(255,77,109,0.15); color: var(--red); }
  .badge-active { background: rgba(0,230,118,0.15); color: var(--green); }
  .badge-revoked { background: rgba(255,77,109,0.15); color: var(--red); }
  .badge-expired { background: rgba(122,140,163,0.15); color: var(--gray); }
  .badge-hidden-key { background: rgba(122,140,163,0.25); color: #aaa; }
  .key-value {
    font-family: 'Consolas', monospace; font-size: 12px;
    color: var(--cyan); background: rgba(0,0,0,0.4);
    padding: 8px 10px; border-radius: 6px;
    word-break: break-all; user-select: all; margin: 6px 0;
  }
  .key-meta { display: flex; gap: 12px; font-size: 11px; color: var(--gray); flex-wrap: wrap; margin-top: 6px; }
  .key-meta span { color: var(--white); font-weight: 600; }
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
  @media (max-width: 700px) { .stats { grid-template-columns: 1fr 1fr; } }
  .stat-item {
    background: rgba(0,212,255,0.05); border: 1px solid rgba(0,212,255,0.15);
    border-radius: 10px; padding: 14px; text-align: center;
  }
  .stat-value { font-size: 24px; font-weight: 800; color: var(--cyan); }
  .stat-label { font-size: 11px; color: var(--gray); text-transform: uppercase; margin-top: 4px; }
  .toast {
    position: fixed; top: 20px; right: 20px; padding: 12px 20px;
    border-radius: 10px; font-size: 13px; font-weight: 600;
    z-index: 9999; opacity: 0; transform: translateX(100%);
    transition: all 0.3s; max-width: 320px;
  }
  .toast.show { opacity: 1; transform: translateX(0); }
  .toast-success { background: linear-gradient(135deg, #00e676, #00b050); color: #050a14; }
  .toast-error { background: linear-gradient(135deg, #ff4d6d, #b91c3c); color: white; }
  .toast-info { background: linear-gradient(135deg, #00d4ff, #2563eb); color: #050a14; }
  .login-screen { display: flex; align-items: center; justify-content: center; min-height: 70vh; }
  .login-card { max-width: 400px; width: 100%; }
  .hidden { display: none !important; }
  .mt-10 { margin-top: 10px; }
  .filter-row { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
  .tab-active { background: linear-gradient(135deg, #00d4ff, #2563eb) !important; color: #050a14 !important; }
</style>
</head>
<body>
<div class="container">

  <!-- LOGIN -->
  <div id="loginScreen" class="login-screen">
    <div class="card login-card">
      <div class="header">
        <div class="logo">LP KEY v2</div>
        <div class="subtitle">⚡ ADMIN PANEL ⚡</div>
      </div>
      <div class="grid">
        <div>
          <label>🔑 Admin Secret</label>
          <input type="password" id="adminSecret" placeholder="Nhập admin secret...">
        </div>
        <button class="btn btn-primary" onclick="doLogin()">🚀 ĐĂNG NHẬP</button>
      </div>
    </div>
  </div>

  <!-- MAIN -->
  <div id="mainPanel" class="hidden">
    <div class="header">
      <div class="logo">LP KEY ADMIN v2</div>
      <div class="subtitle">⚡ RENDER + SQLITE + HIDE + CLEANUP ⚡</div>
    </div>

    <!-- STATS -->
    <div class="card">
      <div class="card-title">📊 THỐNG KÊ</div>
      <div class="stats">
        <div class="stat-item"><div class="stat-value" id="statTotal">-</div><div class="stat-label">Tổng key</div></div>
        <div class="stat-item"><div class="stat-value" id="statActive" style="color:var(--green)">-</div><div class="stat-label">Hoạt động</div></div>
        <div class="stat-item"><div class="stat-value" id="statUsed" style="color:var(--cyan)">-</div><div class="stat-label">Đã kích hoạt</div></div>
        <div class="stat-item"><div class="stat-value" id="statHidden" style="color:var(--gray)">-</div><div class="stat-label">Đã ẩn</div></div>
      </div>
    </div>

    <!-- CREATE -->
    <div class="card">
      <div class="card-title">🎁 TẠO KEY MỚI</div>
      <div class="grid grid-3">
        <div>
          <label>Loại key</label>
          <select id="newType">
            <option value="VIP1">🔓 VIP 1 (1-7 logic)</option>
            <option value="VIP3">🔐 VIP 3 (1-10 logic)</option>
            <option value="SUPER">👑 SUPER (full)</option>
            <option value="ADMIN">⚡ ADMIN (vĩnh viễn)</option>
          </select>
        </div>
        <div>
          <label>Thời hạn</label>
          <select id="newDuration">
            <option value="24">1 ngày (24h)</option>
            <option value="72">3 ngày (72h)</option>
            <option value="168">1 tuần (168h)</option>
            <option value="720">1 tháng (720h)</option>
            <option value="880800">Vĩnh viễn</option>
          </select>
        </div>
        <div>
          <label>Ghi chú</label>
          <input type="text" id="newNote" placeholder="VD: khách A - 500k">
        </div>
      </div>
      <button class="btn btn-primary mt-10" onclick="createKey()">⚡ TẠO KEY</button>
      <div id="newKeyResult" class="hidden mt-10">
        <div class="key-value" id="newKeyValue"></div>
        <div class="btn-row mt-10">
          <button class="btn btn-primary btn-small" onclick="copyKey()">📋 Copy</button>
          <button class="btn btn-danger btn-small" onclick="hideNewKey()">✖ Đóng</button>
        </div>
      </div>
    </div>

    <!-- KEYS LIST -->
    <div class="card">
      <div class="card-title">
        📋 DANH SÁCH KEY
        <button class="btn btn-primary btn-small" style="margin-left:auto" onclick="loadKeys()">🔄 Refresh</button>
      </div>

      <!-- TABS -->
      <div class="filter-row" style="margin-bottom:12px;">
        <button class="btn btn-small tab-active" id="tabMain" onclick="switchTab('main')">📋 Key chính</button>
        <button class="btn btn-gray btn-small" id="tabHidden" onclick="switchTab('hidden')">👁️ Key đã ẩn</button>
        <button class="btn btn-gray btn-small" id="tabDeleted" onclick="switchTab('deleted')">🗑️ Lịch sử xoá</button>
      </div>

      <div class="filter-row" id="filterRow">
        <input type="text" id="filterText" placeholder="🔍 Tìm key..." style="flex:1; min-width:200px;" oninput="renderKeys()">
        <select id="filterStatus" onchange="renderKeys()" style="width:auto;">
          <option value="all">Tất cả</option>
          <option value="active">Đang hoạt động</option>
          <option value="used">Đã kích hoạt</option>
          <option value="expired">Hết hạn</option>
          <option value="revoked">Đã thu hồi</option>
        </select>
      </div>
      <div id="keysList"></div>
    </div>

    <!-- DELETED HISTORY -->
    <div class="card">
      <div class="card-title">
        🗑️ LỊCH SỬ KEY ĐÃ XOÁ
        <button class="btn btn-danger btn-small" style="margin-left:auto" onclick="clearDeletedHistory()">🗑️ Xoá lịch sử</button>
      </div>
      <div id="deletedList"></div>
    </div>

    <!-- LOGS -->
    <div class="card">
      <div class="card-title">
        📜 NHẬT KÝ HOẠT ĐỘNG
        <button class="btn btn-primary btn-small" style="margin-left:auto" onclick="loadLogs()">🔄 Refresh</button>
      </div>
      <div id="logsList" style="max-height:400px; overflow-y:auto;"></div>
    </div>

    <div class="card" style="text-align:center">
      <button class="btn btn-danger" onclick="doLogout()">🚪 ĐĂNG XUẤT</button>
    </div>
  </div>
</div>

<div id="toast" class="toast"></div>

<script>
const API_BASE = window.location.origin;
let adminSecret = '';
let cachedKeys = [];
let currentTab = 'main';
let deletedHistory = JSON.parse(localStorage.getItem('lptool_deleted_history') || '[]');

function toast(msg, type = 'success') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show toast-' + type;
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.className = 'toast toast-' + type; }, 3000);
}

async function api(action, data = {}) {
  const r = await fetch(`${API_BASE}/api/admin`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + adminSecret },
    body: JSON.stringify({ action, ...data }),
  });
  const j = await r.json();
  if (!j.ok && j.error === 'Unauthorized') {
    toast('❌ Sai admin secret!', 'error');
    throw new Error('Unauthorized');
  }
  return j;
}

function doLogin() {
  const s = document.getElementById('adminSecret').value.trim();
  if (!s) { toast('⚠️ Nhập secret!', 'error'); return; }
  adminSecret = s;
  sessionStorage.setItem('lptool_admin_secret', s);
  toast('✅ Đăng nhập!', 'success');
  showMain();
}

function doLogout() {
  if (!confirm('Đăng xuất?')) return;
  adminSecret = '';
  sessionStorage.removeItem('lptool_admin_secret');
  document.getElementById('loginScreen').classList.remove('hidden');
  document.getElementById('mainPanel').classList.add('hidden');
}

function showMain() {
  document.getElementById('loginScreen').classList.add('hidden');
  document.getElementById('mainPanel').classList.remove('hidden');
  loadStats(); loadKeys(); loadLogs(); switchTab('main');
}

let lastKey = null;

async function createKey() {
  const type = document.getElementById('newType').value;
  const duration = parseInt(document.getElementById('newDuration').value);
  const note = document.getElementById('newNote').value.trim();
  try {
    const j = await api('create', { type, duration_hours: duration, note, created_by: 'admin' });
    if (!j.ok) { toast('❌ ' + j.error, 'error'); return; }
    lastKey = j.key;
    document.getElementById('newKeyValue').textContent = j.key;
    document.getElementById('newKeyResult').classList.remove('hidden');
    toast('🎉 Tạo key thành công!', 'success');
    loadStats(); loadKeys();
  } catch (e) { toast('❌ ' + e.message, 'error'); }
}

function copyKey() {
  if (!lastKey) return;
  navigator.clipboard.writeText(lastKey).then(() => toast('📋 Đã copy!', 'success'));
}

function hideNewKey() {
  document.getElementById('newKeyResult').classList.add('hidden');
  lastKey = null;
}

function switchTab(tab) {
  currentTab = tab;
  const tabs = {
    main: document.getElementById('tabMain'),
    hidden: document.getElementById('tabHidden'),
    deleted: document.getElementById('tabDeleted'),
  };
  Object.keys(tabs).forEach(k => {
    const el = tabs[k];
    if (!el) return;
    el.classList.remove('tab-active');
    el.className = (k === tab)
      ? 'btn btn-info btn-small tab-active'
      : 'btn btn-gray btn-small';
  });

  const filterRow = document.getElementById('filterRow');
  const keysList = document.getElementById('keysList');

  if (tab === 'deleted') {
    filterRow.style.display = 'none';
    keysList.style.display = 'none';
    renderDeletedHistory();
  } else {
    filterRow.style.display = 'flex';
    keysList.style.display = 'block';
    renderKeys();
  }
}

function getKeyStatus(k) {
  const now = Date.now();
  if (!k.active) return 'revoked';
  if (k.expires_at < now && k.type !== 'ADMIN') return 'expired';
  return 'active';
}

function isHiddenKey(k) { return k.hidden === true; }

function formatTime(ts) {
  if (!ts) return '-';
  return new Date(ts).toLocaleString('vi-VN', { day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' });
}

function formatDuration(ms) {
  if (ms <= 0) return 'Đã hết';
  const days = Math.floor(ms / 86400000);
  const hours = Math.floor((ms % 86400000) / 3600000);
  if (days > 0) return `${days}d ${hours}h`;
  return `${hours}h`;
}

async function loadKeys() {
  try {
    const j = await api('list');
    if (!j.ok) return;
    cachedKeys = j.keys || [];
    await autoCleanupExpired();
    renderKeys();
  } catch (e) { toast('❌ ' + e.message, 'error'); }
}

async function autoCleanupExpired() {
  try {
    const j = await api('cleanup_expired');
    if (!j.ok || !j.deleted_count) return;

    for (const k of j.deleted_keys) {
      deletedHistory.unshift({
        ...k,
        deleted_at: new Date().toLocaleString('vi-VN'),
        delete_reason: 'Hết hạn (tự động)',
        delete_reason_type: 'expired',
      });
    }
    if (deletedHistory.length > 100) deletedHistory = deletedHistory.slice(0, 100);
    saveDeletedHistory();

    toast(`🧹 Đã dọn ${j.deleted_count} key hết hạn`, 'info');

    // Reload lại danh sách
    const j2 = await api('list');
    if (j2.ok) cachedKeys = j2.keys || [];
  } catch (e) {
    console.warn('Cleanup fail:', e);
  }
}

function renderKeys() {
  const box = document.getElementById('keysList');
  const filterText = (document.getElementById('filterText').value || '').toLowerCase();
  const filterStatus = document.getElementById('filterStatus').value;
  const now = Date.now();

  let list = cachedKeys.filter(k => {
    if (currentTab === 'main' && isHiddenKey(k)) return false;
    if (currentTab === 'hidden' && !isHiddenKey(k)) return false;
    if (filterText && !k.key.toLowerCase().includes(filterText) && !(k.note || '').toLowerCase().includes(filterText)) return false;
    const st = getKeyStatus(k);
    if (filterStatus === 'active' && st !== 'active') return false;
    if (filterStatus === 'expired' && st !== 'expired') return false;
    if (filterStatus === 'revoked' && st !== 'revoked') return false;
    if (filterStatus === 'used' && !k.device_id) return false;
    return true;
  });

  if (!list.length) {
    box.innerHTML = '<div style="text-align:center; padding:30px; color:var(--gray);">📭 Không có key</div>';
    return;
  }

  box.innerHTML = list.map(k => {
    const st = getKeyStatus(k);
    const hidden = isHiddenKey(k);
    const statusBadge = st === 'active' ? '<span class="badge badge-active">✅ ACTIVE</span>'
      : st === 'expired' ? '<span class="badge badge-expired">⏰ HẾT HẠN</span>'
      : '<span class="badge badge-revoked">❌ THU HỒI</span>';
    const hiddenBadge = hidden ? '<span class="badge badge-hidden-key">👁️ ĐÃ ẨN</span>' : '';
    const typeBadge = {
      VIP1: '<span class="badge badge-vip1">🔓 VIP1</span>',
      VIP3: '<span class="badge badge-vip3">🔐 VIP3</span>',
      SUPER: '<span class="badge badge-super">👑 SUPER</span>',
      ADMIN: '<span class="badge badge-admin">⚡ ADMIN</span>',
    }[k.type] || '';
    const remain = k.type === 'ADMIN' ? 'VĨNH VIỄN' : formatDuration(k.expires_at - now);
    const deviceShort = k.device_id ? k.device_id.substring(0, 16) + '...' : 'chưa dùng';

    return `
      <div class="key-item" style="${hidden ? 'opacity:0.6; border-color:#555;' : ''}">
        <div class="key-header">
          <div style="display:flex; gap:6px; flex-wrap:wrap;">${typeBadge} ${statusBadge} ${hiddenBadge}</div>
          <div style="font-size:11px; color:var(--gray);">🕐 ${formatTime(k.created_at)}</div>
        </div>
        <div class="key-value">${k.key}</div>
        <div class="key-meta">
          <div>⏱️ Còn: <span>${remain}</span></div>
          <div>👤 <span>${k.created_by || '-'}</span></div>
          <div>📱 <span>${deviceShort}</span></div>
          <div>🔢 <span>${k.use_count || 0} lần</span></div>
          ${k.note ? `<div>📝 <span>${k.note}</span></div>` : ''}
        </div>
        <div class="btn-row mt-10">
          <button class="btn btn-primary btn-small" onclick="copyAnyKey('${k.key}')">📋 Copy</button>
          ${st === 'active'
            ? `<button class="btn btn-warn btn-small" onclick="revokeKey('${k.key}')">🚫 Thu hồi</button>`
            : `<button class="btn btn-info btn-small" onclick="activateKey('${k.key}')">⚡ Activa</button>`}
          ${k.device_id ? `<button class="btn btn-warn btn-small" onclick="resetDevice('${k.key}')">📱 Reset</button>` : ''}
          <button class="btn btn-primary btn-small" onclick="extendKey('${k.key}')">➕ Gia hạn</button>
          <button class="btn btn-gray btn-small" onclick="toggleHideKey('${k.key}')">
            ${hidden ? '👁️ Hiện' : '🙈 Ẩn'}
          </button>
          <button class="btn btn-danger btn-small" onclick="deleteKey('${k.key}')">🗑️ Xoá</button>
        </div>
      </div>`;
  }).join('');
}

function renderDeletedHistory() {
  const box = document.getElementById('deletedList');
  if (!deletedHistory.length) {
    box.innerHTML = '<div style="text-align:center; padding:30px; color:var(--gray);">📭 Chưa có key nào bị xoá</div>';
    return;
  }

  box.innerHTML = deletedHistory.map(k => {
    const typeBadge = {
      VIP1: '<span class="badge badge-vip1">🔓 VIP1</span>',
      VIP3: '<span class="badge badge-vip3">🔐 VIP3</span>',
      SUPER: '<span class="badge badge-super">👑 SUPER</span>',
      ADMIN: '<span class="badge badge-admin">⚡ ADMIN</span>',
    }[k.type] || '';

    const reason = k.delete_reason || 'Đã xoá';
    const reasonColor = {
      'expired': 'var(--gray)',
      'manual': 'var(--red)',
      'revoked': 'var(--red)',
    }[k.delete_reason_type] || 'var(--yellow)';

    return `
      <div class="key-item" style="opacity:0.85;">
        <div class="key-header">
          <div style="display:flex; gap:6px; flex-wrap:wrap;">
            ${typeBadge}
            <span class="badge" style="background:rgba(255,77,109,0.15); color:${reasonColor};">🗑️ ${reason}</span>
          </div>
          <div style="font-size:11px; color:var(--gray);">🕐 ${k.deleted_at || '-'}</div>
        </div>
        <div class="key-value" style="color:#888;">${k.key}</div>
        <div class="key-meta">
          <div>⏱️ Hết hạn: <span>${formatTime(k.expires_at)}</span></div>
          <div>👤 <span>${k.created_by || '-'}</span></div>
          <div>📱 <span>${(k.device_id || 'chưa dùng').substring(0, 16)}...</span></div>
          <div>🔢 <span>${k.use_count || 0} lần</span></div>
          ${k.note ? `<div>📝 <span>${k.note}</span></div>` : ''}
        </div>
      </div>`;
  }).join('');
}

function clearDeletedHistory() {
  if (!confirm('Xoá toàn bộ lịch sử key đã xoá?')) return;
  deletedHistory = [];
  saveDeletedHistory();
  renderDeletedHistory();
  toast('🗑️ Đã xoá lịch sử', 'success');
}

function saveDeletedHistory() {
  localStorage.setItem('lptool_deleted_history', JSON.stringify(deletedHistory));
}

function copyAnyKey(k) { navigator.clipboard.writeText(k).then(() => toast('📋 Copy!', 'success')); }

async function revokeKey(key) {
  const reason = prompt('Lý do thu hồi?', 'Admin revoked');
  if (reason === null) return;
  const j = await api('revoke', { key, reason });
  if (j.ok) { toast('🚫 Đã thu hồi', 'success'); loadKeys(); loadStats(); }
  else toast('❌ ' + j.error, 'error');
}

async function activateKey(key) {
  if (!confirm('Kích hoạt lại key này?')) return;
  const j = await api('reactivate', { key });
  if (j.ok) { toast('⚡ Đã kích hoạt lại', 'success'); loadKeys(); loadStats(); }
  else toast('❌ ' + j.error, 'error');
}

async function resetDevice(key) {
  if (!confirm('Reset device cho key này?')) return;
  const j = await api('reset_device', { key });
  if (j.ok) { toast('📱 Đã reset', 'success'); loadKeys(); }
  else toast('❌ ' + j.error, 'error');
}

async function extendKey(key) {
  const h = prompt('Gia hạn bao nhiêu giờ?', '24');
  if (!h) return;
  const j = await api('extend', { key, hours: parseInt(h) });
  if (j.ok) { toast('➕ Đã gia hạn', 'success'); loadKeys(); loadStats(); }
  else toast('❌ ' + j.error, 'error');
}

async function toggleHideKey(key) {
  const j = await api('toggle_hide', { key });
  if (j.ok) {
    toast(j.hidden ? '🙈 Đã ẩn key' : '👁️ Đã hiện key', 'success');
    loadKeys();
  } else toast('❌ ' + j.error, 'error');
}

async function deleteKey(key) {
  if (!confirm('XOÁ VĨNH VIỄN key này?')) return;
  const reason = prompt('Lý do xoá?', 'Admin xoá thủ công');
  if (reason === null) return;

  const keyData = cachedKeys.find(k => k.key === key);
  if (keyData) {
    deletedHistory.unshift({
      ...keyData,
      deleted_at: new Date().toLocaleString('vi-VN'),
      delete_reason: reason,
      delete_reason_type: 'manual',
    });
    if (deletedHistory.length > 100) deletedHistory = deletedHistory.slice(0, 100);
    saveDeletedHistory();
  }

  const j = await api('delete', { key });
  if (j.ok) { toast('🗑️ Đã xoá', 'success'); loadKeys(); loadStats(); }
  else toast('❌ ' + j.error, 'error');
}

async function loadStats() {
  const j = await api('stats');
  if (!j.ok) return;
  document.getElementById('statTotal').textContent = j.stats.total;
  document.getElementById('statActive').textContent = j.stats.active;
  document.getElementById('statUsed').textContent = j.stats.used;
  document.getElementById('statHidden').textContent = j.stats.hidden || 0;
}

async function loadLogs() {
  const j = await api('logs');
  if (!j.ok) return;
  const box = document.getElementById('logsList');
  if (!j.logs.length) { box.innerHTML = '<div style="text-align:center; padding:20px; color:var(--gray);">📭 Chưa có log</div>'; return; }
  box.innerHTML = j.logs.map(l => {
    const time = new Date(l.ts).toLocaleString('vi-VN');
    const color = { create:'var(--green)', validate_ok:'var(--cyan)', bind_device:'var(--yellow)', revoke:'var(--red)', delete:'var(--red)', extend:'var(--green)', toggle_hide:'var(--gray)', reactivate:'var(--cyan)', auto_cleanup_expired:'var(--gray)' }[l.action] || 'var(--white)';
    return `<div style="padding:8px; border-bottom:1px solid rgba(0,212,255,0.1); font-size:12px;">
      <span style="color:${color}; font-weight:700;">${l.action}</span>
      <span style="color:var(--gray); margin-left:8px;">${time}</span>
      <div style="color:var(--cyan); font-family:monospace; margin-top:4px; word-break:break-all;">${l.key || ''}</div>
    </div>`;
  }).join('');
}

(function init() {
  const saved = sessionStorage.getItem('lptool_admin_secret');
  if (saved) { adminSecret = saved; showMain(); }
  document.getElementById('adminSecret').addEventListener('keypress', e => { if (e.key === 'Enter') doLogin(); });
  document.getElementById('newType').addEventListener('change', e => {
    const dur = document.getElementById('newDuration');
    if (e.target.value === 'ADMIN') dur.value = '880800';
    else if (dur.value === '880800') dur.value = '24';
  });
})();
</script>
</body>
</html>
"""


@app.route("/admin")
def admin_page():
    return render_template_string(ADMIN_HTML)


@app.route("/")
def index():
    return """
    <!DOCTYPE html><html><head><meta charset="UTF-8"><title>LP-TOOL KEY SERVER v2</title>
    <style>
      body { background:#050a14; color:#eaf2ff; font-family:sans-serif;
             display:flex; align-items:center; justify-content:center;
             min-height:100vh; margin:0; text-align:center; }
      .box { max-width:500px; padding:40px; }
      h1 { color:#00d4ff; font-size:48px; letter-spacing:6px; margin:0 0 10px; }
      p { color:#7a8ca3; }
      a { display:inline-block; margin-top:20px; padding:12px 30px;
          background:linear-gradient(135deg,#00d4ff,#2563eb); color:#050a14;
          text-decoration:none; border-radius:8px; font-weight:700; }
    </style></head><body>
    <div class="box">
      <h1>LP KEY v2</h1>
      <p>Server đang chạy. Truy cập /admin để quản lý key.</p>
      <a href="/admin">🚀 VÀO ADMIN</a>
    </div>
    </body></html>
    """


# ==============================================================
# INIT & RUN
# ==============================================================

init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
