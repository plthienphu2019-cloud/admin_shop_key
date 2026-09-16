# -*- coding: utf-8 -*-
# ==============================================================
# LP-TOOL KEY SERVER — Render.com Edition
# Admin: Thiên Phú - Minh Lâm
# Key chỉ tính hạn từ lúc user nhập lần đầu + Nút Active toggle
# ==============================================================

from __future__ import annotations

import os
import sqlite3
import time
import random
import json
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, render_template_string, Response

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
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            type TEXT NOT NULL,
            duration_hours INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            active INTEGER DEFAULT 0,
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
    c.execute("CREATE INDEX IF NOT EXISTS idx_keys_key ON keys(key)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_keys_device ON keys(device_id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_keys_active ON keys(active)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_logs_key ON logs(key)")
    conn.commit()
    conn.close()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def log_action(key, action, device_id=None, ip=None, info=None):
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

def rand_str(n):
    return "".join(random.choice(CHARS) for _ in range(n))


def generate_key(key_type):
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
# ADMIN AUTH
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
# API: VALIDATE — Timer bắt đầu khi user nhập key lần đầu
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

    # ⚡ CHECK ACTIVE — key phải được Admin bật mới dùng được
    if row["active"] != 1:
        log_action(key_str, "validate_failed_not_active", device_id, ip)
        conn.close()
        return jsonify({
            "ok": False,
            "error": "Key chưa Active, Vui lòng báo Admin",
            "need_activation": True
        }), 403

    # ⚡ KEY CHƯA DÙNG LẦN NÀO → BẮT ĐẦU TÍNH HẠN TỪ BÂY GIỜ
    if not row["first_used_at"]:
        # set expires_at = now + duration_hours
        new_expires = now_ms + int(row["duration_hours"]) * 3600 * 1000
        c.execute("""
            UPDATE keys SET
                first_used_at = ?,
                expires_at = ?,
                device_id = ?,
                device_fingerprint = ?,
                last_seen = ?,
                last_ip = ?,
                use_count = 1
            WHERE id = ?
        """, (now_ms, new_expires, device_id, fingerprint, now_ms, ip, row["id"]))
        conn.commit()
        log_action(key_str, "first_use_start_timer", device_id, ip,
                   {"duration_hours": row["duration_hours"], "expires_at": new_expires})
        conn.close()
        return jsonify({
            "ok": True,
            "key_type": row["type"],
            "duration_hours": row["duration_hours"],
            "expires_at": new_expires,
            "is_admin": row["type"] == "ADMIN",
            "created_by": row["created_by"],
            "message": "Kích hoạt lần đầu thành công — bắt đầu tính hạn"
        })

    # ⚡ KEY ĐÃ DÙNG → check hết hạn
    if row["expires_at"] < now_ms and row["type"] != "ADMIN":
        log_action(key_str, "validate_failed_expired", device_id, ip)
        conn.close()
        return jsonify({
            "ok": False,
            "error": "Key đã hết hạn",
            "expired_at": row["expires_at"]
        }), 403

    # ⚡ CHECK DEVICE
    if not row["device_id"]:
        c.execute("""
            UPDATE keys SET device_id=?, device_fingerprint=?, last_seen=?, last_ip=?,
                            use_count = use_count + 1
            WHERE id=?
        """, (device_id, fingerprint, now_ms, ip, row["id"]))
        log_action(key_str, "bind_device", device_id, ip)
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
        c.execute("""
            UPDATE keys SET last_seen=?, last_ip=?, use_count = use_count + 1
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

    if row["active"] != 1:
        conn.close()
        return jsonify({"ok": False, "error": "Key chưa Active, Vui lòng báo Admin"}), 403

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
# API: ADMIN
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

    # ============ CREATE (mặc định active=0, expires_at=0) ============
    if action == "create":
        key_type = data.get("type", "VIP1")
        duration_hours = int(data.get("duration_hours", 24))
        note = data.get("note", "")
        created_by = data.get("created_by", "admin")
        try:
            quantity = int(data.get("quantity", 1))
        except Exception:
            quantity = 1
        quantity = max(1, min(quantity, 100))

        if key_type not in ("VIP1", "VIP3", "SUPER", "ADMIN"):
            conn.close()
            return jsonify({"ok": False, "error": "Loại key không hợp lệ"}), 400

        if key_type == "ADMIN":
            duration_hours = 36700 * 24

        now_ms = int(time.time() * 1000)

        created_keys = []
        for _ in range(quantity):
            for _attempt in range(10):
                key_str = generate_key(key_type)
                exists = c.execute("SELECT 1 FROM keys WHERE key=?", (key_str,)).fetchone()
                if not exists:
                    break
            try:
                # ⚡ active=0 mặc định, expires_at=0 (chưa tính)
                c.execute("""
                    INSERT INTO keys (key, type, duration_hours, created_at, expires_at,
                                      active, created_by, note)
                    VALUES (?, ?, ?, ?, 0, 0, ?, ?)
                """, (key_str, key_type, duration_hours, now_ms, created_by, note))
                created_keys.append(key_str)
            except sqlite3.IntegrityError:
                continue

        conn.commit()
        for k in created_keys:
            log_action(k, "create", None, None,
                       {"type": key_type, "duration": duration_hours,
                        "created_by": created_by, "batch": quantity})

        conn.close()
        return jsonify({
            "ok": True,
            "keys": created_keys,
            "quantity": len(created_keys),
            "info": {
                "type": key_type,
                "duration_hours": duration_hours,
                "created_at": now_ms,
                "expires_at": 0,
                "active": 0,
                "created_by": created_by,
                "note": note,
            }
        })

    # ============ LIST ============
    if action == "list":
        rows = c.execute("SELECT * FROM keys ORDER BY created_at DESC").fetchall()
        keys = [dict(r) for r in rows]
        conn.close()
        return jsonify({"ok": True, "keys": keys, "total": len(keys)})

    # ============ SET ACTIVE ============
    if action == "set_active":
        key_str = data.get("key")
        try:
            value = int(data.get("value", 1))
        except Exception:
            conn.close()
            return jsonify({"ok": False, "error": "value không hợp lệ"}), 400
        value = 1 if value else 0

        row = c.execute("SELECT * FROM keys WHERE key=?", (key_str,)).fetchone()
        if not row:
            conn.close()
            return jsonify({"ok": False, "error": "Key không tồn tại"}), 404

        c.execute("UPDATE keys SET active=? WHERE key=?", (value, key_str))
        conn.commit()
        log_action(key_str, "set_active", None, None, {"value": value})
        conn.close()
        msg = "✅ Đã bật Active" if value == 1 else "⏸️ Đã tắt Active"
        return jsonify({"ok": True, "message": msg, "active": value})

    # ============ BULK ACTIVE ============
    if action == "bulk_active":
        keys = data.get("keys") or []
        try:
            value = 1 if int(data.get("value", 1)) else 0
        except Exception:
            value = 1
        if not isinstance(keys, list) or not keys:
            conn.close()
            return jsonify({"ok": False, "error": "Thiếu danh sách key"}), 400

        for k in keys:
            c.execute("UPDATE keys SET active=? WHERE key=?", (value, k))
            log_action(k, "set_active_bulk", None, None, {"value": value})
        conn.commit()
        conn.close()
        return jsonify({"ok": True, "count": len(keys), "active": value})

    # ============ DELETE ============
    if action == "delete":
        key_str = data.get("key")
        c.execute("DELETE FROM keys WHERE key=?", (key_str,))
        conn.commit()
        log_action(key_str, "delete")
        conn.close()
        return jsonify({"ok": True, "message": "Đã xoá key"})

    # ============ RESET DEVICE ============
    if action == "reset_device":
        key_str = data.get("key")
        c.execute("""
            UPDATE keys SET device_id=NULL, device_fingerprint=NULL,
                            first_used_at=NULL, expires_at=0
            WHERE key=?
        """, (key_str,))
        conn.commit()
        log_action(key_str, "reset_device")
        conn.close()
        return jsonify({"ok": True, "message": "Đã reset device và hạn"})

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
        base = max(row["expires_at"] or 0, now_ms)
        new_exp = base + hours * 3600 * 1000
        c.execute("""
            UPDATE keys SET expires_at=?, active=1, duration_hours=duration_hours+?
            WHERE key=?
        """, (new_exp, hours, key_str))
        conn.commit()
        log_action(key_str, "extend", None, None, {"hours": hours})
        conn.close()
        return jsonify({"ok": True, "message": "Đã gia hạn", "expires_at": new_exp})

    # ============ STATS ============
    if action == "stats":
        total = c.execute("SELECT COUNT(*) FROM keys").fetchone()[0]
        now_ms = int(time.time() * 1000)
        used = c.execute("SELECT COUNT(*) FROM keys WHERE first_used_at IS NOT NULL").fetchone()[0]
        not_active = c.execute("SELECT COUNT(*) FROM keys WHERE active=0").fetchone()[0]
        active = c.execute("SELECT COUNT(*) FROM keys WHERE active=1").fetchone()[0]
        # key còn hạn (đã active + đã dùng + chưa hết hạn)
        running = c.execute("""
            SELECT COUNT(*) FROM keys
            WHERE active=1 AND first_used_at IS NOT NULL AND (expires_at > ? OR type='ADMIN')
        """, (now_ms,)).fetchone()[0]

        by_type = {}
        for t in ("VIP1", "VIP3", "SUPER", "ADMIN"):
            by_type[t] = c.execute("SELECT COUNT(*) FROM keys WHERE type=?", (t,)).fetchone()[0]

        conn.close()
        return jsonify({
            "ok": True,
            "stats": {
                "total": total, "active": active, "notActive": not_active,
                "used": used, "running": running, "byType": by_type
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

    # ============ EXPORT ============
    if action == "export":
        mode = (data.get("mode") or "all").strip().lower()
        filename = (data.get("filename") or "").strip()
        if not filename:
            filename = f"keys_{mode}_{int(time.time())}.txt"
        if not filename.endswith(".txt"):
            filename += ".txt"

        if mode == "active":
            rows = c.execute("SELECT key, type, expires_at, first_used_at FROM keys WHERE active=1 ORDER BY created_at DESC").fetchall()
        elif mode == "not_active":
            rows = c.execute("SELECT key, type, expires_at, first_used_at FROM keys WHERE active=0 ORDER BY created_at DESC").fetchall()
        else:
            rows = c.execute("SELECT key, type, expires_at, first_used_at FROM keys ORDER BY created_at DESC").fetchall()

        conn.close()

        lines = []
        for r in rows:
            r = dict(r)
            exp = r["expires_at"] or 0
            if r["type"] == "ADMIN":
                exp_str = "NEVER"
            elif exp == 0:
                exp_str = "NOT_STARTED"
            else:
                exp_str = datetime.fromtimestamp(exp / 1000).strftime("%Y-%m-%d %H:%M:%S")
            lines.append(f"{r['key']} | {r['type']} | EXP: {exp_str}")

        content = "\n".join(lines)
        log_action(None, "export", None, None, {"mode": mode, "filename": filename, "count": len(lines)})

        return Response(
            content,
            mimetype="text/plain",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Filename": filename,
                "X-Count": str(len(lines)),
            }
        )

    conn.close()
    return jsonify({"ok": False, "error": "Action không hợp lệ"}), 400


# ==============================================================
# ADMIN HTML
# ==============================================================

ADMIN_HTML = r"""
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>⚡ LP-TOOL KEY ADMIN ⚡</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Segoe UI', Roboto, sans-serif; }
  :root {
    --cyan:#00d4ff; --blue:#2563eb; --blue-light:#60a5fa;
    --green:#00e676; --yellow:#ffd740; --red:#ff4d6d; --gray:#7a8ca3; --white:#eaf2ff;
  }
  body { background: radial-gradient(ellipse at top,#0a1a3a 0%,#050a14 60%);
         color: var(--white); min-height: 100vh; padding: 20px; }
  .container { max-width: 1200px; margin: 0 auto; }
  .header { text-align: center; margin-bottom: 24px; }
  .logo { font-size: 38px; font-weight: 900;
    background: linear-gradient(135deg,var(--cyan),var(--blue-light),var(--cyan));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent; letter-spacing: 4px; }
  .subtitle { color: var(--gray); font-size: 12px; letter-spacing: 2px; text-transform: uppercase; }
  .card { background: linear-gradient(145deg,rgba(11,26,51,0.85),rgba(5,10,20,0.95));
          border: 1px solid rgba(0,212,255,0.25); border-radius: 16px;
          padding: 24px; margin-bottom: 20px; box-shadow: 0 8px 40px rgba(0,0,0,0.5); }
  .card-title { font-size: 16px; color: var(--cyan); margin-bottom: 16px;
    padding-bottom: 10px; border-bottom: 1px solid rgba(0,212,255,0.15);
    letter-spacing: 1px; display: flex; align-items: center; gap: 8px; }
  label { display: block; color: var(--gray); font-size: 11px; margin-bottom: 6px;
    text-transform: uppercase; font-weight: 600; }
  input, select, textarea { width: 100%; padding: 12px 14px;
    background: rgba(5,10,20,0.8); border: 1px solid rgba(0,212,255,0.25);
    border-radius: 8px; color: var(--white); font-size: 14px; outline: none;
    font-family: 'Consolas', monospace; }
  input:focus, select:focus { border-color: var(--cyan); box-shadow: 0 0 0 3px rgba(0,212,255,0.15); }
  .grid { display: grid; gap: 12px; }
  .grid-4 { grid-template-columns: 1fr 1fr 1fr 1fr; }
  .grid-3 { grid-template-columns: 1fr 1fr 1fr; }
  @media (max-width: 700px) {
    .grid-4, .grid-3 { grid-template-columns: 1fr; }
  }
  .btn { padding: 12px 20px; border: none; border-radius: 8px;
    font-size: 14px; font-weight: 700; letter-spacing: 1px;
    cursor: pointer; transition: all 0.2s; text-transform: uppercase; }
  .btn-primary { background: linear-gradient(135deg,var(--cyan),var(--blue)); color: #050a14; }
  .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(0,212,255,0.55); }
  .btn-danger { background: linear-gradient(135deg,var(--red),#b91c3c); color: white; }
  .btn-warn { background: linear-gradient(135deg,var(--yellow),#f59e0b); color: #050a14; }
  .btn-green { background: linear-gradient(135deg,var(--green),#00b050); color: #050a14; }
  .btn-small { padding: 6px 12px; font-size: 11px; }
  .btn-row { display: flex; gap: 8px; flex-wrap: wrap; }
  .key-item { background: rgba(5,10,20,0.6); border: 1px solid rgba(0,212,255,0.15);
    border-radius: 10px; padding: 12px; margin-bottom: 8px; }
  .key-item.not-active { border-color: rgba(255,77,109,0.35); }
  .key-item.running { border-color: rgba(0,230,118,0.35); }
  .key-header { display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 8px; flex-wrap: wrap; gap: 6px; }
  .badge { padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; }
  .badge-vip1 { background: rgba(0,230,118,0.15); color: var(--green); }
  .badge-vip3 { background: rgba(96,165,250,0.15); color: var(--blue-light); }
  .badge-super { background: rgba(255,215,64,0.15); color: var(--yellow); }
  .badge-admin { background: rgba(255,77,109,0.15); color: var(--red); }
  .badge-running { background: rgba(0,230,118,0.2); color: var(--green); }
  .badge-active { background: rgba(0,212,255,0.15); color: var(--cyan); }
  .badge-not-active { background: rgba(255,77,109,0.15); color: var(--red); }
  .badge-expired { background: rgba(122,140,163,0.15); color: var(--gray); }
  .key-value { font-family: 'Consolas', monospace; font-size: 12px;
    color: var(--cyan); background: rgba(0,0,0,0.4);
    padding: 8px 10px; border-radius: 6px;
    word-break: break-all; user-select: all; margin: 6px 0; }
  .key-meta { display: flex; gap: 12px; font-size: 11px; color: var(--gray); flex-wrap: wrap; margin-top: 6px; }
  .key-meta span { color: var(--white); font-weight: 600; }
  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
  @media (max-width: 700px) { .stats { grid-template-columns: 1fr 1fr; } }
  .stat-item { background: rgba(0,212,255,0.05); border: 1px solid rgba(0,212,255,0.15);
    border-radius: 10px; padding: 14px; text-align: center; }
  .stat-value { font-size: 24px; font-weight: 800; color: var(--cyan); }
  .stat-label { font-size: 11px; color: var(--gray); text-transform: uppercase; margin-top: 4px; }
  .toast { position: fixed; top: 20px; right: 20px; padding: 12px 20px;
    border-radius: 10px; font-size: 13px; font-weight: 600;
    z-index: 9999; opacity: 0; transform: translateX(100%);
    transition: all 0.3s; max-width: 320px; }
  .toast.show { opacity: 1; transform: translateX(0); }
  .toast-success { background: linear-gradient(135deg,#00e676,#00b050); color: #050a14; }
  .toast-error { background: linear-gradient(135deg,#ff4d6d,#b91c3c); color: white; }
  .login-screen { display: flex; align-items: center; justify-content: center; min-height: 70vh; }
  .login-card { max-width: 400px; width: 100%; }
  .hidden { display: none !important; }
  .mt-10 { margin-top: 10px; }
  .filter-row { display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }
  .keys-created-list { background: rgba(0,0,0,0.4); border-radius: 8px; padding: 10px;
    max-height: 240px; overflow-y: auto; margin-top: 8px;
    font-family: 'Consolas', monospace; font-size: 12px; color: var(--cyan); }
  .keys-created-list div { padding: 3px 0; border-bottom: 1px dashed rgba(0,212,255,0.15); user-select: all; }
</style>
</head>
<body>
<div class="container">

  <div id="loginScreen" class="login-screen">
    <div class="card login-card">
      <div class="header">
        <div class="logo">LP KEY</div>
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

  <div id="mainPanel" class="hidden">
    <div class="header">
      <div class="logo">LP KEY ADMIN</div>
      <div class="subtitle">⚡ KEY TÍNH HẠN TỪ LÚC DÙNG ⚡</div>
    </div>

    <div class="card">
      <div class="card-title">📊 THỐNG KÊ</div>
      <div class="stats">
        <div class="stat-item"><div class="stat-value" id="statTotal">-</div><div class="stat-label">Tổng key</div></div>
        <div class="stat-item"><div class="stat-value" id="statActive" style="color:var(--cyan)">-</div><div class="stat-label">Đã Active</div></div>
        <div class="stat-item"><div class="stat-value" id="statRunning" style="color:var(--green)">-</div><div class="stat-label">Đang dùng</div></div>
        <div class="stat-item"><div class="stat-value" id="statNotActive" style="color:var(--yellow)">-</div><div class="stat-label">Chưa Active</div></div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">🎁 TẠO KEY MỚI</div>
      <div class="grid grid-4">
        <div>
          <label>Loại key</label>
          <select id="newType">
            <option value="VIP1">🔓 VIP 1</option>
            <option value="VIP3">🔐 VIP 3</option>
            <option value="SUPER">👑 SUPER</option>
            <option value="ADMIN">⚡ ADMIN (vĩnh viễn)</option>
          </select>
        </div>
        <div>
          <label>Thời hạn (tính từ lúc user nhập)</label>
          <select id="newDuration">
            <option value="24">1 ngày (24h)</option>
            <option value="72">3 ngày (72h)</option>
            <option value="168">1 tuần (168h)</option>
            <option value="720">1 tháng (720h)</option>
            <option value="880800">Vĩnh viễn</option>
          </select>
        </div>
        <div>
          <label>Số lượng (1-100)</label>
          <input type="number" id="newQuantity" value="1" min="1" max="100">
        </div>
        <div>
          <label>Ghi chú</label>
          <input type="text" id="newNote" placeholder="VD: khách A">
        </div>
      </div>
      <button class="btn btn-primary mt-10" onclick="createKey()">⚡ TẠO KEY</button>

      <div id="newKeyResult" class="hidden mt-10">
        <label>✅ Đã tạo <span id="newKeyCount">0</span> key (trạng thái: <b style="color:var(--red)">CHƯA ACTIVE</b>)</label>
        <div class="keys-created-list" id="newKeysList"></div>
        <div class="btn-row mt-10">
          <button class="btn btn-primary btn-small" onclick="copyAllNewKeys()">📋 Copy tất cả</button>
          <button class="btn btn-green btn-small" onclick="activateNewKeys()">✅ Bật Active tất cả</button>
          <button class="btn btn-danger btn-small" onclick="hideNewKey()">✖ Đóng</button>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">📥 XUẤT FILE KEY</div>
      <div class="grid grid-3">
        <div>
          <label>Loại xuất</label>
          <select id="exportMode">
            <option value="all">📦 Tất cả</option>
            <option value="active">✅ Chỉ key đã Active</option>
            <option value="not_active">🟡 Chỉ key chưa Active</option>
          </select>
        </div>
        <div>
          <label>Tên file (không cần .txt)</label>
          <input type="text" id="exportFilename" placeholder="VD: key_vip_1">
        </div>
        <div style="display:flex; align-items:flex-end;">
          <button class="btn btn-primary" style="width:100%" onclick="exportKeys()">📥 XUẤT FILE</button>
        </div>
      </div>
      <div class="mt-10" style="font-size:11px; color:var(--gray);">
        💡 Format: <code style="color:var(--cyan)">KEY | TYPE | EXP: YYYY-MM-DD HH:MM:SS</code>
        (EXP = <b>NOT_STARTED</b> nếu user chưa nhập key lần nào)
      </div>
    </div>

    <div class="card">
      <div class="card-title">
        📋 DANH SÁCH KEY
        <button class="btn btn-primary btn-small" style="margin-left:auto" onclick="loadKeys()">🔄 Refresh</button>
      </div>
      <div class="filter-row">
        <input type="text" id="filterText" placeholder="🔍 Tìm key..." style="flex:1; min-width:200px;" oninput="renderKeys()">
        <select id="filterStatus" onchange="renderKeys()" style="width:auto;">
          <option value="all">Tất cả</option>
          <option value="running">Đang dùng</option>
          <option value="active">Đã Active (chưa dùng)</option>
          <option value="not_active">Chưa Active</option>
          <option value="used">Đã kích hoạt</option>
          <option value="expired">Hết hạn</option>
        </select>
      </div>
      <div id="keysList"></div>
    </div>

    <div class="card">
      <div class="card-title">
        📜 NHẬT KÝ
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
let lastNewKeys = [];

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
  loadStats(); loadKeys(); loadLogs();
}

async function createKey() {
  const type = document.getElementById('newType').value;
  const duration = parseInt(document.getElementById('newDuration').value);
  const quantity = parseInt(document.getElementById('newQuantity').value) || 1;
  const note = document.getElementById('newNote').value.trim();
  if (quantity < 1 || quantity > 100) { toast('⚠️ Số lượng phải từ 1-100', 'error'); return; }

  try {
    const j = await api('create', { type, duration_hours: duration, quantity, note, created_by: 'admin' });
    if (!j.ok) { toast('❌ ' + j.error, 'error'); return; }
    lastNewKeys = j.keys || [];
    document.getElementById('newKeyCount').textContent = j.quantity;
    document.getElementById('newKeysList').innerHTML = lastNewKeys.map(k => `<div>${k}</div>`).join('');
    document.getElementById('newKeyResult').classList.remove('hidden');
    toast(`🎉 Tạo ${j.quantity} key thành công!`, 'success');
    loadStats(); loadKeys();
  } catch (e) { toast('❌ ' + e.message, 'error'); }
}

function copyAllNewKeys() {
  if (!lastNewKeys.length) return;
  navigator.clipboard.writeText(lastNewKeys.join('\n')).then(() => toast(`📋 Đã copy ${lastNewKeys.length} key!`, 'success'));
}

async function activateNewKeys() {
  if (!lastNewKeys.length) return;
  if (!confirm(`Bật Active cho ${lastNewKeys.length} key vừa tạo?`)) return;
  const j = await api('bulk_active', { keys: lastNewKeys, value: 1 });
  if (j.ok) {
    toast(`✅ Đã bật Active cho ${j.count} key`, 'success');
    loadKeys(); loadStats();
  }
}

function hideNewKey() {
  document.getElementById('newKeyResult').classList.add('hidden');
  lastNewKeys = [];
}

async function exportKeys() {
  const mode = document.getElementById('exportMode').value;
  let filename = document.getElementById('exportFilename').value.trim();
  if (!filename) {
    const now = new Date();
    const stamp = now.getFullYear() + String(now.getMonth()+1).padStart(2,'0') + String(now.getDate()).padStart(2,'0')
      + '_' + String(now.getHours()).padStart(2,'0') + String(now.getMinutes()).padStart(2,'0');
    filename = `keys_${mode}_${stamp}`;
  }

  try {
    const r = await fetch(`${API_BASE}/api/admin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + adminSecret },
      body: JSON.stringify({ action: 'export', mode, filename }),
    });
    if (!r.ok) { const err = await r.json().catch(() => ({})); toast('❌ ' + (err.error || 'Lỗi xuất file'), 'error'); return; }

    const blob = await r.blob();
    const finalName = r.headers.get('X-Filename') || (filename + '.txt');
    const count = r.headers.get('X-Count') || '0';

    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = finalName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);

    toast(`📥 Đã xuất ${count} key → ${finalName}`, 'success');
  } catch (e) { toast('❌ ' + e.message, 'error'); }
}

async function loadKeys() {
  try {
    const j = await api('list');
    if (!j.ok) return;
    cachedKeys = j.keys || [];
    renderKeys();
  } catch (e) { toast('❌ ' + e.message, 'error'); }
}

// Trạng thái key:
// - not_active: chưa bật nút Active
// - active: đã bật Active nhưng user chưa nhập (chưa tính hạn)
// - running: đã Active + user đã nhập + còn hạn
// - expired: đã Active + user đã nhập + hết hạn
function getKeyStatus(k) {
  const now = Date.now();
  if (k.active != 1) return 'not_active';
  if (!k.first_used_at) return 'active';   // Đã Active nhưng chưa ai dùng
  if (k.expires_at && k.expires_at < now && k.type !== 'ADMIN') return 'expired';
  return 'running';
}

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

function renderKeys() {
  const box = document.getElementById('keysList');
  const filterText = (document.getElementById('filterText').value || '').toLowerCase();
  const filterStatus = document.getElementById('filterStatus').value;
  const now = Date.now();

  let list = cachedKeys.filter(k => {
    if (filterText && !k.key.toLowerCase().includes(filterText) && !(k.note || '').toLowerCase().includes(filterText)) return false;
    const st = getKeyStatus(k);
    if (filterStatus === 'active' && st !== 'active') return false;
    if (filterStatus === 'not_active' && st !== 'not_active') return false;
    if (filterStatus === 'running' && st !== 'running') return false;
    if (filterStatus === 'expired' && st !== 'expired') return false;
    if (filterStatus === 'used' && !k.first_used_at) return false;
    return true;
  });

  if (!list.length) {
    box.innerHTML = '<div style="text-align:center; padding:30px; color:var(--gray);">📭 Không có key</div>';
    return;
  }

  box.innerHTML = list.map(k => {
    const st = getKeyStatus(k);
    const statusBadge =
      st === 'running' ? '<span class="badge badge-running">🟢 ĐANG DÙNG</span>'
      : st === 'active' ? '<span class="badge badge-active">🔵 ĐÃ ACTIVE (chưa dùng)</span>'
      : st === 'not_active' ? '<span class="badge badge-not-active">🔴 CHƯA ACTIVE</span>'
      : '<span class="badge badge-expired">⏰ HẾT HẠN</span>';

    const typeBadge = {
      VIP1: '<span class="badge badge-vip1">🔓 VIP1</span>',
      VIP3: '<span class="badge badge-vip3">🔐 VIP3</span>',
      SUPER: '<span class="badge badge-super">👑 SUPER</span>',
      ADMIN: '<span class="badge badge-admin">⚡ ADMIN</span>',
    }[k.type] || '';

    let remain;
    if (k.type === 'ADMIN') remain = 'VĨNH VIỄN';
    else if (!k.first_used_at) remain = 'Chưa bắt đầu';
    else remain = formatDuration(k.expires_at - now);

    const deviceShort = k.device_id ? k.device_id.substring(0, 16) + '...' : 'chưa dùng';
    const itemClass = st === 'not_active' ? 'key-item not-active' : st === 'running' ? 'key-item running' : 'key-item';

    return `
      <div class="${itemClass}">
        <div class="key-header">
          <div style="display:flex; gap:6px;">${typeBadge} ${statusBadge}</div>
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
          ${k.active == 1
            ? `<button class="btn btn-warn btn-small" onclick="setActive('${k.key}', 0)">⏸️ Tắt Active</button>`
            : `<button class="btn btn-green btn-small" onclick="setActive('${k.key}', 1)">✅ Bật Active</button>`}
          ${k.first_used_at ? `<button class="btn btn-warn btn-small" onclick="resetDevice('${k.key}')">📱 Reset</button>` : ''}
          <button class="btn btn-primary btn-small" onclick="extendKey('${k.key}')">➕ Gia hạn</button>
          <button class="btn btn-danger btn-small" onclick="deleteKey('${k.key}')">🗑️ Xoá</button>
        </div>
      </div>`;
  }).join('');
}

function copyAnyKey(k) { navigator.clipboard.writeText(k).then(() => toast('📋 Copy!', 'success')); }

async function setActive(key, value) {
  const j = await api('set_active', { key, value });
  if (j.ok) {
    toast(value === 1 ? '✅ Đã bật Active' : '⏸️ Đã tắt Active', 'success');
    loadKeys(); loadStats();
  }
}

async function resetDevice(key) {
  if (!confirm('Reset device và hạn? (Key sẽ về trạng thái chưa dùng)')) return;
  const j = await api('reset_device', { key });
  if (j.ok) { toast('📱 Đã reset', 'success'); loadKeys(); loadStats(); }
}
async function extendKey(key) {
  const h = prompt('Gia hạn bao nhiêu giờ?', '24');
  if (!h) return;
  const j = await api('extend', { key, hours: parseInt(h) });
  if (j.ok) { toast('➕ Đã gia hạn', 'success'); loadKeys(); loadStats(); }
}
async function deleteKey(key) {
  if (!confirm('XOÁ VĨNH VIỄN?')) return;
  const j = await api('delete', { key });
  if (j.ok) { toast('🗑️ Đã xoá', 'success'); loadKeys(); loadStats(); }
}

async function loadStats() {
  const j = await api('stats');
  if (!j.ok) return;
  document.getElementById('statTotal').textContent = j.stats.total;
  document.getElementById('statActive').textContent = j.stats.active;
  document.getElementById('statRunning').textContent = j.stats.running;
  document.getElementById('statNotActive').textContent = j.stats.notActive;
}

async function loadLogs() {
  const j = await api('logs');
  if (!j.ok) return;
  const box = document.getElementById('logsList');
  if (!j.logs.length) { box.innerHTML = '<div style="text-align:center; padding:20px; color:var(--gray);">📭 Chưa có log</div>'; return; }
  box.innerHTML = j.logs.map(l => {
    const time = new Date(l.ts).toLocaleString('vi-VN');
    const color = {
      create:'var(--green)', validate_ok:'var(--cyan)', bind_device:'var(--yellow)',
      first_use_start_timer:'var(--green)', set_active:'var(--cyan)',
      set_active_bulk:'var(--cyan)', export:'var(--yellow)',
      validate_failed_not_active:'var(--red)', reset_device:'var(--yellow)',
      delete:'var(--red)', extend:'var(--green)'
    }[l.action] || 'var(--white)';
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
    <!DOCTYPE html><html><head><meta charset="UTF-8"><title>LP-TOOL KEY SERVER</title>
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
      <h1>LP KEY</h1>
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
