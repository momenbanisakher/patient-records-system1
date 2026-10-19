"""سجل التدقيق: كل سجل يحمل تجزئة السجل السابق، فأي تعديل لاحق يكسر السلسلة."""
import json
from datetime import datetime, timezone

from security import sha256_hex

GENESIS = "GENESIS"


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _entry_hash(prev_hash, user_id, username, action, entity, entity_id, details, ip, created_at):
    payload = json.dumps(
        [user_id, username, action, entity, entity_id, details, ip, created_at],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return sha256_hex(prev_hash + payload)


def log_event(db, user, action, entity=None, entity_id=None, details="", ip=None, username=None):
    """يسجل حدثًا. لا يعمل commit، فالمستدعي يحفظه مع التغيير نفسه."""
    last = db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = last["hash"] if last else GENESIS
    user_id = user["id"] if user else None
    uname = user["username"] if user else username
    created_at = _now()
    h = _entry_hash(prev_hash, user_id, uname, action, entity, entity_id, details, ip, created_at)
    db.execute(
        "INSERT INTO audit_log (user_id, username, action, entity, entity_id, details, ip,"
        " created_at, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (user_id, uname, action, entity, entity_id, details, ip, created_at, prev_hash, h),
    )


def verify_chain(db):
    """يعيد (True, عدد_السجلات, None) أو (False, عدد_السجلات, رقم_أول_سجل_تالف)."""
    rows = db.execute("SELECT * FROM audit_log ORDER BY id ASC").fetchall()
    prev = GENESIS
    for row in rows:
        expected = _entry_hash(
            prev, row["user_id"], row["username"], row["action"], row["entity"],
            row["entity_id"], row["details"], row["ip"], row["created_at"],
        )
        if row["prev_hash"] != prev or row["hash"] != expected:
            return False, len(rows), row["id"]
        prev = row["hash"]
    return True, len(rows), None
