"""بصمة السلامة (SHA-256) لملف المريض.

البصمة تُحسب من بيانات المريض وزياراته ونتائج فحوصاته معًا، وتُخزَّن مع الملف.
أي تعديل مباشر على قاعدة البيانات (خارج النظام) يجعل البصمة المحسوبة تختلف عن المخزَّنة،
فيُكتشف التلاعب عند الفحص.
"""
import json
import sqlite3

from security import sha256_hex

PATIENT_FIELDS = (
    "file_no", "full_name", "dob", "gender", "phone", "address", "blood_type",
    "allergies", "chronic_conditions", "emergency_contact", "national_id_hash",
    "national_id_last4", "created_at",
)
VISIT_FIELDS = ("id", "doctor_id", "visit_date", "complaint", "diagnosis",
                "treatment", "prescription", "notes", "created_at")
LAB_FIELDS = ("id", "test_name", "result", "result_date", "notes", "added_by", "created_at")

VALID, TAMPERED, UNVERIFIED = "valid", "tampered", "unverified"


def compute_fingerprint(db, patient_id):
    """يحسب بصمة الملف الحالية، أو None إذا لم يوجد المريض."""
    p = db.execute("SELECT * FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if p is None:
        return None
    visits = db.execute(
        "SELECT * FROM visits WHERE patient_id = ? ORDER BY id", (patient_id,)).fetchall()
    labs = db.execute(
        "SELECT * FROM lab_results WHERE patient_id = ? ORDER BY id", (patient_id,)).fetchall()
    payload = {
        "patient": {f: p[f] for f in PATIENT_FIELDS},
        "visits": [{f: v[f] for f in VISIT_FIELDS} for v in visits],
        "labs": [{f: l[f] for f in LAB_FIELDS} for l in labs],
    }
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return sha256_hex(canonical)


def update_fingerprint(db, patient_id):
    """يعيد حساب البصمة ويحفظها. يُستدعى بعد أي تغيير مشروع على الملف."""
    fp = compute_fingerprint(db, patient_id)
    if fp is not None:
        db.execute("UPDATE patients SET fingerprint = ? WHERE id = ?", (fp, patient_id))
    return fp


def check_patient(db, patient_id):
    """يعيد dict فيه status (valid/tampered/unverified) والبصمتان المخزَّنة والحالية."""
    row = db.execute("SELECT fingerprint FROM patients WHERE id = ?", (patient_id,)).fetchone()
    stored = row["fingerprint"] if row else None
    current = compute_fingerprint(db, patient_id)
    if not stored:
        status = UNVERIFIED
    elif stored == current:
        status = VALID
    else:
        status = TAMPERED
    return {"status": status, "stored": stored, "current": current}


def verify_all(db):
    """يفحص كل الملفات. يعيد (العدد_الكلي، قائمة_أرقام_التالفة، عدد_غير_المحسوبة)."""
    ids = [r["id"] for r in db.execute("SELECT id FROM patients ORDER BY id")]
    tampered, unverified = [], 0
    for pid in ids:
        status = check_patient(db, pid)["status"]
        if status == TAMPERED:
            tampered.append(pid)
        elif status == UNVERIFIED:
            unverified += 1
    return len(ids), tampered, unverified


def backfill(conn):
    """يحسب البصمة للملفات الموجودة قبل إضافة الميزة (للترحيل مرة واحدة)."""
    conn.row_factory = sqlite3.Row
    for r in conn.execute("SELECT id FROM patients").fetchall():
        update_fingerprint(conn, r["id"])
    conn.commit()
