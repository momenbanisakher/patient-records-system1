"""أوامر الإدارة:
    python manage.py create-user      إنشاء مستخدم (يُنصح بإنشاء مدير أولًا)
    python manage.py seed-demo        بيانات تجريبية للعرض
    python manage.py verify           فحص سلامة ملفات المرضى وسجل التدقيق
"""
import argparse
import getpass
import os
import sys

import audit
import integrity
from app import ROLES, create_app, now_iso
from db import get_db
from security import check_password_strength, hash_password, sha256_hex


def add_user(app, username, full_name, role, password):
    with app.app_context():
        db = get_db()
        if db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            print(f"المستخدم {username} موجود مسبقًا.")
            return None
        cur = db.execute(
            "INSERT INTO users (username, full_name, role, password_hash, created_at)"
            " VALUES (?,?,?,?,?)",
            (username, full_name, role,
             hash_password(password, app.config["PBKDF2_ITERATIONS"]), now_iso()),
        )
        audit.log_event(db, None, "USER_CREATE", "USER", cur.lastrowid,
                        f"{username} ({role}) via CLI", "cli", username="cli")
        db.commit()
        return cur.lastrowid


def cmd_create_user(app, _args):
    username = input("اسم المستخدم: ").strip().lower()
    full_name = input("الاسم الكامل: ").strip()
    role = input(f"الدور ({'/'.join(ROLES)}): ").strip()
    if role not in ROLES:
        sys.exit("دور غير صالح.")
    password = getpass.getpass("كلمة المرور: ")
    errors = check_password_strength(password)
    if errors:
        sys.exit("\n".join(errors))
    if add_user(app, username, full_name, role, password):
        print("تم إنشاء المستخدم.")


DEMO_PATIENTS = [
    ("أحمد محمد العلي", "1985-03-12", "male", "0791234567", "عمّان - الجبيهة", "O+",
     "البنسلين", "السكري النوع الثاني", "0797654321", "9851012345"),
    ("سارة خالد الحسن", "1992-07-25", "female", "0782345678", "إربد - شارع الجامعة", "A+",
     "", "", "0775551234", "9921098765"),
    ("عمر يوسف المصري", "1970-11-02", "male", "0773456789", "الزرقاء - الهاشمية", "B-",
     "", "ارتفاع ضغط الدم", "0788881234", ""),
]


def cmd_seed_demo(app, _args):
    custom_pw = os.environ.get("DEMO_PASSWORD")
    pw = custom_pw or "Demo12345"
    add_user(app, "admin", "مدير النظام", "admin", pw)
    add_user(app, "doctor1", "د. ليلى أحمد", "doctor", pw)
    add_user(app, "nurse1", "ممرض خالد", "nurse", pw)
    add_user(app, "reception1", "موظفة الاستقبال", "reception", pw)
    with app.app_context():
        db = get_db()
        if db.execute("SELECT COUNT(*) FROM patients").fetchone()[0]:
            print("البيانات التجريبية موجودة مسبقًا.")
            return
        doctor = db.execute("SELECT id FROM users WHERE username='doctor1'").fetchone()
        ts = now_iso()
        for i, (name, dob, gender, phone, addr, blood, allergy, chronic, emerg, nid) in \
                enumerate(DEMO_PATIENTS, start=1):
            cur = db.execute(
                "INSERT INTO patients (file_no, full_name, dob, gender, phone, address, blood_type,"
                " allergies, chronic_conditions, emergency_contact, national_id_hash,"
                " national_id_last4, created_by, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (f"P-{i:06d}", name, dob, gender, phone, addr, blood, allergy, chronic, emerg,
                 sha256_hex(nid) if nid else None, nid[-4:] if nid else None,
                 doctor["id"], ts, ts),
            )
            audit.log_event(db, None, "PATIENT_CREATE", "PATIENT", cur.lastrowid,
                            f"P-{i:06d}", "cli", username="cli")
        db.execute(
            "INSERT INTO visits (patient_id, doctor_id, visit_date, complaint, diagnosis,"
            " treatment, prescription, notes, created_at) VALUES (1,?,?,?,?,?,?,?,?)",
            (doctor["id"], "2026-09-15", "عطش شديد وتعب عام", "ارتفاع سكر الدم",
             "تعديل النظام الغذائي ومتابعة", "ميتفورمين 500 ملغ مرتين يوميًا",
             "مراجعة بعد شهر", ts),
        )
        db.execute(
            "INSERT INTO lab_results (patient_id, test_name, result, result_date, notes, added_by,"
            " created_at) VALUES (1,?,?,?,?,?,?)",
            ("سكر صائم", "168 mg/dL", "2026-09-15", "", doctor["id"], ts),
        )
        for row in db.execute("SELECT id FROM patients").fetchall():
            integrity.update_fingerprint(db, row["id"])
        db.commit()
        if custom_pw:
            print("تمت إضافة البيانات التجريبية (كلمة المرور من DEMO_PASSWORD).")
        else:
            print("تمت إضافة البيانات التجريبية. كلمة مرور كل الحسابات: " + pw)


def bootstrap_from_env(app, env=None):
    """للنشر على خادم بلا طرفية (مثل Render): ينشئ المدير الأول من متغيرات البيئة.

    ADMIN_PASSWORD  كلمة مرور المدير (تُنشأ فقط إذا لا يوجد أي مستخدم)
    ADMIN_USERNAME  اسم المدير (الافتراضي admin)
    DEMO_DATA=1     يضيف حسابات ومرضى تجريبيين (كلمة المرور من DEMO_PASSWORD)
    """
    env = os.environ if env is None else env
    password = env.get("ADMIN_PASSWORD")
    if password:
        with app.app_context():
            users = get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if users == 0:
            errors = check_password_strength(password)
            if errors:
                raise SystemExit("ADMIN_PASSWORD ضعيفة: " + " ".join(errors))
            username = env.get("ADMIN_USERNAME", "admin").strip().lower()
            add_user(app, username, "مدير النظام", "admin", password)
    if env.get("DEMO_DATA") == "1":
        cmd_seed_demo(app, None)


def cmd_verify(app, _args):
    with app.app_context():
        db = get_db()
        total, tampered, unverified = integrity.verify_all(db)
        print(f"ملفات المرضى: {total} | سليمة: {total - len(tampered) - unverified}"
              f" | متلاعب بها: {len(tampered)} | بدون بصمة: {unverified}")
        for pid in tampered:
            file_no = db.execute("SELECT file_no FROM patients WHERE id = ?", (pid,)).fetchone()[0]
            print(f"  ✘ الملف {file_no} لا تطابق بصمته المحفوظة")
        ok, count, bad_id = audit.verify_chain(db)
        if ok:
            print(f"سجل التدقيق: سليم ({count} سجلًا)")
        else:
            print(f"سجل التدقيق: تلاعب عند السجل رقم {bad_id}")
        sys.exit(0 if not tampered and ok else 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["create-user", "seed-demo", "verify"])
    args = parser.parse_args()
    app = create_app()
    {"create-user": cmd_create_user, "seed-demo": cmd_seed_demo,
     "verify": cmd_verify}[args.command](app, args)


if __name__ == "__main__":
    main()
