"""نظام إدارة ملفات المرضى في المستشفيات - الخادم (Flask)."""
import hmac
import os
import re
import secrets
from datetime import date, datetime, timedelta, timezone
from functools import wraps

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)

import audit
import integrity
from db import close_db, get_db, init_db
from security import (DEFAULT_ITERATIONS, check_password_strength, hash_password,
                      sha256_hex, verify_password)

ROLES = {
    "admin": "مدير النظام",
    "doctor": "طبيب",
    "nurse": "ممرض",
    "reception": "استقبال",
}

PERMISSIONS = {
    "admin": {"patients.view", "patients.create", "patients.edit", "patients.delete",
              "visits.view", "visits.create", "labs.view", "labs.create",
              "users.manage", "audit.view"},
    "doctor": {"patients.view", "patients.create", "patients.edit",
               "visits.view", "visits.create", "labs.view", "labs.create"},
    "nurse": {"patients.view", "patients.edit", "visits.view", "labs.view", "labs.create"},
    "reception": {"patients.view", "patients.create", "patients.edit"},
}

GENDERS = {"male": "ذكر", "female": "أنثى"}
BLOOD_TYPES = ["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"]
MAX_FAILED_ATTEMPTS = 5
LOCK_MINUTES = 15
PAGE_SIZE = 20


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def today_str():
    return date.today().isoformat()


def valid_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(
        DATABASE=os.environ.get("DATABASE_PATH",
                                os.path.join(app.instance_path, "patients.db")),
        SECRET_KEY=os.environ.get("SECRET_KEY"),
        PBKDF2_ITERATIONS=DEFAULT_ITERATIONS,
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    )
    if config:
        app.config.update(config)

    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(app.config["DATABASE"])), exist_ok=True)
    if not app.config["SECRET_KEY"]:
        key_file = os.path.join(app.instance_path, "secret.key")
        if not os.path.exists(key_file):
            with open(key_file, "w") as fh:
                fh.write(secrets.token_hex(32))
        with open(key_file) as fh:
            app.config["SECRET_KEY"] = fh.read().strip()
    init_db(app.config["DATABASE"])
    app.teardown_appcontext(close_db)

    # ------------------------------------------------------------------ helpers
    def client_ip():
        return request.remote_addr

    def log(action, entity=None, entity_id=None, details=""):
        audit.log_event(get_db(), g.user, action, entity, entity_id, details, client_ip())

    def has_perm(perm):
        return bool(g.get("user")) and perm in PERMISSIONS.get(g.user["role"], set())

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not g.user:
                return redirect(url_for("login"))
            return view(*args, **kwargs)
        return wrapped

    def permission_required(perm):
        def decorator(view):
            @wraps(view)
            def wrapped(*args, **kwargs):
                if not g.user:
                    return redirect(url_for("login"))
                if not has_perm(perm):
                    log("ACCESS_DENIED", details=f"{request.method} {request.path}")
                    get_db().commit()
                    abort(403)
                return view(*args, **kwargs)
            return wrapped
        return decorator

    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return session["csrf"]

    # ------------------------------------------------------------ request hooks
    @app.before_request
    def load_user():
        g.user = None
        uid = session.get("user_id")
        if uid:
            user = get_db().execute(
                "SELECT * FROM users WHERE id = ? AND is_active = 1", (uid,)
            ).fetchone()
            if user:
                g.user = user
            else:
                session.clear()

    @app.before_request
    def csrf_protect():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            expected = session.get("csrf")
            sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
            if not expected or not sent or not hmac.compare_digest(expected, sent):
                abort(400)

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' https://cdn.jsdelivr.net; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "font-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data:"
        )
        return resp

    @app.context_processor
    def inject_globals():
        return {
            "csrf_token": csrf_token,
            "can": has_perm,
            "ROLES": ROLES,
            "GENDERS": GENDERS,
            "BLOOD_TYPES": BLOOD_TYPES,
        }

    @app.template_filter("age")
    def age_filter(dob):
        d = valid_date(dob)
        if not d:
            return ""
        t = date.today()
        return t.year - d.year - ((t.month, t.day) < (d.month, d.day))

    @app.errorhandler(400)
    def bad_request(_e):
        return render_template("error.html", code=400,
                               message="الطلب غير صالح أو انتهت صلاحية الصفحة. أعد المحاولة."), 400

    @app.errorhandler(403)
    def forbidden(_e):
        return render_template("error.html", code=403,
                               message="ليس لديك صلاحية للوصول إلى هذه الصفحة."), 403

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("error.html", code=404, message="الصفحة غير موجودة."), 404

    # --------------------------------------------------------------------- auth
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            username = request.form.get("username", "").strip().lower()
            password = request.form.get("password", "")
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

            if user and user["locked_until"] and user["locked_until"] > now_iso():
                audit.log_event(db, None, "LOGIN_BLOCKED", "USER", user["id"], "", client_ip(),
                                username=username)
                db.commit()
                flash("الحساب مقفل مؤقتًا بسبب محاولات فاشلة كثيرة. حاول لاحقًا.", "danger")
                return render_template("login.html"), 429

            if user and user["is_active"] and verify_password(user["password_hash"], password):
                db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                           (user["id"],))
                session.clear()
                session["user_id"] = user["id"]
                session.permanent = True
                csrf_token()
                g.user = user
                log("LOGIN", "USER", user["id"])
                db.commit()
                return redirect(url_for("dashboard"))

            if user:
                attempts = user["failed_attempts"] + 1
                locked = None
                if attempts >= MAX_FAILED_ATTEMPTS:
                    locked = (datetime.now(timezone.utc) + timedelta(minutes=LOCK_MINUTES)
                              ).strftime("%Y-%m-%dT%H:%M:%SZ")
                    attempts = 0
                db.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                           (attempts, locked, user["id"]))
            else:
                # تجزئة وهمية حتى لا يختلف زمن الرد بين مستخدم موجود وغير موجود
                verify_password("pbkdf2_sha256$1000$00$00", password)
            audit.log_event(db, None, "LOGIN_FAILED", "USER", user["id"] if user else None,
                            "", client_ip(), username=username)
            db.commit()
            flash("اسم المستخدم أو كلمة المرور غير صحيحة.", "danger")
            return render_template("login.html"), 401
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        log("LOGOUT", "USER", g.user["id"])
        get_db().commit()
        session.clear()
        return redirect(url_for("login"))

    # ---------------------------------------------------------------- dashboard
    @app.route("/")
    @login_required
    def dashboard():
        db = get_db()
        stats = {
            "patients": db.execute("SELECT COUNT(*) FROM patients").fetchone()[0],
            "visits_today": db.execute(
                "SELECT COUNT(*) FROM visits WHERE visit_date = ?", (today_str(),)
            ).fetchone()[0],
            "visits_total": db.execute("SELECT COUNT(*) FROM visits").fetchone()[0],
            "users": db.execute("SELECT COUNT(*) FROM users WHERE is_active = 1").fetchone()[0],
        }
        recent_patients = db.execute(
            "SELECT id, file_no, full_name, created_at FROM patients ORDER BY id DESC LIMIT 5"
        ).fetchall()
        recent_visits = []
        if has_perm("visits.view"):
            recent_visits = db.execute(
                "SELECT v.id, v.visit_date, v.complaint, p.id AS patient_id, p.full_name, p.file_no "
                "FROM visits v JOIN patients p ON p.id = v.patient_id "
                "ORDER BY v.id DESC LIMIT 5"
            ).fetchall()
        return render_template("dashboard.html", stats=stats,
                               recent_patients=recent_patients, recent_visits=recent_visits)

    # ----------------------------------------------------------------- patients
    def search_patients(q, limit, offset=0):
        db = get_db()
        sql = ("SELECT id, file_no, full_name, dob, gender, phone FROM patients")
        params = []
        if q:
            like = f"%{q}%"
            sql += (" WHERE full_name LIKE ? OR file_no LIKE ? OR phone LIKE ?"
                    " OR national_id_hash = ?")
            params += [like, like, like, sha256_hex(q)]
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        return db.execute(sql, params).fetchall()

    @app.route("/patients")
    @permission_required("patients.view")
    def patients_list():
        q = request.args.get("q", "").strip()
        try:
            page = max(1, int(request.args.get("page", 1)))
        except ValueError:
            page = 1
        rows = search_patients(q, PAGE_SIZE + 1, (page - 1) * PAGE_SIZE)
        has_next = len(rows) > PAGE_SIZE
        return render_template("patients.html", patients=rows[:PAGE_SIZE], q=q,
                               page=page, has_next=has_next)

    @app.route("/api/patients/search")
    @permission_required("patients.view")
    def api_patients_search():
        q = request.args.get("q", "").strip()
        rows = search_patients(q, 20)
        return jsonify([
            {"id": r["id"], "file_no": r["file_no"], "full_name": r["full_name"],
             "dob": r["dob"], "gender": GENDERS.get(r["gender"], ""),
             "phone": r["phone"] or "", "url": url_for("patient_detail", patient_id=r["id"])}
            for r in rows
        ])

    def parse_patient_form(form, patient_id=None):
        db = get_db()
        errors = []
        data = {k: form.get(k, "").strip() for k in (
            "full_name", "dob", "gender", "phone", "address", "blood_type",
            "allergies", "chronic_conditions", "emergency_contact", "national_id")}
        if len(data["full_name"]) < 3:
            errors.append("الاسم الكامل مطلوب (3 أحرف على الأقل).")
        d = valid_date(data["dob"])
        if not d:
            errors.append("تاريخ الميلاد غير صالح.")
        elif d > date.today():
            errors.append("تاريخ الميلاد لا يمكن أن يكون في المستقبل.")
        if data["gender"] not in GENDERS:
            errors.append("اختر الجنس.")
        if data["blood_type"] and data["blood_type"] not in BLOOD_TYPES:
            errors.append("فصيلة الدم غير صالحة.")
        if data["phone"] and not re.fullmatch(r"[0-9+\-\s]{7,15}", data["phone"]):
            errors.append("رقم الهاتف غير صالح.")
        nid = data["national_id"]
        if nid:
            if not re.fullmatch(r"\d{10}", nid):
                errors.append("الرقم الوطني يجب أن يتكون من 10 أرقام.")
            else:
                existing = db.execute(
                    "SELECT id FROM patients WHERE national_id_hash = ?", (sha256_hex(nid),)
                ).fetchone()
                if existing and existing["id"] != patient_id:
                    errors.append("يوجد مريض مسجل بنفس الرقم الوطني.")
        return data, errors

    @app.route("/patients/new", methods=["GET", "POST"])
    @permission_required("patients.create")
    def patient_new():
        if request.method == "POST":
            data, errors = parse_patient_form(request.form)
            if errors:
                for e in errors:
                    flash(e, "danger")
                return render_template("patient_form.html", p=data, mode="new"), 400
            db = get_db()
            next_id = db.execute("SELECT COALESCE(MAX(id), 0) + 1 FROM patients").fetchone()[0]
            file_no = f"P-{next_id:06d}"
            nid = data["national_id"]
            ts = now_iso()
            cur = db.execute(
                "INSERT INTO patients (file_no, full_name, dob, gender, phone, address, blood_type,"
                " allergies, chronic_conditions, emergency_contact, national_id_hash,"
                " national_id_last4, created_by, created_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (file_no, data["full_name"], data["dob"], data["gender"], data["phone"],
                 data["address"], data["blood_type"], data["allergies"],
                 data["chronic_conditions"], data["emergency_contact"],
                 sha256_hex(nid) if nid else None, nid[-4:] if nid else None,
                 g.user["id"], ts, ts),
            )
            pid = cur.lastrowid
            integrity.update_fingerprint(db, pid)
            log("PATIENT_CREATE", "PATIENT", pid, file_no)
            db.commit()
            flash(f"تم إنشاء ملف المريض {file_no} بنجاح.", "success")
            return redirect(url_for("patient_detail", patient_id=pid))
        return render_template("patient_form.html", p={}, mode="new")

    def get_patient_or_404(patient_id):
        p = get_db().execute("SELECT * FROM patients WHERE id = ?", (patient_id,)).fetchone()
        if not p:
            abort(404)
        return p

    @app.route("/patients/<int:patient_id>")
    @permission_required("patients.view")
    def patient_detail(patient_id):
        db = get_db()
        p = get_patient_or_404(patient_id)
        visits, labs = [], []
        if has_perm("visits.view"):
            visits = db.execute(
                "SELECT v.*, u.full_name AS doctor_name FROM visits v "
                "LEFT JOIN users u ON u.id = v.doctor_id WHERE v.patient_id = ? "
                "ORDER BY v.visit_date DESC, v.id DESC", (patient_id,)).fetchall()
        if has_perm("labs.view"):
            labs = db.execute(
                "SELECT l.*, u.full_name AS added_by_name FROM lab_results l "
                "LEFT JOIN users u ON u.id = l.added_by WHERE l.patient_id = ? "
                "ORDER BY l.result_date DESC, l.id DESC", (patient_id,)).fetchall()
        check = integrity.check_patient(db, patient_id)
        log("PATIENT_VIEW", "PATIENT", patient_id, p["file_no"])
        if check["status"] == integrity.TAMPERED:
            log("INTEGRITY_FAIL", "PATIENT", patient_id, p["file_no"])
        db.commit()
        return render_template("patient_detail.html", p=p, visits=visits, labs=labs,
                               today=today_str(), integrity=check)

    @app.route("/patients/<int:patient_id>/edit", methods=["GET", "POST"])
    @permission_required("patients.edit")
    def patient_edit(patient_id):
        p = get_patient_or_404(patient_id)
        if request.method == "POST":
            data, errors = parse_patient_form(request.form, patient_id)
            if errors:
                for e in errors:
                    flash(e, "danger")
                data["file_no"] = p["file_no"]
                data["national_id_last4"] = p["national_id_last4"]
                return render_template("patient_form.html", p=data, mode="edit",
                                       patient_id=patient_id), 400
            db = get_db()
            nid = data["national_id"]
            hash_val, last4 = p["national_id_hash"], p["national_id_last4"]
            if nid:
                hash_val, last4 = sha256_hex(nid), nid[-4:]
            db.execute(
                "UPDATE patients SET full_name=?, dob=?, gender=?, phone=?, address=?, blood_type=?,"
                " allergies=?, chronic_conditions=?, emergency_contact=?, national_id_hash=?,"
                " national_id_last4=?, updated_at=? WHERE id=?",
                (data["full_name"], data["dob"], data["gender"], data["phone"], data["address"],
                 data["blood_type"], data["allergies"], data["chronic_conditions"],
                 data["emergency_contact"], hash_val, last4, now_iso(), patient_id),
            )
            integrity.update_fingerprint(db, patient_id)
            log("PATIENT_UPDATE", "PATIENT", patient_id, p["file_no"])
            db.commit()
            flash("تم تحديث بيانات المريض.", "success")
            return redirect(url_for("patient_detail", patient_id=patient_id))
        return render_template("patient_form.html", p=dict(p), mode="edit", patient_id=patient_id)

    @app.route("/patients/<int:patient_id>/delete", methods=["POST"])
    @permission_required("patients.delete")
    def patient_delete(patient_id):
        p = get_patient_or_404(patient_id)
        db = get_db()
        db.execute("DELETE FROM patients WHERE id = ?", (patient_id,))
        log("PATIENT_DELETE", "PATIENT", patient_id, p["file_no"])
        db.commit()
        flash(f"تم حذف ملف المريض {p['file_no']}.", "success")
        return redirect(url_for("patients_list"))

    # ------------------------------------------------------------ visits & labs
    @app.route("/patients/<int:patient_id>/visits", methods=["POST"])
    @permission_required("visits.create")
    def visit_add(patient_id):
        p = get_patient_or_404(patient_id)
        f = {k: request.form.get(k, "").strip() for k in
             ("visit_date", "complaint", "diagnosis", "treatment", "prescription", "notes")}
        d = valid_date(f["visit_date"])
        if not d or d > date.today():
            flash("تاريخ الزيارة غير صالح.", "danger")
        elif not f["complaint"]:
            flash("الشكوى الرئيسية مطلوبة.", "danger")
        else:
            db = get_db()
            cur = db.execute(
                "INSERT INTO visits (patient_id, doctor_id, visit_date, complaint, diagnosis,"
                " treatment, prescription, notes, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (patient_id, g.user["id"], f["visit_date"], f["complaint"], f["diagnosis"],
                 f["treatment"], f["prescription"], f["notes"], now_iso()),
            )
            integrity.update_fingerprint(db, patient_id)
            log("VISIT_CREATE", "VISIT", cur.lastrowid, p["file_no"])
            db.commit()
            flash("تمت إضافة الزيارة.", "success")
        return redirect(url_for("patient_detail", patient_id=patient_id))

    @app.route("/patients/<int:patient_id>/labs", methods=["POST"])
    @permission_required("labs.create")
    def lab_add(patient_id):
        p = get_patient_or_404(patient_id)
        f = {k: request.form.get(k, "").strip() for k in
             ("test_name", "result", "result_date", "notes")}
        d = valid_date(f["result_date"])
        if not d or d > date.today():
            flash("تاريخ النتيجة غير صالح.", "danger")
        elif not f["test_name"] or not f["result"]:
            flash("اسم الفحص والنتيجة مطلوبان.", "danger")
        else:
            db = get_db()
            cur = db.execute(
                "INSERT INTO lab_results (patient_id, test_name, result, result_date, notes,"
                " added_by, created_at) VALUES (?,?,?,?,?,?,?)",
                (patient_id, f["test_name"], f["result"], f["result_date"], f["notes"],
                 g.user["id"], now_iso()),
            )
            integrity.update_fingerprint(db, patient_id)
            log("LAB_CREATE", "LAB", cur.lastrowid, p["file_no"])
            db.commit()
            flash("تمت إضافة نتيجة الفحص.", "success")
        return redirect(url_for("patient_detail", patient_id=patient_id))

    # -------------------------------------------------------------------- users
    @app.route("/users")
    @permission_required("users.manage")
    def users_list():
        users = get_db().execute("SELECT * FROM users ORDER BY id").fetchall()
        return render_template("users.html", users=users)

    @app.route("/users/new", methods=["POST"])
    @permission_required("users.manage")
    def user_new():
        username = request.form.get("username", "").strip().lower()
        full_name = request.form.get("full_name", "").strip()
        role = request.form.get("role", "")
        password = request.form.get("password", "")
        errors = []
        if not re.fullmatch(r"[a-z0-9_]{3,30}", username):
            errors.append("اسم المستخدم: 3-30 حرفًا إنجليزيًا صغيرًا أو أرقامًا أو _.")
        if len(full_name) < 3:
            errors.append("الاسم الكامل مطلوب.")
        if role not in ROLES:
            errors.append("الدور غير صالح.")
        errors += check_password_strength(password)
        db = get_db()
        if not errors and db.execute("SELECT 1 FROM users WHERE username = ?",
                                     (username,)).fetchone():
            errors.append("اسم المستخدم مستخدم مسبقًا.")
        if errors:
            for e in errors:
                flash(e, "danger")
        else:
            cur = db.execute(
                "INSERT INTO users (username, full_name, role, password_hash, created_at)"
                " VALUES (?,?,?,?,?)",
                (username, full_name, role,
                 hash_password(password, app.config["PBKDF2_ITERATIONS"]), now_iso()),
            )
            log("USER_CREATE", "USER", cur.lastrowid, f"{username} ({role})")
            db.commit()
            flash("تم إنشاء المستخدم.", "success")
        return redirect(url_for("users_list"))

    @app.route("/users/<int:user_id>/toggle", methods=["POST"])
    @permission_required("users.manage")
    def user_toggle(user_id):
        db = get_db()
        u = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not u:
            abort(404)
        if u["id"] == g.user["id"]:
            flash("لا يمكنك تعطيل حسابك الخاص.", "danger")
        else:
            new_state = 0 if u["is_active"] else 1
            db.execute("UPDATE users SET is_active = ?, failed_attempts = 0, locked_until = NULL"
                       " WHERE id = ?", (new_state, user_id))
            log("USER_ENABLE" if new_state else "USER_DISABLE", "USER", user_id, u["username"])
            db.commit()
            flash("تم تحديث حالة المستخدم.", "success")
        return redirect(url_for("users_list"))

    @app.route("/users/<int:user_id>/reset-password", methods=["POST"])
    @permission_required("users.manage")
    def user_reset_password(user_id):
        db = get_db()
        u = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not u:
            abort(404)
        password = request.form.get("password", "")
        errors = check_password_strength(password)
        if errors:
            for e in errors:
                flash(e, "danger")
        else:
            db.execute("UPDATE users SET password_hash = ?, failed_attempts = 0,"
                       " locked_until = NULL WHERE id = ?",
                       (hash_password(password, app.config["PBKDF2_ITERATIONS"]), user_id))
            log("USER_PASSWORD_RESET", "USER", user_id, u["username"])
            db.commit()
            flash("تم تغيير كلمة المرور.", "success")
        return redirect(url_for("users_list"))

    # -------------------------------------------------------------------- audit
    @app.route("/audit")
    @permission_required("audit.view")
    def audit_view():
        db = get_db()
        rows = db.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200").fetchall()
        return render_template("audit.html", rows=rows)

    @app.route("/audit/verify", methods=["POST"])
    @permission_required("audit.view")
    def audit_verify():
        db = get_db()
        ok, count, bad_id = audit.verify_chain(db)
        log("AUDIT_VERIFY", details="valid" if ok else f"broken at {bad_id}")
        db.commit()
        if ok:
            flash(f"سجل التدقيق سليم ({count} سجلًا).", "success")
        else:
            flash(f"تم اكتشاف تلاعب في سجل التدقيق عند السجل رقم {bad_id}.", "danger")
        return redirect(url_for("audit_view"))

    @app.route("/integrity/verify-all", methods=["POST"])
    @permission_required("audit.view")
    def integrity_verify_all():
        db = get_db()
        total, tampered, unverified = integrity.verify_all(db)
        if tampered:
            files = "، ".join(
                db.execute("SELECT file_no FROM patients WHERE id = ?", (pid,)).fetchone()[0]
                for pid in tampered)
            log("INTEGRITY_CHECK", details=f"tampered: {files}")
            flash(f"تم اكتشاف تلاعب في {len(tampered)} ملف من أصل {total}: {files}", "danger")
        else:
            log("INTEGRITY_CHECK", details=f"all {total} files valid")
            flash(f"كل ملفات المرضى سليمة ({total} ملفًا).", "success")
        if unverified:
            flash(f"{unverified} ملف بدون بصمة محفوظة.", "warning")
        db.commit()
        return redirect(url_for("audit_view"))

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
