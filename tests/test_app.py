import audit
from conftest import PASSWORD, get_csrf, login, post


# ------------------------------------------------------------------ auth
def test_redirects_to_login_when_anonymous(client):
    r = client.get("/")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_login_success_and_logout(client):
    r = login(client, "admin")
    assert r.status_code == 302
    assert client.get("/").status_code == 200
    post(client, "/logout")
    assert client.get("/").status_code == 302


def test_login_wrong_password(client):
    r = login(client, "admin", "Wrong12345")
    assert r.status_code == 401


def test_login_unknown_user(client):
    assert login(client, "nobody").status_code == 401


def test_post_without_csrf_is_rejected(client):
    r = client.post("/login", data={"username": "admin", "password": PASSWORD})
    assert r.status_code == 400


def test_account_locks_after_five_failures(client):
    for _ in range(5):
        assert login(client, "admin", "Wrong12345").status_code == 401
    # حتى كلمة المرور الصحيحة مرفوضة أثناء القفل
    assert login(client, "admin", PASSWORD).status_code == 429


def test_disabled_user_cannot_login(client):
    login(client, "admin")
    post(client, "/users/2/toggle", token_path="/users")
    post(client, "/logout")
    assert login(client, "doc").status_code == 401


# ------------------------------------------------------------------ RBAC
def test_reception_cannot_see_users_or_audit(client):
    login(client, "recep")
    assert client.get("/users").status_code == 403
    assert client.get("/audit").status_code == 403


def test_nurse_cannot_create_patient_but_doctor_can(client, make_patient):
    login(client, "nurse")
    assert client.get("/patients/new").status_code == 403
    post(client, "/logout")
    login(client, "doc")
    assert make_patient().status_code == 302


def test_reception_cannot_add_visit(client, make_patient):
    login(client, "recep")
    make_patient()
    r = post(client, "/patients/1/visits",
             {"visit_date": "2026-01-01", "complaint": "x"}, "/patients/1")
    assert r.status_code == 403


def test_reception_does_not_see_medical_sections(client, make_patient):
    login(client, "recep")
    make_patient(allergies="بنسلين")
    html = client.get("/patients/1").get_data(as_text=True)
    assert "الزيارات" not in html
    assert "بنسلين" not in html


def test_only_admin_can_delete_patient(client, make_patient):
    login(client, "doc")
    make_patient()
    assert post(client, "/patients/1/delete", token_path="/patients/1").status_code == 403
    post(client, "/logout")
    login(client, "admin")
    assert post(client, "/patients/1/delete", token_path="/patients/1").status_code == 302
    assert client.get("/patients/1").status_code == 404


# -------------------------------------------------------------- patients
def test_create_patient_assigns_file_number(client, make_patient):
    login(client, "doc")
    r = make_patient()
    assert r.status_code == 302
    html = client.get("/patients/1").get_data(as_text=True)
    assert "P-000001" in html and "محمد أحمد" in html


def test_national_id_is_stored_hashed_only(client, app, make_patient):
    login(client, "doc")
    make_patient()
    import sqlite3
    row = sqlite3.connect(app.config["DATABASE"]).execute(
        "SELECT national_id_hash, national_id_last4 FROM patients").fetchone()
    assert row[0] != "9905201234" and len(row[0]) == 64
    assert row[1] == "1234"
    html = client.get("/patients/1").get_data(as_text=True)
    assert "9905201234" not in html and "******1234" in html


def test_duplicate_national_id_rejected(client, make_patient):
    login(client, "doc")
    assert make_patient().status_code == 302
    assert make_patient(full_name="شخص آخر").status_code == 400


def test_patient_validation_errors(client, make_patient):
    login(client, "doc")
    assert make_patient(full_name="ab").status_code == 400
    assert make_patient(dob="2999-01-01").status_code == 400
    assert make_patient(dob="not-a-date").status_code == 400
    assert make_patient(gender="x").status_code == 400
    assert make_patient(national_id="123").status_code == 400
    assert make_patient(phone="abc").status_code == 400


def test_search_by_name_phone_file_no_and_national_id(client, make_patient):
    login(client, "doc")
    make_patient()
    for q in ["محمد", "0791112233", "P-000001", "9905201234"]:
        data = client.get("/api/patients/search", query_string={"q": q}).get_json()
        assert len(data) == 1, q
    assert client.get("/api/patients/search", query_string={"q": "zzz"}).get_json() == []


def test_search_is_safe_against_sql_injection(client, make_patient):
    login(client, "doc")
    make_patient()
    r = client.get("/api/patients/search", query_string={"q": "' OR '1'='1"})
    assert r.status_code == 200 and r.get_json() == []


def test_edit_keeps_national_id_when_left_blank(client, make_patient):
    login(client, "doc")
    make_patient()
    data = {"full_name": "محمد أحمد الجديد", "dob": "1990-05-20", "gender": "male",
            "phone": "0791112233", "national_id": ""}
    assert post(client, "/patients/1/edit", data, "/patients/1/edit").status_code == 302
    assert "محمد أحمد الجديد" in client.get("/patients/1").get_data(as_text=True)
    found = client.get("/api/patients/search", query_string={"q": "9905201234"}).get_json()
    assert len(found) == 1


def test_html_in_input_is_escaped(client, make_patient):
    login(client, "doc")
    make_patient(full_name="<script>alert(1)</script>")
    html = client.get("/patients/1").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# ---------------------------------------------------------- visits & labs
def test_add_visit_and_lab(client, make_patient):
    login(client, "doc")
    make_patient()
    r = post(client, "/patients/1/visits", {
        "visit_date": "2026-09-01", "complaint": "صداع", "diagnosis": "شقيقة"}, "/patients/1")
    assert r.status_code == 302
    r = post(client, "/patients/1/labs", {
        "test_name": "CBC", "result": "طبيعي", "result_date": "2026-09-01"}, "/patients/1")
    assert r.status_code == 302
    html = client.get("/patients/1").get_data(as_text=True)
    assert "صداع" in html and "شقيقة" in html and "CBC" in html


def test_visit_validation(client, make_patient):
    login(client, "doc")
    make_patient()
    post(client, "/patients/1/visits", {"visit_date": "2999-01-01", "complaint": "x"}, "/patients/1")
    post(client, "/patients/1/visits", {"visit_date": "2026-01-01", "complaint": ""}, "/patients/1")
    html = client.get("/patients/1").get_data(as_text=True)
    assert "الزيارات (0)" in html


# ------------------------------------------------------------------ users
def test_admin_creates_user_with_strong_password_only(client):
    login(client, "admin")
    post(client, "/users/new", {"username": "newdoc", "full_name": "طبيب جديد",
                                "role": "doctor", "password": "weak"}, "/users")
    assert "newdoc" not in client.get("/users").get_data(as_text=True)
    post(client, "/users/new", {"username": "newdoc", "full_name": "طبيب جديد",
                                "role": "doctor", "password": "Strong1234"}, "/users")
    assert "newdoc" in client.get("/users").get_data(as_text=True)


def test_admin_cannot_disable_self(client):
    login(client, "admin")
    post(client, "/users/1/toggle", token_path="/users")
    assert client.get("/").status_code == 200


# ------------------------------------------------------------------ audit
def test_actions_are_audited_and_chain_is_valid(client, app, make_patient):
    login(client, "doc")
    make_patient()
    client.get("/patients/1")
    with app.app_context():
        from db import get_db
        db = get_db()
        actions = [r["action"] for r in db.execute("SELECT action FROM audit_log ORDER BY id")]
        assert "LOGIN" in actions and "PATIENT_CREATE" in actions and "PATIENT_VIEW" in actions
        ok, count, bad = audit.verify_chain(db)
        assert ok and bad is None and count == len(actions)


def test_tampering_with_audit_log_is_detected(client, app, make_patient):
    login(client, "doc")
    make_patient()
    import sqlite3
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.execute("UPDATE audit_log SET details = 'tampered' WHERE action = 'PATIENT_CREATE'")
    conn.commit()
    conn.close()
    with app.app_context():
        from db import get_db
        ok, _count, bad = audit.verify_chain(get_db())
        assert not ok and bad is not None


def test_deleting_audit_row_is_detected(client, app, make_patient):
    login(client, "doc")
    make_patient()
    client.get("/patients/1")
    import sqlite3
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.execute("DELETE FROM audit_log WHERE id = 2")
    conn.commit()
    conn.close()
    with app.app_context():
        from db import get_db
        ok, _c, _b = audit.verify_chain(get_db())
        assert not ok


def test_admin_verify_button_reports_status(client):
    login(client, "admin")
    r = post(client, "/audit/verify", token_path="/audit")
    assert r.status_code == 302
    assert "سليم" in client.get("/audit").get_data(as_text=True)


def test_security_headers_present(client):
    r = client.get("/login")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in r.headers
