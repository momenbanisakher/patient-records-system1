import re
import sqlite3

import integrity
from conftest import login, post
from db import SCHEMA, get_db, init_db


def _exec(app, sql, params=()):
    conn = sqlite3.connect(app.config["DATABASE"])
    conn.execute(sql, params)
    conn.commit()
    conn.close()


def _status(app, pid=1):
    with app.app_context():
        return integrity.check_patient(get_db(), pid)["status"]


def test_new_patient_gets_valid_fingerprint(client, app, make_patient):
    login(client, "doc")
    make_patient()
    assert _status(app) == integrity.VALID
    html = client.get("/patients/1").get_data(as_text=True)
    assert "الملف سليم" in html


def test_fingerprint_is_sha256_hex_and_deterministic(client, app, make_patient):
    login(client, "doc")
    make_patient()
    with app.app_context():
        db = get_db()
        a = integrity.compute_fingerprint(db, 1)
        b = integrity.compute_fingerprint(db, 1)
        assert a == b and re.fullmatch(r"[0-9a-f]{64}", a)
        assert integrity.compute_fingerprint(db, 999) is None


def test_viewing_does_not_change_fingerprint(client, app, make_patient):
    login(client, "doc")
    make_patient()
    with app.app_context():
        before = get_db().execute("SELECT fingerprint FROM patients").fetchone()[0]
    client.get("/patients/1")
    client.get("/patients/1")
    with app.app_context():
        after = get_db().execute("SELECT fingerprint FROM patients").fetchone()[0]
    assert before == after


def test_legitimate_changes_keep_file_valid_but_change_fingerprint(client, app, make_patient):
    login(client, "doc")
    make_patient()
    with app.app_context():
        fp0 = get_db().execute("SELECT fingerprint FROM patients").fetchone()[0]
    post(client, "/patients/1/visits", {"visit_date": "2026-09-01", "complaint": "صداع"}, "/patients/1")
    assert _status(app) == integrity.VALID
    post(client, "/patients/1/labs", {"test_name": "CBC", "result": "طبيعي",
                                      "result_date": "2026-09-01"}, "/patients/1")
    assert _status(app) == integrity.VALID
    post(client, "/patients/1/edit", {"full_name": "محمد أحمد المعدّل", "dob": "1990-05-20",
                                      "gender": "male"}, "/patients/1/edit")
    assert _status(app) == integrity.VALID
    with app.app_context():
        fp1 = get_db().execute("SELECT fingerprint FROM patients").fetchone()[0]
    assert fp0 != fp1


def test_direct_edit_of_patient_row_is_detected(client, app, make_patient):
    login(client, "doc")
    make_patient()
    _exec(app, "UPDATE patients SET phone = '0000000000' WHERE id = 1")
    assert _status(app) == integrity.TAMPERED
    html = client.get("/patients/1").get_data(as_text=True)
    assert "تعديل غير مصرح به" in html and "الملف سليم" not in html


def test_direct_edit_of_visit_is_detected(client, app, make_patient):
    login(client, "doc")
    make_patient()
    post(client, "/patients/1/visits", {"visit_date": "2026-09-01", "complaint": "صداع",
                                        "diagnosis": "شقيقة"}, "/patients/1")
    _exec(app, "UPDATE visits SET diagnosis = 'معدّل خفية' WHERE id = 1")
    assert _status(app) == integrity.TAMPERED


def test_direct_deletion_of_lab_is_detected(client, app, make_patient):
    login(client, "doc")
    make_patient()
    post(client, "/patients/1/labs", {"test_name": "CBC", "result": "طبيعي",
                                      "result_date": "2026-09-01"}, "/patients/1")
    _exec(app, "DELETE FROM lab_results WHERE id = 1")
    assert _status(app) == integrity.TAMPERED


def test_injected_visit_is_detected(client, app, make_patient):
    login(client, "doc")
    make_patient()
    _exec(app, "INSERT INTO visits (patient_id, visit_date, complaint, created_at)"
               " VALUES (1, '2026-01-01', 'مدسوسة', '2026-01-01T00:00:00Z')")
    assert _status(app) == integrity.TAMPERED


def test_tampered_view_is_written_to_audit_log(client, app, make_patient):
    login(client, "doc")
    make_patient()
    _exec(app, "UPDATE patients SET address = 'x' WHERE id = 1")
    client.get("/patients/1")
    with app.app_context():
        actions = [r[0] for r in get_db().execute("SELECT action FROM audit_log")]
    assert "INTEGRITY_FAIL" in actions


def test_verify_all_reports_tampered_files(client, app, make_patient):
    login(client, "doc")
    make_patient()
    make_patient(full_name="مريض ثاني", national_id="")
    with app.app_context():
        assert integrity.verify_all(get_db()) == (2, [], 0)
    _exec(app, "UPDATE patients SET full_name = 'مزوّر' WHERE id = 2")
    with app.app_context():
        assert integrity.verify_all(get_db()) == (2, [2], 0)


def test_verify_all_route_is_admin_only_and_flags_tampering(client, app, make_patient):
    login(client, "doc")
    make_patient()
    assert post(client, "/integrity/verify-all", token_path="/patients/1").status_code == 403
    post(client, "/logout")
    login(client, "admin")
    _exec(app, "UPDATE patients SET phone = '1' WHERE id = 1")
    r = post(client, "/integrity/verify-all", token_path="/audit")
    assert r.status_code == 302
    assert "تم اكتشاف تلاعب" in client.get("/audit").get_data(as_text=True)


def test_missing_fingerprint_is_reported_as_unverified(client, app, make_patient):
    login(client, "doc")
    make_patient()
    _exec(app, "UPDATE patients SET fingerprint = NULL WHERE id = 1")
    assert _status(app) == integrity.UNVERIFIED


def test_migration_adds_column_and_backfills(tmp_path):
    """قاعدة قديمة بدون عمود البصمة تُرحَّل وتُحسب بصماتها."""
    path = str(tmp_path / "old.db")
    old_schema = re.sub(r"\n\s+fingerprint\s+TEXT,", "", SCHEMA)
    conn = sqlite3.connect(path)
    conn.executescript(old_schema)
    conn.execute("INSERT INTO patients (file_no, full_name, dob, gender, created_at, updated_at)"
                 " VALUES ('P-000001', 'قديم', '1980-01-01', 'male', 't', 't')")
    conn.commit()
    conn.close()

    init_db(path)

    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    assert integrity.check_patient(conn, 1)["status"] == integrity.VALID
    conn.close()
