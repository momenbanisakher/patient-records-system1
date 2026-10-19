"""طبقة قاعدة البيانات: الاتصال بـ SQLite وإنشاء الجداول."""
import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    full_name       TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('admin','doctor','nurse','reception')),
    password_hash   TEXT NOT NULL,
    is_active       INTEGER NOT NULL DEFAULT 1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS patients (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    file_no            TEXT NOT NULL UNIQUE,
    full_name          TEXT NOT NULL,
    dob                TEXT NOT NULL,
    gender             TEXT NOT NULL CHECK (gender IN ('male','female')),
    phone              TEXT,
    address            TEXT,
    blood_type         TEXT,
    allergies          TEXT,
    chronic_conditions TEXT,
    emergency_contact  TEXT,
    national_id_hash   TEXT UNIQUE,
    national_id_last4  TEXT,
    fingerprint        TEXT,
    created_by         INTEGER REFERENCES users(id),
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_patients_name ON patients(full_name);
CREATE INDEX IF NOT EXISTS idx_patients_phone ON patients(phone);

CREATE TABLE IF NOT EXISTS visits (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id   INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    doctor_id    INTEGER REFERENCES users(id),
    visit_date   TEXT NOT NULL,
    complaint    TEXT NOT NULL,
    diagnosis    TEXT,
    treatment    TEXT,
    prescription TEXT,
    notes        TEXT,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_visits_patient ON visits(patient_id);

CREATE TABLE IF NOT EXISTS lab_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id  INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    test_name   TEXT NOT NULL,
    result      TEXT NOT NULL,
    result_date TEXT NOT NULL,
    notes       TEXT,
    added_by    INTEGER REFERENCES users(id),
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_labs_patient ON lab_results(patient_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,
    username   TEXT,
    action     TEXT NOT NULL,
    entity     TEXT,
    entity_id  INTEGER,
    details    TEXT,
    ip         TEXT,
    created_at TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(path):
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    # ترحيل: قواعد البيانات القديمة لا تحتوي عمود البصمة
    columns = [r[1] for r in conn.execute("PRAGMA table_info(patients)")]
    if "fingerprint" not in columns:
        conn.execute("ALTER TABLE patients ADD COLUMN fingerprint TEXT")
        conn.commit()
        from integrity import backfill
        backfill(conn)
    conn.commit()
    conn.close()
