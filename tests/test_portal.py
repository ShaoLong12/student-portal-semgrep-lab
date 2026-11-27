"""Lab 5 Step 1 checks plus the security controls from Lab 1 and Lab 2. Run: python -m unittest -v"""
import io
import os
import sqlite3
import sys
import tempfile
import time
import unittest

import pyotp

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app_secure as portal  # noqa: E402

PW = "Correct-Horse-Battery-9!"


def pdf(extra=b""):
    return b"%PDF-1.4\n" + extra + b"\n%%EOF\n"


class PortalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = portal.create_app({"DATABASE": os.path.join(self.tmp.name, "t.db"), "UPLOAD_DIR": os.path.join(self.tmp.name, "up"),
                                      "TESTING": True, "WTF_CSRF_ENABLED": False})
        self.db = sqlite3.connect(self.app.config["DATABASE"])
        self.db.row_factory = sqlite3.Row
        mk = lambda u, n, e, r: portal.create_user(self.db, u, n, e, r, PW)
        self.alice, self.bob = mk("alice", "Alice Tan", "alice@s.example", "student"), mk("bob", "Bob Lim", "bob@s.example", "student")
        self.chen, self.kumar = mk("chen", "Dr Chen", "chen@u.example", "lecturer"), mk("kumar", "Dr Kumar", "kumar@u.example", "lecturer")
        self.db.execute("INSERT INTO courses (id, code, title, lecturer_id) VALUES (1,'CT101','Web',?),(2,'CT102','DB',?)", (self.chen, self.kumar))
        self.db.executemany("INSERT INTO enrolments VALUES (?,?)", [(self.alice, 1), (self.bob, 1), (self.bob, 2)])
        self.db.executemany("INSERT INTO grades (student_id, course_id, assessment, score) VALUES (?,?,?,?)", [(self.alice, 1, "Quiz", 86), (self.bob, 1, "Quiz", 41)])
        self.db.execute("INSERT INTO attendance VALUES (?,1,12,11)", (self.alice,))
        self.db.commit()

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    # -- helpers
    def code_for(self, username):
        row = self.db.execute("SELECT totp_secret FROM users WHERE username=?", (username,)).fetchone()
        self.db.execute("UPDATE users SET totp_last_step=0 WHERE username=?", (username,))
        self.db.commit()
        return pyotp.TOTP(row["totp_secret"]).now()

    def login(self, username, password=PW, client=None):
        c = client or self.app.test_client()
        r = c.post("/login", data={"username": username, "password": password})
        self.assertEqual(r.status_code, 302, r.data[:200])
        c.get("/mfa")                                                     # creates the secret on first use
        r = c.post("/mfa", data={"code": self.code_for(username)})
        self.assertEqual(r.status_code, 302)
        return c

    # -- Lab 5 Step 1
    def test_login_valid_requires_mfa_then_works(self):
        c = self.app.test_client()
        self.assertEqual(c.get("/grades").status_code, 302)               # not signed in
        r = c.post("/login", data={"username": "alice", "password": PW})
        self.assertTrue(r.headers["Location"].endswith("/mfa"))
        self.assertEqual(c.get("/grades").status_code, 302)               # password alone is not enough
        c.get("/mfa")
        c.post("/mfa", data={"code": self.code_for("alice")})
        self.assertEqual(c.get("/grades").status_code, 200)

    def test_wrong_login_generic_and_identical(self):
        c = self.app.test_client()
        a = c.post("/login", data={"username": "alice", "password": "wrong-password-1"})
        b = c.post("/login", data={"username": "nobody", "password": "wrong-password-1"})
        self.assertEqual(a.status_code, b.status_code)
        self.assertIn(b"Invalid credentials.", a.data)
        self.assertEqual(a.data.replace(b"alice", b""), b.data.replace(b"nobody", b""))  # no user-existence leak (4.2.1)

    def test_upload_allowed_types_and_rejections(self):
        c = self.login("alice")
        ok = c.post("/assignments", data={"course_id": "1", "file": (io.BytesIO(pdf()), "report.pdf")}, content_type="multipart/form-data")
        self.assertEqual(ok.status_code, 302)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM submissions").fetchone()[0], 1)
        bad = [("evil.exe", b"MZ\x90\x00"), ("fake.pdf", b"not a pdf"), ("macro.docm", b"PK\x03\x04"), ("shell.php", b"<?php ?>"),
               ("eicar.txt", b"X5O!P%@AP EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"), ("img.png", b"%PDF-1.4 pretending")]
        for name, data in bad:
            r = c.post("/assignments", data={"course_id": "1", "file": (io.BytesIO(data), name)}, content_type="multipart/form-data")
            self.assertEqual(r.status_code, 200, name)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM submissions").fetchone()[0], 1)
        stored = self.db.execute("SELECT stored_name FROM submissions").fetchone()[0]
        self.assertNotIn(".", stored)                                     # random name, no extension

    def test_upload_to_unenrolled_course_rejected_and_size_limit(self):
        c = self.login("alice")
        r = c.post("/assignments", data={"course_id": "2", "file": (io.BytesIO(pdf()), "a.pdf")}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)
        big = pdf(b"A" * (portal.MAX_UPLOAD + 10))
        r = c.post("/assignments", data={"course_id": "1", "file": (io.BytesIO(big), "big.pdf")}, content_type="multipart/form-data")
        self.assertIn(r.status_code, (200, 413))
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM submissions").fetchone()[0], 0)

    def test_messaging_works_and_is_scoped(self):
        lec = self.login("chen")
        r = lec.post("/messages/new", data={"recipient_id": self.alice, "subject": "Feedback", "body": "Well done"})
        self.assertEqual(r.status_code, 302)
        stu = self.login("alice")
        self.assertIn(b"Feedback", stu.get("/messages").data)
        mid = self.db.execute("SELECT id FROM messages").fetchone()[0]
        self.assertEqual(stu.get(f"/messages/{mid}").status_code, 200)
        self.assertEqual(self.login("bob").get(f"/messages/{mid}").status_code, 404)      # other student cannot read it
        # lecturer may only message students of their own courses; students cannot send at all
        self.assertEqual(self.login("kumar").post("/messages/new", data={"recipient_id": self.alice, "subject": "x", "body": "y"}).status_code, 403)
        self.assertEqual(stu.post("/messages/new", data={"recipient_id": self.bob, "subject": "x", "body": "y"}).status_code, 403)

    def test_profile_update_only_own_and_only_allowed_fields(self):
        c = self.login("alice")
        r = c.post("/profile", data={"email": "new@s.example", "phone": "012-3456789", "address": "1 Road", "current_password": PW,
                                     "role": "lecturer", "id": str(self.bob), "username": "hacked", "pw_hash": "x"})
        self.assertEqual(r.status_code, 302)
        alice = self.db.execute("SELECT * FROM users WHERE id=?", (self.alice,)).fetchone()
        self.assertEqual((alice["email"], alice["role"], alice["username"]), ("new@s.example", "student", "alice"))
        bob = self.db.execute("SELECT * FROM users WHERE id=?", (self.bob,)).fetchone()
        self.assertEqual(bob["email"], "bob@s.example")

    # -- Lab 1 / Lab 2 controls
    def test_profile_update_needs_password(self):
        c = self.login("alice")
        c.post("/profile", data={"email": "new@s.example", "phone": "", "address": "", "current_password": "wrong-password-1"})
        self.assertEqual(self.db.execute("SELECT email FROM users WHERE id=?", (self.alice,)).fetchone()[0], "alice@s.example")

    def test_lockout_after_five_failures_even_with_right_password(self):
        c = self.app.test_client()
        for _ in range(5):
            c.post("/login", data={"username": "alice", "password": "wrong-password-1"})
        r = c.post("/login", data={"username": "alice", "password": PW})
        self.assertIn(b"Invalid credentials.", r.data)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(self.db.execute("SELECT locked_until FROM users WHERE id=?", (self.alice,)).fetchone()[0] > time.time())

    def test_captcha_required_after_repeated_failures(self):
        c = self.app.test_client()
        for _ in range(portal.CAPTCHA_AFTER_IP_FAILS):
            c.post("/login", data={"username": "ghost", "password": "wrong-password-1"})
        page = c.get("/login")
        self.assertIn(b"What is", page.data)
        r = c.post("/login", data={"username": "bob", "password": PW, "captcha": "0"})       # right password, wrong captcha
        self.assertEqual(r.status_code, 200)

    def test_totp_code_cannot_be_replayed(self):
        c = self.login("alice")
        row = self.db.execute("SELECT totp_secret FROM users WHERE id=?", (self.alice,)).fetchone()
        code = pyotp.TOTP(row["totp_secret"]).now()
        c2 = self.app.test_client()
        c2.post("/login", data={"username": "alice", "password": PW})
        c2.post("/mfa", data={"code": code})
        self.assertEqual(c2.get("/grades").status_code, 302)              # same code already used at login

    def test_student_sees_only_own_grades_and_roles_enforced(self):
        body = self.login("alice").get("/grades").data
        self.assertIn(b"86", body)
        self.assertNotIn(b">41<", body)
        self.assertEqual(self.login("chen").get("/grades").status_code, 403)
        self.assertEqual(self.login("alice").get("/submissions").status_code, 403)

    def test_file_download_idor(self):
        a = self.login("alice")
        a.post("/assignments", data={"course_id": "1", "file": (io.BytesIO(pdf()), "mine.pdf")}, content_type="multipart/form-data")
        sid = self.db.execute("SELECT id FROM submissions").fetchone()[0]
        self.assertEqual(a.get(f"/files/{sid}").status_code, 200)
        self.assertEqual(self.login("chen").get(f"/files/{sid}").status_code, 200)        # course lecturer
        self.assertEqual(self.login("bob").get(f"/files/{sid}").status_code, 404)         # other student
        self.assertEqual(self.login("kumar").get(f"/files/{sid}").status_code, 404)       # other lecturer
        r = a.get(f"/files/{sid}")
        self.assertIn("attachment", r.headers["Content-Disposition"])

    def test_message_output_encoded_and_url_allowlist(self):
        html = str(portal.linkify('<script>alert(1)</script> see https://example.org/a?b=1&c=2 and javascript:alert(1) and https://x.test"onmouseover=1'))
        self.assertNotIn("<script>", html)
        self.assertIn('href="https://example.org/a?b=1&amp;c=2"', html)
        self.assertNotIn('href="javascript', html)
        self.assertNotIn('"onmouseover', html.replace("&#34;", ""))

    def test_csrf_enforced(self):
        app = portal.create_app({"DATABASE": os.path.join(self.tmp.name, "t.db"), "UPLOAD_DIR": os.path.join(self.tmp.name, "up"), "TESTING": True})
        r = app.test_client().post("/login", data={"username": "alice", "password": PW})
        self.assertEqual(r.status_code, 400)

    def test_headers_cookies_and_error_pages(self):
        c = self.app.test_client()
        r = c.get("/login")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        r = c.get("/nope")
        self.assertEqual(r.status_code, 404)
        self.assertNotIn(b"Traceback", r.data)
        r = self.login("alice").post("/password", data={"current": PW, "new": "short", "again": "short"})
        self.assertIn(b"12 to 128", r.data)

    def test_audit_trail_records_events(self):
        self.login("alice")
        self.app.test_client().post("/login", data={"username": "alice", "password": "wrong-password-1"})
        actions = {r[0] for r in self.db.execute("SELECT action FROM audit")}
        self.assertTrue({"login.success", "login.failure"} <= actions)

    def test_idle_session_expires(self):
        c = self.login("alice")
        with c.session_transaction() as s:
            s["seen"] = time.time() - portal.IDLE_TIMEOUT - 5
        self.assertEqual(c.get("/grades").status_code, 302)

    def test_passwords_stored_with_argon2(self):
        h = self.db.execute("SELECT pw_hash FROM users WHERE id=?", (self.alice,)).fetchone()[0]
        self.assertTrue(h.startswith("$argon2"))


if __name__ == "__main__":
    unittest.main()
