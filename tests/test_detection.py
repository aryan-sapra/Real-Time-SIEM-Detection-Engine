import os
import tempfile
import unittest
from datetime import datetime

import log_parser


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.tmp.close()
        self.old_db = log_parser.DB
        log_parser.DB = self.tmp.name
        log_parser.init_db()
        log_parser.recent_failures.clear()
        log_parser.recent_invalid_users.clear()
        log_parser.recent_usernames.clear()
        log_parser.last_alert_time.clear()

    def tearDown(self):
        log_parser.DB = self.old_db
        os.unlink(self.tmp.name)

    def test_parse_extracts_ip_and_username(self):
        line = "May 28 10:20:00 kali sshd: Failed password for invalid user attacker from 192.168.1.50"
        entry = log_parser.parse_line(line)
        self.assertEqual(entry["tag"], "failed_login")
        self.assertEqual(entry["src_ip"], "192.168.1.50")
        self.assertEqual(entry["username"], "attacker")
        self.assertEqual(entry["severity"], "medium")

    def test_parse_marks_privileged_target(self):
        line = "May 28 10:20:00 kali sshd: Failed password for root from 10.0.0.5"
        entry = log_parser.parse_line(line)
        self.assertEqual(entry["target_class"], "privileged_target")

    def test_bruteforce_is_per_ip(self):
        original = log_parser.ALERT_CONFIG["failed_login_threshold"]
        log_parser.ALERT_CONFIG["failed_login_threshold"] = 2
        try:
            e1 = log_parser.parse_line("May 28 10:20:00 kali sshd: Failed password for bob from 10.0.0.1")
            e2 = log_parser.parse_line("May 28 10:20:01 kali sshd: Failed password for bob from 10.0.0.1")
            log_parser.check_thresholds(e1)
            log_parser.check_thresholds(e2)
            alerts = log_parser.sqlite3.connect(log_parser.DB).execute("SELECT alert_type, src_ip FROM alerts").fetchall()
            self.assertTrue(any(a[0] == "brute_force_detected" and a[1] == "10.0.0.1" for a in alerts))
        finally:
            log_parser.ALERT_CONFIG["failed_login_threshold"] = original


if __name__ == "__main__":
    unittest.main()
