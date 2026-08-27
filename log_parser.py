"""
Real-Time Mini SIEM — log collector, parser, correlation and alerting engine.

The collector watches a syslog-style file, normalizes SSH/authentication events,
stores them in SQLite, correlates suspicious activity per source IP, and emits
SOC alerts through the console, Slack and SMTP email.

Configuration is read from environment variables so secrets are never committed
to the repository.
"""

import ipaddress
import os
import re
import smtplib
import sqlite3
import threading
import time
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests

DB = os.getenv("SIEM_DB", "siem.db")
LOG_FILE = os.getenv("SIEM_LOG_FILE", "test.log")

ALERT_CONFIG = {
    "failed_login_threshold": int(os.getenv("FAILED_LOGIN_THRESHOLD", "5")),
    "failed_login_window_secs": int(os.getenv("FAILED_LOGIN_WINDOW_SECS", "60")),
    "invalid_user_threshold": int(os.getenv("INVALID_USER_THRESHOLD", "3")),
    "invalid_user_window_secs": int(os.getenv("INVALID_USER_WINDOW_SECS", "60")),
    "unique_user_threshold": int(os.getenv("UNIQUE_USER_THRESHOLD", "4")),
    "unique_user_window_secs": int(os.getenv("UNIQUE_USER_WINDOW_SECS", "60")),
    "correlation_window_secs": int(os.getenv("CORRELATION_WINDOW_SECS", "180")),
    "alert_cooldown_secs": int(os.getenv("ALERT_COOLDOWN_SECS", "300")),
    "email_enabled": os.getenv("EMAIL_ENABLED", "false").lower() == "true",
    "smtp_host": os.getenv("SMTP_HOST", "smtp.gmail.com"),
    "smtp_port": int(os.getenv("SMTP_PORT", "587")),
    "smtp_user": os.getenv("SMTP_USER", ""),
    "smtp_password": os.getenv("SMTP_PASSWORD", ""),
    "alert_recipient": os.getenv("ALERT_RECIPIENT", ""),
    "slack_enabled": os.getenv("SLACK_ENABLED", "false").lower() == "true",
    "slack_webhook_url": os.getenv("SLACK_WEBHOOK_URL", ""),
}

IP_PATTERN = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
USER_PATTERN = re.compile(
    r"(?:for (?:invalid user )?|user )([A-Za-z0-9._@-]+)"
)
SYSLOG_PATTERN = re.compile(
    r"(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+([^\[:\s]+)"
    r"(?:\[\d+\])?\s*:\s+(.*)"
)

TAG_RULES = [
    ("Failed password", "failed_login"),
    ("Accepted password", "successful_login"),
    ("Accepted publickey", "successful_login"),
    ("Invalid user", "invalid_user"),
    ("Connection closed", "connection_closed"),
    ("Disconnected from", "disconnected"),
    ("session opened", "session_opened"),
    ("session closed", "session_closed"),
    ("sudo:", "sudo"),
    ("CRON", "cron"),
]

SEVERITY = {
    "normal": "low",
    "successful_login": "low",
    "session_opened": "low",
    "session_closed": "low",
    "connection_closed": "low",
    "disconnected": "low",
    "cron": "low",
    "sudo": "medium",
    "invalid_user": "medium",
    "failed_login": "medium",
}

MITRE = {
    "brute_force_detected": ("T1110.001", "Password Guessing"),
    "password_spraying_detected": ("T1110.003", "Password Spraying"),
    "invalid_user_probe": ("T1087.001", "Local Account"),
    "successful_login_after_failures": ("T1078", "Valid Accounts"),
    "privileged_user_targeted": ("T1078", "Valid Accounts"),
}


def classify_user(username: str) -> str:
    """Return a small targeting label for common high-value account names."""
    if not username:
        return ""
    user = username.lower()
    if user in {"root", "administrator", "admin", "ubuntu"}:
        return "privileged_target"
    if any(word in user for word in ("test", "guest", "backup", "service")):
        return "service_or_test_target"
    return ""


def normalize_ip(value: str) -> str:
    """Keep only valid IPv4 values; malformed values are discarded."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def parse_line(line: str):
    match = SYSLOG_PATTERN.match(line.strip())
    if not match:
        return None

    timestamp_raw, host, program, message = match.groups()
    tag = "normal"
    for keyword, event_tag in TAG_RULES:
        if keyword.lower() in message.lower():
            tag = event_tag
            break

    ip_match = IP_PATTERN.search(message)
    src_ip = normalize_ip(ip_match.group(1)) if ip_match else ""

    username = ""
    user_match = USER_PATTERN.search(message)
    if user_match:
        username = user_match.group(1)
    elif "for root" in message.lower():
        username = "root"

    return {
        "timestamp": datetime.now().isoformat(sep=" ", timespec="seconds"),
        "syslog_timestamp": timestamp_raw,
        "host": host,
        "program": program,
        "message": message,
        "tag": tag,
        "src_ip": src_ip,
        "username": username,
        "severity": SEVERITY.get(tag, "low"),
        "target_class": classify_user(username),
    }


def init_db():
    conn = sqlite3.connect(DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            host TEXT,
            program TEXT,
            message TEXT,
            tag TEXT,
            src_ip TEXT,
            username TEXT DEFAULT '',
            severity TEXT DEFAULT 'low',
            target_class TEXT DEFAULT ''
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            alert_type TEXT,
            detail TEXT,
            sent_via TEXT,
            severity TEXT DEFAULT 'high',
            src_ip TEXT DEFAULT '',
            mitre_id TEXT DEFAULT '',
            mitre_name TEXT DEFAULT ''
        )
    """)
    # Backward-compatible schema upgrades for an existing local DB.
    for column, ddl in [
        ("username", "TEXT DEFAULT ''"),
        ("severity", "TEXT DEFAULT 'low'"),
        ("target_class", "TEXT DEFAULT ''"),
    ]:
        try:
            conn.execute(f"ALTER TABLE logs ADD COLUMN {column} {ddl}")
        except sqlite3.OperationalError:
            pass
    for column, ddl in [
        ("severity", "TEXT DEFAULT 'high'"),
        ("src_ip", "TEXT DEFAULT ''"),
        ("mitre_id", "TEXT DEFAULT ''"),
        ("mitre_name", "TEXT DEFAULT ''"),
    ]:
        try:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {column} {ddl}")
        except sqlite3.OperationalError:
            pass
    conn.commit()
    conn.close()
    print(f"[DB] Initialised {DB}")


def insert_log(entry):
    conn = sqlite3.connect(DB)
    conn.execute(
        """INSERT INTO logs
           (timestamp, host, program, message, tag, src_ip, username, severity, target_class)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (
            entry["timestamp"], entry["host"], entry["program"], entry["message"],
            entry["tag"], entry.get("src_ip", ""), entry.get("username", ""),
            entry.get("severity", "low"), entry.get("target_class", ""),
        ),
    )
    conn.commit()
    conn.close()


def insert_alert(alert_type, detail, sent_via, severity, src_ip):
    mitre_id, mitre_name = MITRE.get(alert_type, ("", ""))
    conn = sqlite3.connect(DB)
    conn.execute(
        """INSERT INTO alerts
           (timestamp, alert_type, detail, sent_via, severity, src_ip, mitre_id, mitre_name)
           VALUES (?,?,?,?,?,?,?,?)""",
        (datetime.now().isoformat(sep=" ", timespec="seconds"),
         alert_type, detail, sent_via, severity, src_ip, mitre_id, mitre_name),
    )
    conn.commit()
    conn.close()


# Per-IP correlation state. Bounded deques prevent unbounded memory growth.
recent_failures = defaultdict(deque)
recent_invalid_users = defaultdict(deque)
recent_usernames = defaultdict(deque)
last_alert_time = {}


def _prune(queue, cutoff):
    while queue and queue[0][0] <= cutoff:
        queue.popleft()


def send_email(subject, body):
    if not ALERT_CONFIG["email_enabled"]:
        return False
    if not all([
        ALERT_CONFIG["smtp_user"],
        ALERT_CONFIG["smtp_password"],
        ALERT_CONFIG["alert_recipient"],
    ]):
        print("[EMAIL] Skipped: SMTP credentials/recipient not configured.")
        return False

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = ALERT_CONFIG["smtp_user"]
        msg["To"] = ALERT_CONFIG["alert_recipient"]
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP(
            ALERT_CONFIG["smtp_host"], ALERT_CONFIG["smtp_port"], timeout=10
        ) as smtp:
            smtp.starttls()
            smtp.login(ALERT_CONFIG["smtp_user"], ALERT_CONFIG["smtp_password"])
            smtp.sendmail(
                ALERT_CONFIG["smtp_user"],
                ALERT_CONFIG["alert_recipient"],
                msg.as_string(),
            )
        return True
    except Exception as exc:
        print(f"[EMAIL ERROR] {exc}")
        return False


def send_slack(message):
    if not ALERT_CONFIG["slack_enabled"]:
        return False
    webhook = ALERT_CONFIG["slack_webhook_url"]
    if not webhook:
        print("[SLACK] Skipped: webhook not configured.")
        return False

    try:
        payload = {
            "text": f"🚨 *SIEM ALERT*\n```{message}```",
            "username": "Mini-SIEM",
            "icon_emoji": ":warning:",
        }
        resp = requests.post(webhook, json=payload, timeout=5)
        if 200 <= resp.status_code < 300:
            return True
        print(f"[SLACK ERROR] HTTP {resp.status_code}")
    except requests.RequestException as exc:
        print(f"[SLACK ERROR] {exc}")
    return False


def fire_alert(alert_type, detail, src_ip="", severity="high"):
    """Deduplicated, source-aware alert delivery and persistence."""
    now = datetime.now()
    key = f"{alert_type}:{src_ip or 'unknown'}"
    last = last_alert_time.get(key)
    if last and (now - last).total_seconds() < ALERT_CONFIG["alert_cooldown_secs"]:
        return False

    last_alert_time[key] = now
    mitre_id, mitre_name = MITRE.get(alert_type, ("", ""))

    subject = (
        f"🚨 SIEM [{severity.upper()}] "
        f"{alert_type.replace('_', ' ').title()}"
    )
    body = (
        f"{subject}\n\n"
        f"Time: {now.isoformat(sep=' ', timespec='seconds')}\n"
        f"Source IP: {src_ip or 'unknown'}\n"
        f"Severity: {severity}\n"
        f"MITRE ATT&CK: {mitre_id} {mitre_name}\n"
        f"Detail: {detail}\n"
    )

    print("\n" + "=" * 64)
    print(f"  ⚠ ALERT: {alert_type} | {severity.upper()} | {src_ip or 'unknown'}")
    print(f"  {detail}")
    if mitre_id:
        print(f"  ATT&CK: {mitre_id} — {mitre_name}")
    print("=" * 64)

    channels = []
    if send_email(subject, body):
        channels.append("email")
    if send_slack(body):
        channels.append("slack")
    if not channels:
        channels.append("console")

    insert_alert(alert_type, detail, ", ".join(channels), severity, src_ip)
    return True


def check_thresholds(entry):
    """Detect brute force, user enumeration, spraying, and post-compromise signals."""
    ip = entry.get("src_ip", "")
    if not ip:
        return

    now = datetime.now()
    tag = entry["tag"]
    cutoff = now - timedelta(
        seconds=max(
            ALERT_CONFIG["failed_login_window_secs"],
            ALERT_CONFIG["invalid_user_window_secs"],
            ALERT_CONFIG["unique_user_window_secs"],
            ALERT_CONFIG["correlation_window_secs"],
        )
    )

    # Maintain all per-IP windows.
    if tag == "failed_login":
        recent_failures[ip].append((now, entry.get("username", "")))
    if tag == "invalid_user":
        recent_invalid_users[ip].append((now, entry.get("username", "")))

    username = entry.get("username", "")
    if username:
        recent_usernames[ip].append((now, username.lower()))

    _prune(recent_failures[ip], cutoff)
    _prune(recent_invalid_users[ip], cutoff)
    _prune(recent_usernames[ip], cutoff)

    # 1. Same-IP brute force.
    fail_cutoff = now - timedelta(seconds=ALERT_CONFIG["failed_login_window_secs"])
    failures = [x for x in recent_failures[ip] if x[0] > fail_cutoff]
    if len(failures) >= ALERT_CONFIG["failed_login_threshold"]:
        fire_alert(
            "brute_force_detected",
            f"{len(failures)} failed SSH logins from {ip} "
            f"within {ALERT_CONFIG['failed_login_window_secs']}s.",
            ip,
            "high",
        )

    # 2. Invalid-user / account enumeration.
    invalid_cutoff = now - timedelta(
        seconds=ALERT_CONFIG["invalid_user_window_secs"]
    )
    invalids = [x for x in recent_invalid_users[ip] if x[0] > invalid_cutoff]
    if len(invalids) >= ALERT_CONFIG["invalid_user_threshold"]:
        fire_alert(
            "invalid_user_probe",
            f"{len(invalids)} invalid-user attempts from {ip}; "
            f"possible account enumeration.",
            ip,
            "medium",
        )

    # 3. Password spraying: many distinct accounts from one source.
    unique_cutoff = now - timedelta(
        seconds=ALERT_CONFIG["unique_user_window_secs"]
    )
    users = {
        username
        for ts, username in recent_usernames[ip]
        if ts > unique_cutoff and username
    }
    if len(users) >= ALERT_CONFIG["unique_user_threshold"]:
        fire_alert(
            "password_spraying_detected",
            f"{len(users)} distinct usernames targeted from {ip} "
            f"within {ALERT_CONFIG['unique_user_window_secs']}s.",
            ip,
            "high",
        )

    # 4. High-value account targeting.
    if entry.get("target_class") == "privileged_target":
        fire_alert(
            "privileged_user_targeted",
            f"Authentication attempt targeted high-value account "
            f"'{entry.get('username')}'.",
            ip,
            "high",
        )

    # 5. Correlation: success following recent failures from same IP.
    if tag == "successful_login":
        correlation_cutoff = now - timedelta(
            seconds=ALERT_CONFIG["correlation_window_secs"]
        )
        prior_failures = [
            ts for ts, _ in recent_failures[ip] if ts > correlation_cutoff
        ]
        if prior_failures:
            fire_alert(
                "successful_login_after_failures",
                f"Successful login from {ip} after "
                f"{len(prior_failures)} recent failed attempts; investigate.",
                ip,
                "critical",
            )


def watch_log():
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "a").close()

    print(f"[SIEM] Watching {LOG_FILE} — Ctrl+C to stop")

    with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as file:
        file.seek(0, 2)

        while True:
            line = file.readline()
            if not line:
                time.sleep(0.5)
                continue

            entry = parse_line(line)
            if not entry:
                continue

            insert_log(entry)
            tag_display = entry["tag"].upper().ljust(24)
            ip_display = f" ip={entry['src_ip']}" if entry["src_ip"] else ""
            user_display = f" user={entry['username']}" if entry["username"] else ""

            print(
                f"[{entry['severity'].upper():8}] "
                f"[{tag_display}] {entry['message'][:70]}"
                f"{ip_display}{user_display}"
            )

            # Correlation state is shared; keep parsing responsive.
            threading.Thread(
                target=check_thresholds,
                args=(entry,),
                daemon=True,
            ).start()


if __name__ == "__main__":
    init_db()
    print("[SIEM] Detection profile:")
    print(
        f"       Brute force   : {ALERT_CONFIG['failed_login_threshold']} "
        f"fails / {ALERT_CONFIG['failed_login_window_secs']}s per IP"
    )
    print(
        f"       User probe    : {ALERT_CONFIG['invalid_user_threshold']} "
        f"invalid users / {ALERT_CONFIG['invalid_user_window_secs']}s per IP"
    )
    print(
        f"       Spray         : {ALERT_CONFIG['unique_user_threshold']} "
        f"unique users / {ALERT_CONFIG['unique_user_window_secs']}s per IP"
    )
    print(
        f"       Correlation   : success after failures within "
        f"{ALERT_CONFIG['correlation_window_secs']}s"
    )
    print(f"       Email alerts  : {'ON' if ALERT_CONFIG['email_enabled'] else 'OFF'}")
    print(f"       Slack alerts  : {'ON' if ALERT_CONFIG['slack_enabled'] else 'OFF'}")
    watch_log()
