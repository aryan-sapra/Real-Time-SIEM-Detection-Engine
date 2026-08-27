"""Generate safe, local synthetic SSH events for demo/testing."""
from pathlib import Path
import argparse
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", default="test.log")
    args = parser.parse_args()
    path = Path(args.log)

    events = [
        "May 28 10:20:00 kali sshd: Failed password for invalid user attacker1 from 192.168.1.50",
        "May 28 10:20:01 kali sshd: Failed password for invalid user attacker2 from 192.168.1.50",
        "May 28 10:20:02 kali sshd: Failed password for invalid user attacker3 from 192.168.1.50",
        "May 28 10:20:03 kali sshd: Failed password for invalid user attacker4 from 192.168.1.50",
        "May 28 10:20:04 kali sshd: Failed password for invalid user attacker5 from 192.168.1.50",
        "May 28 10:20:08 kali sshd: Accepted password for admin from 192.168.1.50",
    ]

    with path.open("a", encoding="utf-8") as fh:
        for line in events:
            fh.write(line + "\n")
            fh.flush()
            print("[SIM]", line)
            time.sleep(0.3)


if __name__ == "__main__":
    main()
