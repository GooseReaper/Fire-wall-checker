#!/usr/bin/env python3
"""Simple firewall checker for Linux, Windows, and macOS."""

import json
import platform
import subprocess
import sys


def run_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except Exception as exc:  # pragma: no cover - defensive guard
        return 1, "", str(exc)


def check_linux_firewall():
    checks = [
        ("ufw", "ufw status 2>/dev/null"),
        ("iptables", "iptables -S 2>/dev/null || iptables-save 2>/dev/null"),
        ("nftables", "nft list ruleset 2>/dev/null"),
        ("firewalld", "firewall-cmd --state 2>/dev/null"),
    ]

    for name, command in checks:
        code, stdout, stderr = run_command(command)
        if code == 0 and stdout.strip():
            detail_lines = stdout.splitlines()[:20]
            return {
                "name": name,
                "enabled": True,
                "details": detail_lines,
            }

    return {
        "name": "Linux firewall",
        "enabled": False,
        "details": "No common Linux firewall was detected or it is disabled.",
    }


def check_windows_firewall():
    commands = [
        r'netsh advfirewall firewall show rule name=all',
        r'netsh advfirewall show allprofiles',
    ]

    for command in commands:
        code, stdout, stderr = run_command(command)
        if code == 0 and stdout.strip():
            return {
                "name": "Windows Firewall",
                "enabled": True,
                "details": stdout.splitlines()[:20],
            }

    return {
        "name": "Windows Firewall",
        "enabled": False,
        "details": "Windows Firewall could not be confirmed from the local system.",
    }


def check_macos_firewall():
    code, stdout, stderr = run_command("pfctl -sr 2>/dev/null")
    if code == 0 and stdout.strip():
        return {
            "name": "macOS PF",
            "enabled": True,
            "details": stdout.splitlines()[:20],
        }

    return {
        "name": "macOS firewall",
        "enabled": False,
        "details": "No active PF rules were detected; firewall may be off or not configured.",
    }


def main():
    os_name = platform.system().lower()

    if os_name.startswith("linux"):
        status = check_linux_firewall()
    elif os_name.startswith("windows"):
        status = check_windows_firewall()
    elif os_name.startswith("darwin"):
        status = check_macos_firewall()
    else:
        status = {
            "name": platform.system() or "Unknown",
            "enabled": False,
            "details": "Unsupported operating system for this checker.",
        }

    print(json.dumps(status, indent=2))
    return 0 if status.get("enabled") else 1


if __name__ == "__main__":
    raise SystemExit(main())
