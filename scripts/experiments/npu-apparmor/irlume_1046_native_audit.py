"""Strict attribution for all AppArmor denials in one guest test window."""

import json
import re


def validate_window(journal, *, control_pid=None):
    # common_lsm_audit records task_tgid_nr(current), not the worker TID.
    if control_pid is not None and (type(control_pid) is not int or control_pid <= 0):
        raise ValueError("invalid control process identity")
    denials = []
    for line in journal.splitlines():
        row = json.loads(line)
        message = row.get("MESSAGE", "")
        if not isinstance(message, str):
            raise TypeError("unreadable journal message")
        if 'apparmor="DENIED"' not in message:
            continue
        if row.get("_TRANSPORT") not in ("kernel", "audit"):
            raise ValueError("untrusted AppArmor denial source")
        denials.append(message)
        if control_pid is None:
            raise ValueError("unexpected AppArmor denial")
        pid = re.search(r"\bpid=(\d+)\b", message)
        profile = re.search(r'\bprofile="([^"]*)"', message)
        path = re.search(r'\bname="([^"]*)"', message)
        if (
            not pid
            or int(pid[1]) != control_pid
            or not profile
            or profile[1] != "irlumed"
            or not path
            or path[1] != "/opt/irlume-aa-denied"
        ):
            raise ValueError("unrelated AppArmor denial")
    if control_pid is not None and not denials:
        raise ValueError("missing control denial")
    return denials
