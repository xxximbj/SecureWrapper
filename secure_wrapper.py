#!/usr/bin/env python3
from __future__ import annotations
import os
import re
import time
import json
import hmac
import getpass
import hashlib
import threading
from pathlib import Path
from datetime import datetime
from collections import deque, defaultdict
import shlex
import subprocess
import sys
import signal

HOME = str(Path.home())
STATE_DIR = os.path.join(HOME, ".chain_detector")
AUTH_FILE = os.path.join(STATE_DIR, "auth.json")
CONFIG_FILE = os.path.join(STATE_DIR, "config.json")
REPORTS_DIR = os.path.join(STATE_DIR, "reports")
AUTH_LOG = "/var/log/auth.log"

DEFAULT_CONFIG = {
    "require_password_for_all": False,
    "require_password_for_suspicious": True,
    "recent_chmod_seconds": 12,
    "trusted_paths": [
        "/usr/share/kali-themes/xfce4-panel-genmon-vpnip.sh",
        "/usr/bin/xfce4-panel",
        "/usr/lib/xfce4",
    ],
    "protected_paths": [
        ".chain_detector"
    ],
    "protected_files": [
        "secure_wrapper.py"
    ],
    "protected_extensions": [
        ".py"
    ],
    "always_password_commands": [
        "cat", "less", "more", "nano", "vim", "vi",
        "sed", "awk", "grep",
        "rm", "cp", "mv", "chmod", "chown", "chgrp",
        "tar", "zip", "unzip",
        "find", "stat", "ls",
    ],
    "suspicious_commands_patterns": [
        r'chmod\s+[0-7]{3,4}',
        r'echo\s+.*>/etc/sudoers',
        r'rm\s+-rf\s+/',
        r'base64\s+-d',
        r'exec\s+.*\$\(.+\)',
        r'(curl|wget).*\|\s*sh',
        r'chmod\s+\+x.*\./',
    ],
    "ip_change_keywords": [
        r'\bip\s+link\b', r'\bip\s+addr\b', r'\bip\s+route\b',
        r'\bifconfig\b', r'\bdhclient\b', r'\bnmcli\b'
    ],
}

def ensure_state_dir():
    os.makedirs(STATE_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)

def save_json(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def load_json(path, default):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default
    return default

def create_admin_password():
    ensure_state_dir()
    print("=== Initial setup: create program admin password ===")
    while True:
        a = getpass.getpass("Create admin password (for this wrapper): ")
        b = getpass.getpass("Confirm admin password: ")
        if not a:
            print("Password cannot быть пустым.")
            continue
        if a != b:
            print("Passwords do not match.")
            continue
        salt = os.urandom(16).hex()
        dk = hashlib.pbkdf2_hmac("sha256", a.encode(), salt.encode(), 200000)
        save_json(AUTH_FILE, {"salt": salt, "hash": dk.hex()})
        print("Password saved to", AUTH_FILE)
        break

def verify_admin_password(prompt_text: str = "Enter program password: ") -> bool:
    data = load_json(AUTH_FILE, None)
    if not data:
        print("Admin password not set.")
        return False
    salt = data.get("salt")
    stored = data.get("hash")
    attempt = getpass.getpass(prompt_text)
    dk = hashlib.pbkdf2_hmac("sha256", attempt.encode(), salt.encode(), 200000)
    return hmac.compare_digest(dk.hex(), stored)

def is_trusted_path(cmd, cfg):
    if not cmd:
        return False
    for p in cfg.get("trusted_paths", []):
        if p and p in cmd:
            return True
    return False

def _expand_token_to_path(tok):
    tok = tok.strip('"\'')
    if tok.startswith("$"):
        try:
            return os.path.expanduser(os.path.expandvars(tok))
        except Exception:
            return tok
    try:
        return os.path.abspath(os.path.expanduser(os.path.expandvars(tok)))
    except Exception:
        return tok

def touches_protected_path(cmd, cfg):
    protected = cfg.get("protected_paths", [])
    tokens = shlex.split(cmd) if cmd else []
    for tok in tokens:
        if tok in ("|", ">", ">>", "<", ";", "&&", "||"):
            continue
        p = _expand_token_to_path(tok)
        for pp in protected:
            abs_pp = os.path.abspath(os.path.join(HOME, pp))
            try:
                if p == abs_pp or p.startswith(abs_pp + os.sep):
                    return True
            except Exception:
                pass
            if pp in tok:
                return True
    return False

def touches_protected_code(cmd, cfg):
    protected_files = set(cfg.get("protected_files", []))
    protected_exts = cfg.get("protected_extensions", [])
    tokens = shlex.split(cmd) if cmd else []
    for tok in tokens:
        if tok in ("|", ">", ">>", "<", ";", "&&", "||"):
            continue
        base = os.path.basename(tok.strip('"\'')) 
        if base in protected_files:
            return True
        for ext in protected_exts:
            if base.endswith(ext):
                return True
        try:
            p = _expand_token_to_path(tok)
            if os.path.isfile(p):
                script_dir = os.path.dirname(os.path.abspath(__file__))
                try:
                    if os.path.commonpath([script_dir, p]) == script_dir:
                        return True
                except Exception:
                    pass
        except Exception:
            pass
    return False

def command_requires_password_by_name(cmd, cfg):
    tokens = shlex.split(cmd) if cmd else []
    if not tokens:
        return False
    base = os.path.basename(tokens[0])
    return base in cfg.get("always_password_commands", [])

def match_suspicious_command(cmd, cfg):
    s = cmd or ""
    for regex in cfg.get("suspicious_commands_patterns", []):
        try:
            if re.search(regex, s, re.I):
                return True, regex
        except re.error:
            continue
    if re.search(r'(^|\s)(/tmp/|/var/tmp/)', s):
        return True, "PATH_TMP"
    for pat in cfg.get("ip_change_keywords", []):
        try:
            if re.search(pat, s, re.I):
                return True, "IP_CHANGE"
        except re.error:
            continue
    if re.search(r'/etc/(sudoers|crontab)', s):
        return True, "SYSTEM_WRITE"
    return False, None

def run_command_shell(cmd):
    fallback_shell = "/bin/bash"
    shell = os.environ.get("SHELL", fallback_shell)

    try:
        env_shell_abs = os.path.abspath(shell)
    except Exception:
        env_shell_abs = shell

    try:
        script_path = os.path.abspath(__file__)
    except Exception:
        script_path = ""

    if script_path and env_shell_abs == script_path:
        shell = fallback_shell

    env = os.environ.copy()
    env.setdefault("SHELL", shell)

    try:
        res = subprocess.run([shell, "-c", cmd], env=env)
        return res.returncode
    except Exception as e:
        print("Execution error:", e)
        return 127

ssh_accept_re = re.compile(r'Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)')
def auth_log_tail_thread(ip_map, lock, path=AUTH_LOG, poll_interval=0.5):
    try:
        last_inode = None
        f = None
        pos = 0
        while True:
            try:
                if f is None:
                    f = open(path, "r", errors="ignore")
                    last_inode = os.fstat(f.fileno()).st_ino
                    f.seek(0, os.SEEK_END)
                    pos = f.tell()
                line = f.readline()
                if not line:
                    try:
                        cur_inode = os.stat(path).st_ino
                        if cur_inode != last_inode:
                            f.close()
                            f = open(path, "r", errors="ignore")
                            last_inode = os.fstat(f.fileno()).st_ino
                    except FileNotFoundError:
                        pass
                    time.sleep(poll_interval)
                    continue
                m = ssh_accept_re.search(line)
                if m:
                    user = m.group(1)
                    ip = m.group(2)
                    with lock:
                        s = ip_map.setdefault(user, set())
                        if ip not in s:
                            s.add(ip)
            except Exception:
                time.sleep(poll_interval)
    except Exception:
        return

def shell_loop(cfg, ip_map, lock):
    recent_chmod = {} 
    chmod_re = re.compile(r'chmod\s+(?:\+x|[0-7]{3,4})\s+([^\s;]+)', re.I)
    prompt_user = os.environ.get("USER", "user")

    is_remote = bool(os.environ.get("SSH_CONNECTION"))
    if is_remote:
        print("[info] SSH session detected - wrapper will require program password for every command.")

    while True:
        try:
            line = input(f"{prompt_user}@secure$ ").strip()
        except EOFError:
            print("\n[security] Use Ctrl+C or 'exit' with password to quit.")
            continue
        except KeyboardInterrupt:
            print()  
            ok = verify_admin_password("Enter program password to exit: ")
            if ok:
                print("[info] Password OK. Exiting wrapper...")
                break
            else:
                print("Password incorrect — exit denied.")
                continue

        if not line:
            continue

        if line.lower() in ("exit", "logout", "quit"):
            if verify_admin_password("Enter program password to exit: "):
                break
            else:
                print("Password incorrect — exit denied.")
                continue

        m = chmod_re.search(line)
        if m:
            t = m.group(1).strip('"\'')
            recent_chmod[t] = time.time()

        explicit_susp, _ = match_suspicious_command(line, cfg)
        executed_tmp = bool(re.search(r'(^|\s)(/tmp/|/var/tmp/)', line))
        tokens = shlex.split(line) if line else []
        executed_recent_chmod = False
        for tok in tokens:
            p = tok.strip('"\'')
            if p in recent_chmod and (time.time() - recent_chmod[p] <= int(cfg.get("recent_chmod_seconds", 12))):
                executed_recent_chmod = True
                break
            if os.path.isabs(p) and (p.startswith("/tmp/") or p.startswith("/var/tmp/")) and os.path.exists(p):
                executed_tmp = True

        suspicious = explicit_susp or executed_tmp or executed_recent_chmod

        require_all_cfg = bool(cfg.get("require_password_for_all", False))
        require_for_susp = bool(cfg.get("require_password_for_suspicious", True))
        require_all = require_all_cfg or is_remote

        need_password = False

        if touches_protected_path(line, cfg):
            need_password = True
        elif touches_protected_code(line, cfg):
            need_password = True
        elif command_requires_password_by_name(line, cfg):
            need_password = True
        elif require_all:
            need_password = True
        elif require_for_susp and suspicious:
            need_password = True

        if is_trusted_path(line, cfg):
            if not touches_protected_path(line, cfg) and not touches_protected_code(line, cfg):
                need_password = False

        source_ip = None
        username = prompt_user
        with lock:
            s = ip_map.get(username, set())
            if s:
                source_ip = next(iter(s))

        ip_change_like = bool(re.search(r'(^|\s)(ip\s+link|ip\s+addr|ifconfig|dhclient|nmcli)\b', line, re.I))
        if ip_change_like:
            need_password = True

        if need_password:
            ok = verify_admin_password()
            if not ok:
                print("Password incorrect — command denied.")
                continue

        if tokens:
            cmd0 = tokens[0]

            if cmd0 == "cd":
                target = tokens[1] if len(tokens) > 1 else os.path.expanduser("~")
                target = os.path.expanduser(target)
                try:
                    os.chdir(target)
                except Exception as e:
                    print(f"cd: {e}")
                continue

            if cmd0 == "export":
                for part in tokens[1:]:
                    if "=" in part:
                        k, v = part.split("=", 1)
                        os.environ[k] = v
                    else:
                        os.environ[part] = os.environ.get(part, "")
                continue

            if cmd0 == "unset" and len(tokens) > 1:
                for var in tokens[1:]:
                    os.environ.pop(var, None)
                continue

            if cmd0 == "pwd":
                print(os.getcwd())
                continue

        rc = run_command_shell(line)

        nowt = time.time()
        expiry = int(cfg.get("recent_chmod_seconds", 12))
        to_del = [p for p, ts in recent_chmod.items() if nowt - ts > expiry]
        for p in to_del:
            recent_chmod.pop(p, None)

    print("Exiting wrapper.")

def set_login_shell_for_user(script_path, username):
    try:
        import pwd
        pwd.getpwnam(username)
    except Exception:
        print(f"[warning] cannot find user {username}.")
        return False
    try:
        subprocess.run(["chsh", "-s", script_path, username], check=True)
        print(f"[info] set {username} login shell to {script_path} (via chsh).")
        return True
    except Exception:
        print("[warning] chsh failed (maybe not root). You can run as root:")
        print(f"  sudo chsh -s {script_path} {username}")
        return False

def main():
    ensure_state_dir()
    cfg = load_json(CONFIG_FILE, None)
    if cfg is None:
        cfg = DEFAULT_CONFIG.copy()
        save_json(CONFIG_FILE, cfg)
    if not os.path.exists(AUTH_FILE):
        create_admin_password()

    ip_map = {}
    ip_lock = threading.Lock()

    t = threading.Thread(target=auth_log_tail_thread, args=(ip_map, ip_lock, AUTH_LOG), daemon=True)
    t.start()

    script_path = os.path.abspath(__file__)
    my_user = os.environ.get("USER", None)
    try:
        import pwd
        if my_user:
            shell_in_passwd = pwd.getpwnam(my_user).pw_shell
            if shell_in_passwd != script_path:
                print(f"[info] Your login shell in /etc/passwd is: {shell_in_passwd}")
                if os.geteuid() == 0:
                    print("[info] Running as root. Attempting to set wrapper as login shell for the current user...")
                    set_login_shell_for_user(script_path, my_user)
                else:
                    print(f"[hint] To force wrapper as login shell (so remote logins use it), run as root:")
                    print(f"  sudo chsh -s {script_path} {my_user}")
    except Exception:
        pass

    print("Secure wrapper started. Type 'exit' to quit.")
    shell_loop(cfg, ip_map, ip_lock)

    print("[info] Wrapper exited, starting real shell...")
    os.execv("/bin/bash", ["/bin/bash"])

if __name__ == "__main__":
    main()
