#!/usr/bin/env python3
"""
=============================================================
  CYBER RANGE — VyOS 1.5 Cleanup Script
  Cancella tutta la configurazione firewall (e NAT se richiesto)
  Run on : localmente sul VyOS (sudo python3 cleanup_firewall.py)
  Usage  : sudo python3 cleanup_firewall.py
           sudo python3 cleanup_firewall.py --nat   (include delete nat)
=============================================================
"""
import subprocess, tempfile, os, sys

delete_nat = "--nat" in sys.argv

COMMANDS = """
delete firewall
""" + ("delete nat\n" if delete_nat else "")

def build_script(commands):
    lines = ["#!/bin/vbash",
             "source /opt/vyatta/etc/functions/script-template",
             "configure"]
    for line in commands.strip().splitlines():
        line = line.strip()
        if line: lines.append(line)
    lines += ["commit", "save", "exit"]
    return "\n".join(lines) + "\n"

def run():
    print("=" * 60)
    print("  VyOS CLEANUP — Cancella configurazione firewall")
    if delete_nat:
        print("  Modalità: firewall + NAT (--nat)")
    else:
        print("  Modalità: solo firewall")
        print("  (usa --nat per cancellare anche il NAT)")
    print("=" * 60)
    print("\n[WARN] Questo cancella TUTTA la configurazione firewall attiva.")
    confirm = input("Procedere? [s/N]: ").strip().lower()
    if confirm not in ("s", "si", "y", "yes"):
        print("[ANNULLATO]"); sys.exit(0)

    script = build_script(COMMANDS)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh",
                                     delete=False, prefix="vyos_clean_") as f:
        f.write(script); tmp = f.name
    os.chmod(tmp, 0o755)
    try:
        r = subprocess.run(["/bin/vbash", tmp], capture_output=True, text=True)
        if r.stdout: print("[OUT]\n" + r.stdout)
        if r.stderr: print("[ERR]\n" + r.stderr)
        if r.returncode == 0:
            print("\n[OK] Firewall pulito. Ora puoi lanciare il configure script.")
        else:
            print(f"\n[ERRORE] rc={r.returncode}")
            sys.exit(r.returncode)
    finally:
        os.unlink(tmp)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[WARN] Esegui come root")
    run()
