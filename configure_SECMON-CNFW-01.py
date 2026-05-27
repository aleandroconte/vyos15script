#!/usr/bin/env python3
"""
=============================================================
  CYBER RANGE — VyOS 1.5 Firewall Configuration Script
  Device  : SECMON-CNFW-01
  Role    : Firewall SOC / SecMon <-> Core Network
  Run on  : localmente sul VyOS (sudo python3 configure_SECMON-CNFW-01.py)
=============================================================
"""

import subprocess
import tempfile
import os
import sys

# ─────────────────────────────────────────────
#  CONFIGURAZIONE — modifica qui se necessario
# ─────────────────────────────────────────────

IF_CN  = "eth1"   # interfaccia verso CN / Switch soc transit  (10.0.94.5)
IF_SOC = "eth2"   # interfaccia verso Switch soczone           (10.0.17.23)

# Subnet SOC
SUBNET_SOC = "10.0.17.0/24"

# Subnet sorgente RDP inbound (Blue Team)
SUBNET_BLUE = "10.0.11.0/24"

# Tutte le subnet monitorate da SecMon (esclusa RED 58.16.10.0/24)
TARGETS = [
    ("10.0.13.0/24",  "DMZ"),
    ("10.0.11.0/24",  "Blue Team"),
    ("10.2.150.0/24", "EMPLOY/Mission"),
    ("10.0.14.0/24",  "IT"),
    ("10.1.21.0/24",  "MANAGE"),
]

# ─────────────────────────────────────────────
#  COSTRUZIONE DINAMICA DEI COMANDI SOC → CN
# ─────────────────────────────────────────────

soc_to_cn_rules = ""
for i, (subnet, label) in enumerate(TARGETS, start=10):
    rule = i * 10  # 100, 110, 120 ...
    soc_to_cn_rules += f"""
set firewall ipv4 name SOC-TO-CN rule {rule} description 'SecMon -> {label}'
set firewall ipv4 name SOC-TO-CN rule {rule} action accept
set firewall ipv4 name SOC-TO-CN rule {rule} source address {SUBNET_SOC}
set firewall ipv4 name SOC-TO-CN rule {rule} destination address {subnet}
"""

COMMANDS = f"""
# ── Zone policy ──────────────────────────────
set zone-policy zone CN description 'Core Network (transit)'
set zone-policy zone CN interface {IF_CN}
set zone-policy zone SOC description 'SecMon / SOC zone'
set zone-policy zone SOC interface {IF_SOC}

# ── Ruleset: CN → SOC ────────────────────────
# Permette al Blue Team (via CN) di fare RDP verso i box SOC
set firewall ipv4 name CN-TO-SOC description 'Core Network verso SOC zone'
set firewall ipv4 name CN-TO-SOC default-action drop
set firewall ipv4 name CN-TO-SOC enable-default-log

set firewall ipv4 name CN-TO-SOC rule 5 description 'Allow established/related'
set firewall ipv4 name CN-TO-SOC rule 5 action accept
set firewall ipv4 name CN-TO-SOC rule 5 state established enable
set firewall ipv4 name CN-TO-SOC rule 5 state related enable

set firewall ipv4 name CN-TO-SOC rule 10 description 'RDP Blue Team -> SOC subnet'
set firewall ipv4 name CN-TO-SOC rule 10 action accept
set firewall ipv4 name CN-TO-SOC rule 10 source address {SUBNET_BLUE}
set firewall ipv4 name CN-TO-SOC rule 10 destination address {SUBNET_SOC}
set firewall ipv4 name CN-TO-SOC rule 10 destination port 3389
set firewall ipv4 name CN-TO-SOC rule 10 protocol tcp

# ── Ruleset: SOC → CN ────────────────────────
# SecMon raggiunge tutte le subnet (esclusa RED) per monitoraggio
set firewall ipv4 name SOC-TO-CN description 'SOC zone verso tutte le subnet (monitoraggio)'
set firewall ipv4 name SOC-TO-CN default-action drop

set firewall ipv4 name SOC-TO-CN rule 5 description 'Allow established/related'
set firewall ipv4 name SOC-TO-CN rule 5 action accept
set firewall ipv4 name SOC-TO-CN rule 5 state established enable
set firewall ipv4 name SOC-TO-CN rule 5 state related enable
{soc_to_cn_rules}
# ── Applica zone policy ───────────────────────
set zone-policy zone SOC from CN  firewall name CN-TO-SOC
set zone-policy zone CN  from SOC firewall name SOC-TO-CN
"""

# ─────────────────────────────────────────────
#  ESECUZIONE
# ─────────────────────────────────────────────

def build_vbash_script(commands):
    lines = ["#!/bin/vbash",
             "source /opt/vyatta/etc/functions/script-template",
             "configure"]
    for line in commands.strip().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    lines += ["commit", "save", "exit"]
    return "\n".join(lines) + "\n"

def run():
    print("=" * 60)
    print("  SECMON-CNFW-01 — VyOS Firewall Configuration")
    print("=" * 60)
    print(f"\n[INFO] SecMon monitorerà {len(TARGETS)} subnet (esclusa RED):")
    for subnet, label in TARGETS:
        print(f"         {subnet}  ({label})")
    script_content = build_vbash_script(COMMANDS)
    print("\n[INFO] Comandi che verranno applicati:\n")
    for line in script_content.splitlines():
        print(f"  {line}")
    print("\n" + "─" * 60)
    confirm = input("Procedere con la configurazione? [s/N]: ").strip().lower()
    if confirm not in ("s", "si", "yes", "y"):
        print("[ANNULLATO] Nessuna modifica applicata.")
        sys.exit(0)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh",
                                     delete=False, prefix="vyos_cfg_") as f:
        f.write(script_content)
        tmpfile = f.name
    os.chmod(tmpfile, 0o755)
    print(f"\n[INFO] Script temporaneo: {tmpfile}")
    print("[INFO] Applicazione configurazione in corso...\n")
    try:
        result = subprocess.run(["/bin/vbash", tmpfile], capture_output=True, text=True)
        if result.stdout:
            print("[OUTPUT]\n" + result.stdout)
        if result.stderr:
            print("[STDERR]\n" + result.stderr)
        if result.returncode == 0:
            print("\n[OK] Configurazione applicata e salvata con successo.")
        else:
            print(f"\n[ERRORE] Codice di uscita: {result.returncode}.")
            sys.exit(result.returncode)
    finally:
        os.unlink(tmpfile)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[WARN] Esegui come root o con sudo per risultati affidabili.")
    run()
