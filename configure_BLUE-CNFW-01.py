#!/usr/bin/env python3
"""
=============================================================
  CYBER RANGE — VyOS 1.5 Firewall Configuration Script
  Device  : BLUE-CNFW-01
  Role    : Firewall Blue Team <-> Core Network
  Run on  : localmente sul VyOS (sudo python3 configure_BLUE-CNFW-01.py)
=============================================================
"""

import subprocess
import tempfile
import os
import sys

# ─────────────────────────────────────────────
#  CONFIGURAZIONE — modifica qui se necessario
# ─────────────────────────────────────────────

IF_CN   = "eth1"   # interfaccia verso CN / Switch blue transit  (10.0.93.29)
IF_BLUE = "eth2"   # interfaccia verso Switch blueteam           (10.0.11.1)

# Subnet Blue Team
SUBNET_BLUE = "10.0.11.0/24"

# Tutte le subnet raggiungibili via CN (esclusa RED)
SUBNET_DMZ    = "10.0.13.0/24"
SUBNET_EMPLOY = "10.2.150.0/24"
SUBNET_SOC    = "10.0.17.0/24"
SUBNET_IT     = "10.0.14.0/24"
SUBNET_MANAGE = "10.1.21.0/24"

IP_VPN01 = "10.0.13.30"   # DMZ-VPN-01 (SSH)
IP_DC01  = "10.0.14.11"    # IT-DC-01 (DNS / Domain Controller)

# ─────────────────────────────────────────────
#  COMANDI VYOS
# ─────────────────────────────────────────────

COMMANDS = f"""
# ── Zone policy ──────────────────────────────
set zone-policy zone CN description 'Core Network (transit)'
set zone-policy zone CN interface {IF_CN}
set zone-policy zone BLUE description 'Blue Team subnet'
set zone-policy zone BLUE interface {IF_BLUE}

# ── Ruleset: BLUE → CN ───────────────────────
set firewall ipv4 name BLUE-TO-CN description 'Blue Team verso Core Network'
set firewall ipv4 name BLUE-TO-CN default-action drop
set firewall ipv4 name BLUE-TO-CN enable-default-log

set firewall ipv4 name BLUE-TO-CN rule 5 description 'Allow established/related'
set firewall ipv4 name BLUE-TO-CN rule 5 action accept
set firewall ipv4 name BLUE-TO-CN rule 5 state established enable
set firewall ipv4 name BLUE-TO-CN rule 5 state related enable

# RDP → DMZ subnet
set firewall ipv4 name BLUE-TO-CN rule 10 description 'RDP Blue -> DMZ'
set firewall ipv4 name BLUE-TO-CN rule 10 action accept
set firewall ipv4 name BLUE-TO-CN rule 10 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-CN rule 10 destination address {SUBNET_DMZ}
set firewall ipv4 name BLUE-TO-CN rule 10 destination port 3389
set firewall ipv4 name BLUE-TO-CN rule 10 protocol tcp

# SSH → DMZ-VPN-01
set firewall ipv4 name BLUE-TO-CN rule 20 description 'SSH Blue -> DMZ-VPN-01'
set firewall ipv4 name BLUE-TO-CN rule 20 action accept
set firewall ipv4 name BLUE-TO-CN rule 20 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-CN rule 20 destination address {IP_VPN01}
set firewall ipv4 name BLUE-TO-CN rule 20 destination port 22
set firewall ipv4 name BLUE-TO-CN rule 20 protocol tcp

# RDP → EMPLOY / Mission subnet
set firewall ipv4 name BLUE-TO-CN rule 30 description 'RDP Blue -> EMPLOY'
set firewall ipv4 name BLUE-TO-CN rule 30 action accept
set firewall ipv4 name BLUE-TO-CN rule 30 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-CN rule 30 destination address {SUBNET_EMPLOY}
set firewall ipv4 name BLUE-TO-CN rule 30 destination port 3389
set firewall ipv4 name BLUE-TO-CN rule 30 protocol tcp

# RDP → SOC subnet
set firewall ipv4 name BLUE-TO-CN rule 40 description 'RDP Blue -> SOC'
set firewall ipv4 name BLUE-TO-CN rule 40 action accept
set firewall ipv4 name BLUE-TO-CN rule 40 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-CN rule 40 destination address {SUBNET_SOC}
set firewall ipv4 name BLUE-TO-CN rule 40 destination port 3389
set firewall ipv4 name BLUE-TO-CN rule 40 protocol tcp

# RDP → IT subnet
set firewall ipv4 name BLUE-TO-CN rule 50 description 'RDP Blue -> IT'
set firewall ipv4 name BLUE-TO-CN rule 50 action accept
set firewall ipv4 name BLUE-TO-CN rule 50 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-CN rule 50 destination address {SUBNET_IT}
set firewall ipv4 name BLUE-TO-CN rule 50 destination port 3389
set firewall ipv4 name BLUE-TO-CN rule 50 protocol tcp

# RDP → MANAGE subnet
set firewall ipv4 name BLUE-TO-CN rule 60 description 'RDP Blue -> MANAGE'
set firewall ipv4 name BLUE-TO-CN rule 60 action accept
set firewall ipv4 name BLUE-TO-CN rule 60 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-CN rule 60 destination address {SUBNET_MANAGE}
set firewall ipv4 name BLUE-TO-CN rule 60 destination port 3389
set firewall ipv4 name BLUE-TO-CN rule 60 protocol tcp

# DNS UDP 53 verso IT-DC-01
set firewall ipv4 name BLUE-TO-CN rule 70 description 'DNS UDP Blue -> IT-DC-01'
set firewall ipv4 name BLUE-TO-CN rule 70 action accept
set firewall ipv4 name BLUE-TO-CN rule 70 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-CN rule 70 destination address {IP_DC01}
set firewall ipv4 name BLUE-TO-CN rule 70 destination port 53
set firewall ipv4 name BLUE-TO-CN rule 70 protocol udp

# DNS TCP 53 verso IT-DC-01
set firewall ipv4 name BLUE-TO-CN rule 80 description 'DNS TCP Blue -> IT-DC-01'
set firewall ipv4 name BLUE-TO-CN rule 80 action accept
set firewall ipv4 name BLUE-TO-CN rule 80 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-CN rule 80 destination address {IP_DC01}
set firewall ipv4 name BLUE-TO-CN rule 80 destination port 53
set firewall ipv4 name BLUE-TO-CN rule 80 protocol tcp

# ── Ruleset: CN → BLUE ───────────────────────
set firewall ipv4 name CN-TO-BLUE description 'Core Network verso Blue Team'
set firewall ipv4 name CN-TO-BLUE default-action drop

set firewall ipv4 name CN-TO-BLUE rule 5 description 'Allow established/related'
set firewall ipv4 name CN-TO-BLUE rule 5 action accept
set firewall ipv4 name CN-TO-BLUE rule 5 state established enable
set firewall ipv4 name CN-TO-BLUE rule 5 state related enable

# ── Applica zone policy ───────────────────────
set zone-policy zone CN   from BLUE firewall name BLUE-TO-CN
set zone-policy zone BLUE from CN   firewall name CN-TO-BLUE
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
    print("  BLUE-CNFW-01 — VyOS Firewall Configuration")
    print("=" * 60)
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
