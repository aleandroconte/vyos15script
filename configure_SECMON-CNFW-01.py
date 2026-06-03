#!/usr/bin/env python3
"""
=============================================================
  CYBER RANGE — VyOS 1.5 Firewall Configuration Script
  Device  : SECMON-CNFW-01
  Syntax  : VyOS 1.5 (circinus) — NO zone-policy
  Run on  : localmente sul VyOS (sudo python3 configure_SECMON-CNFW-01.py)
=============================================================
"""
import subprocess, tempfile, os, sys

IF_CN  = "eth1"   # 10.0.94.5  — transit verso CN
IF_SOC = "eth2"   # 10.0.17.23 — SOC zone

SUBNET_SOC  = "10.0.17.0/24"
SUBNET_BLUE = "10.0.11.0/24"

TARGETS = [
    ("10.0.13.0/24",  "DMZ"),
    ("10.0.11.0/24",  "Blue Team"),
    ("10.2.150.0/24", "EMPLOY/Mission"),
    ("10.0.14.0/24",  "IT"),
    ("10.1.21.0/24",  "MANAGE"),
]

# Build SOC-TO-CN rules dynamically
soc_rules = ""
for i, (subnet, label) in enumerate(TARGETS, start=1):
    rule = i * 10
    soc_rules += f"""
set firewall ipv4 name SOC-TO-CN rule {rule} description 'SecMon -> {label}'
set firewall ipv4 name SOC-TO-CN rule {rule} action accept
set firewall ipv4 name SOC-TO-CN rule {rule} source address {SUBNET_SOC}
set firewall ipv4 name SOC-TO-CN rule {rule} destination address {subnet}
"""

COMMANDS = f"""
# ── NAMED RULESET: CN -> SOC ─────────────────────────────
set firewall ipv4 name CN-TO-SOC description 'Core Network verso SOC zone'
set firewall ipv4 name CN-TO-SOC default-action drop
set firewall ipv4 name CN-TO-SOC default-log

set firewall ipv4 name CN-TO-SOC rule 10 description 'RDP Blue Team -> SOC subnet'
set firewall ipv4 name CN-TO-SOC rule 10 action accept
set firewall ipv4 name CN-TO-SOC rule 10 source address {SUBNET_BLUE}
set firewall ipv4 name CN-TO-SOC rule 10 destination address {SUBNET_SOC}
set firewall ipv4 name CN-TO-SOC rule 10 destination port 3389
set firewall ipv4 name CN-TO-SOC rule 10 protocol tcp

set firewall ipv4 name CN-TO-SOC rule 20 description 'LOG FOR SIEM CN -> SOC'
set firewall ipv4 name CN-TO-SOC rule 20 action accept
set firewall ipv4 name CN-TO-SOC rule 20 destination address {SUBNET_SOC}
set firewall ipv4 name CN-TO-SOC rule 20 destination port 5601,9200
set firewall ipv4 name CN-TO-SOC rule 20 protocol tcp

# ── NAMED RULESET: SOC -> CN ─────────────────────────────
set firewall ipv4 name SOC-TO-CN description 'SOC zone verso tutte le subnet (monitoraggio)'
set firewall ipv4 name SOC-TO-CN default-action drop
{soc_rules}
# ── FORWARD FILTER (sostituisce zone-policy) ──────────────
set firewall ipv4 forward filter default-action drop

set firewall ipv4 forward filter rule 1 description 'Allow established/related globally'
set firewall ipv4 forward filter rule 1 action accept
set firewall ipv4 forward filter rule 1 state established
set firewall ipv4 forward filter rule 1 state related

set firewall ipv4 forward filter rule 100 description 'CN -> SOC jump'
set firewall ipv4 forward filter rule 100 action jump
set firewall ipv4 forward filter rule 100 jump-target CN-TO-SOC
set firewall ipv4 forward filter rule 100 inbound-interface name {IF_CN}
set firewall ipv4 forward filter rule 100 outbound-interface name {IF_SOC}

set firewall ipv4 forward filter rule 110 description 'SOC -> CN jump'
set firewall ipv4 forward filter rule 110 action jump
set firewall ipv4 forward filter rule 110 jump-target SOC-TO-CN
set firewall ipv4 forward filter rule 110 inbound-interface name {IF_SOC}
set firewall ipv4 forward filter rule 110 outbound-interface name {IF_CN}
"""

def build_script(commands):
    lines = ["#!/bin/vbash","source /opt/vyatta/etc/functions/script-template","configure"]
    for line in commands.strip().splitlines():
        line=line.strip()
        if line and not line.startswith("#"): lines.append(line)
    lines+=["commit","save","exit"]
    return "\n".join(lines)+"\n"

def run():
    print("="*60)
    print("  SECMON-CNFW-01 — VyOS 1.5 Firewall")
    print(f"  IF_CN={IF_CN} (10.0.94.5)  IF_SOC={IF_SOC} (10.0.17.23)")
    print(f"  SecMon monitora {len(TARGETS)} subnet (no RED)")
    print("="*60)
    script=build_script(COMMANDS)
    print("\n[INFO] Comandi:\n")
    for l in script.splitlines(): print(f"  {l}")
    print("\n"+"─"*60)
    if input("Procedere? [s/N]: ").strip().lower() not in ("s","si","y","yes"):
        print("[ANNULLATO]"); sys.exit(0)
    with tempfile.NamedTemporaryFile(mode="w",suffix=".sh",delete=False,prefix="vyos_") as f:
        f.write(script); tmp=f.name
    os.chmod(tmp,0o755)
    try:
        r=subprocess.run(["/bin/vbash",tmp],capture_output=True,text=True)
        if r.stdout: print("[OUT]\n"+r.stdout)
        if r.stderr: print("[ERR]\n"+r.stderr)
        print("\n[OK]" if r.returncode==0 else f"\n[ERRORE] rc={r.returncode}")
        if r.returncode!=0: sys.exit(r.returncode)
    finally: os.unlink(tmp)

if __name__=="__main__":
    if os.geteuid()!=0: print("[WARN] Esegui come root")
    run()
