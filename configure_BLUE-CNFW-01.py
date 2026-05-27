#!/usr/bin/env python3
"""
=============================================================
  CYBER RANGE — VyOS 1.5 Firewall Configuration Script
  Device  : BLUE-CNFW-01
  Syntax  : VyOS 1.5 (circinus) — NO zone-policy
  Run on  : localmente sul VyOS (sudo python3 configure_BLUE-CNFW-01.py)
=============================================================
"""
import subprocess, tempfile, os, sys

IF_CN   = "eth1"   # 10.0.93.29 — transit verso CN
IF_BLUE = "eth2"   # 10.0.11.1  — Blue Team subnet

SUBNET_BLUE   = "10.0.11.0/24"
SUBNET_DMZ    = "10.0.13.0/24"
SUBNET_EMPLOY = "10.2.150.0/24"
SUBNET_SOC    = "10.0.17.0/24"
SUBNET_IT     = "10.0.14.0/24"
SUBNET_MANAGE = "10.1.21.0/24"
IP_VPN01      = "10.0.13.30"
IP_DC01       = "10.0.14.11"

COMMANDS = f"""
# ── NAMED RULESET: BLUE -> CN ────────────────────────────
set firewall ipv4 name BLUE-TO-CN description 'Blue Team verso Core Network'
set firewall ipv4 name BLUE-TO-CN default-action drop
set firewall ipv4 name BLUE-TO-CN default-log

set firewall ipv4 name BLUE-TO-CN rule 10 description 'RDP Blue -> DMZ'
set firewall ipv4 name BLUE-TO-CN rule 10 action accept
set firewall ipv4 name BLUE-TO-CN rule 10 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-CN rule 10 destination address {SUBNET_DMZ}
set firewall ipv4 name BLUE-TO-CN rule 10 destination port 3389
set firewall ipv4 name BLUE-TO-CN rule 10 protocol tcp

set firewall ipv4 name BLUE-TO-CN rule 20 description 'SSH Blue -> DMZ-VPN-01'
set firewall ipv4 name BLUE-TO-CN rule 20 action accept
set firewall ipv4 name BLUE-TO-CN rule 20 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-CN rule 20 destination address {IP_VPN01}
set firewall ipv4 name BLUE-TO-CN rule 20 destination port 22
set firewall ipv4 name BLUE-TO-CN rule 20 protocol tcp

set firewall ipv4 name BLUE-TO-CN rule 30 description 'RDP Blue -> EMPLOY'
set firewall ipv4 name BLUE-TO-CN rule 30 action accept
set firewall ipv4 name BLUE-TO-CN rule 30 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-CN rule 30 destination address {SUBNET_EMPLOY}
set firewall ipv4 name BLUE-TO-CN rule 30 destination port 3389
set firewall ipv4 name BLUE-TO-CN rule 30 protocol tcp

set firewall ipv4 name BLUE-TO-CN rule 40 description 'RDP Blue -> SOC'
set firewall ipv4 name BLUE-TO-CN rule 40 action accept
set firewall ipv4 name BLUE-TO-CN rule 40 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-CN rule 40 destination address {SUBNET_SOC}
set firewall ipv4 name BLUE-TO-CN rule 40 destination port 3389
set firewall ipv4 name BLUE-TO-CN rule 40 protocol tcp

set firewall ipv4 name BLUE-TO-CN rule 50 description 'RDP Blue -> IT'
set firewall ipv4 name BLUE-TO-CN rule 50 action accept
set firewall ipv4 name BLUE-TO-CN rule 50 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-CN rule 50 destination address {SUBNET_IT}
set firewall ipv4 name BLUE-TO-CN rule 50 destination port 3389
set firewall ipv4 name BLUE-TO-CN rule 50 protocol tcp

set firewall ipv4 name BLUE-TO-CN rule 60 description 'RDP Blue -> MANAGE'
set firewall ipv4 name BLUE-TO-CN rule 60 action accept
set firewall ipv4 name BLUE-TO-CN rule 60 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-CN rule 60 destination address {SUBNET_MANAGE}
set firewall ipv4 name BLUE-TO-CN rule 60 destination port 3389
set firewall ipv4 name BLUE-TO-CN rule 60 protocol tcp

set firewall ipv4 name BLUE-TO-CN rule 70 description 'DNS UDP Blue -> IT-DC-01'
set firewall ipv4 name BLUE-TO-CN rule 70 action accept
set firewall ipv4 name BLUE-TO-CN rule 70 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-CN rule 70 destination address {IP_DC01}
set firewall ipv4 name BLUE-TO-CN rule 70 destination port 53
set firewall ipv4 name BLUE-TO-CN rule 70 protocol udp

set firewall ipv4 name BLUE-TO-CN rule 80 description 'DNS TCP Blue -> IT-DC-01'
set firewall ipv4 name BLUE-TO-CN rule 80 action accept
set firewall ipv4 name BLUE-TO-CN rule 80 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-CN rule 80 destination address {IP_DC01}
set firewall ipv4 name BLUE-TO-CN rule 80 destination port 53
set firewall ipv4 name BLUE-TO-CN rule 80 protocol tcp

# ── NAMED RULESET: CN -> BLUE ────────────────────────────
set firewall ipv4 name CN-TO-BLUE description 'Core Network verso Blue Team'
set firewall ipv4 name CN-TO-BLUE default-action drop

# ── FORWARD FILTER (sostituisce zone-policy) ──────────────
set firewall ipv4 forward filter default-action drop

set firewall ipv4 forward filter rule 1 description 'Allow established/related globally'
set firewall ipv4 forward filter rule 1 action accept
set firewall ipv4 forward filter rule 1 state established
set firewall ipv4 forward filter rule 1 state related

set firewall ipv4 forward filter rule 100 description 'BLUE -> CN jump'
set firewall ipv4 forward filter rule 100 action jump
set firewall ipv4 forward filter rule 100 jump-target BLUE-TO-CN
set firewall ipv4 forward filter rule 100 inbound-interface name {IF_BLUE}
set firewall ipv4 forward filter rule 100 outbound-interface name {IF_CN}

set firewall ipv4 forward filter rule 110 description 'CN -> BLUE jump'
set firewall ipv4 forward filter rule 110 action jump
set firewall ipv4 forward filter rule 110 jump-target CN-TO-BLUE
set firewall ipv4 forward filter rule 110 inbound-interface name {IF_CN}
set firewall ipv4 forward filter rule 110 outbound-interface name {IF_BLUE}
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
    print("  BLUE-CNFW-01 — VyOS 1.5 Firewall")
    print(f"  IF_CN={IF_CN} (10.0.93.29)  IF_BLUE={IF_BLUE} (10.0.11.1)")
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
