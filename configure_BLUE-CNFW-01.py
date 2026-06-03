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

# ── Porte Active Directory (client → DC) ─────────────────
# (porta, protocollo, descrizione)
AD_CLIENT_TO_DC = [
    (53,          "udp", "DNS UDP"),
    (53,          "tcp", "DNS TCP"),
    (88,          "tcp", "Kerberos TCP"),
    (88,          "udp", "Kerberos UDP"),
    (123,         "udp", "NTP"),
    (135,         "tcp", "RPC Endpoint Mapper"),
    (137,         "udp", "NetBIOS-NS"),
    (138,         "udp", "NetBIOS-DGM"),
    (139,         "tcp", "NetBIOS Session"),
    (389,         "tcp", "LDAP TCP"),
    (389,         "udp", "LDAP UDP"),
    (445,         "tcp", "SMB/CIFS"),
    (464,         "tcp", "Kerberos Password TCP"),
    (464,         "udp", "Kerberos Password UDP"),
    (636,         "tcp", "LDAPS"),
    (3268,        "tcp", "Global Catalog"),
    (3269,        "tcp", "Global Catalog SSL"),
    ("49152-65535","tcp","RPC Dynamic"),
]

# ── Porte DC → client (Group Policy push) ────────────────
AD_DC_TO_CLIENT = [
    (445,          "tcp", "SMB Group Policy"),
    (135,          "tcp", "RPC GP"),
    ("49152-65535", "tcp", "RPC Dynamic GP"),
]

def ad_rules_client_to_dc(ruleset, src, dst, start_rule=100):
    """Genera regole AD da client (src) verso IT-DC-01 (dst)"""
    lines = []
    for i, (port, proto, desc) in enumerate(AD_CLIENT_TO_DC):
        r = start_rule + (i * 10)
        lines += [
            f"set firewall ipv4 name {ruleset} rule {r} description 'AD: {desc}'",
            f"set firewall ipv4 name {ruleset} rule {r} action accept",
            f"set firewall ipv4 name {ruleset} rule {r} source address {src}",
            f"set firewall ipv4 name {ruleset} rule {r} destination address {dst}",
            f"set firewall ipv4 name {ruleset} rule {r} destination port {port}",
            f"set firewall ipv4 name {ruleset} rule {r} protocol {proto}",
        ]
    return "\n".join(lines)

def ad_rules_dc_to_client(ruleset, src, dst, start_rule=100):
    """Genera regole AD da IT-DC-01 (src) verso client (dst)"""
    lines = []
    for i, (port, proto, desc) in enumerate(AD_DC_TO_CLIENT):
        r = start_rule + (i * 10)
        lines += [
            f"set firewall ipv4 name {ruleset} rule {r} description 'AD GP: {desc}'",
            f"set firewall ipv4 name {ruleset} rule {r} action accept",
            f"set firewall ipv4 name {ruleset} rule {r} source address {src}",
            f"set firewall ipv4 name {ruleset} rule {r} destination address {dst}",
            f"set firewall ipv4 name {ruleset} rule {r} destination port {port}",
            f"set firewall ipv4 name {ruleset} rule {r} protocol {proto}",
        ]
    return "\n".join(lines)

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

set firewall ipv4 name BLUE-TO-CN rule 45 description 'SIEM Blue -> SOC (Kibana/ES)'
set firewall ipv4 name BLUE-TO-CN rule 45 action accept
set firewall ipv4 name BLUE-TO-CN rule 45 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-CN rule 45 destination address {SUBNET_SOC}
set firewall ipv4 name BLUE-TO-CN rule 45 destination port 5601,9200
set firewall ipv4 name BLUE-TO-CN rule 45 protocol tcp

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

# AD ports Blue -> IT-DC-01 (rule 100-280)
{ad_rules_client_to_dc("BLUE-TO-CN", SUBNET_BLUE, IP_DC01, start_rule=100)}

# ── NAMED RULESET: CN -> BLUE ────────────────────────────
set firewall ipv4 name CN-TO-BLUE description 'Core Network verso Blue Team'
set firewall ipv4 name CN-TO-BLUE default-action drop

# AD Group Policy: IT-DC-01 -> Blue Team (rule 100-130)
{ad_rules_dc_to_client("CN-TO-BLUE", IP_DC01, SUBNET_BLUE, start_rule=100)}

# ── FORWARD FILTER ────────────────────────────────────────
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
    print("  BLUE-CNFW-01 — VyOS 1.5 Firewall + AD Ports")
    print(f"  IF_CN={IF_CN}  IF_BLUE={IF_BLUE}")
    print(f"  AD ports: {len(AD_CLIENT_TO_DC)} regole client->DC, {len(AD_DC_TO_CLIENT)} DC->client")
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
