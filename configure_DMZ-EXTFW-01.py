#!/usr/bin/env python3
"""
=============================================================
  CYBER RANGE — VyOS 1.5 Firewall + NAT Configuration Script
  Device  : DMZ-EXTFW-01
  Syntax  : VyOS 1.5 (circinus) — NO zone-policy
  Run on  : localmente sul VyOS (sudo python3 configure_DMZ-EXTFW-01.py)
=============================================================
"""
import subprocess, tempfile, os, sys

IF_WAN = "eth2"       # 58.16.10.1 — verso RED / Internet
IF_DMZ = "eth1"       # 10.0.13.3  — verso DMZ

IP_PUBLIC  = "58.16.10.1"
IP_VPN01   = "10.0.13.30"
SUBNET_DMZ = "10.0.13.0/24"

COMMANDS = f"""
# ── NAT DNAT ─────────────────────────────────────────────
set nat destination rule 10 description 'DNAT OpenVPN UDP 1194 -> VPN-01'
set nat destination rule 10 inbound-interface name {IF_WAN}
set nat destination rule 10 destination address {IP_PUBLIC}
set nat destination rule 10 destination port 1194
set nat destination rule 10 protocol udp
set nat destination rule 10 translation address {IP_VPN01}
set nat destination rule 10 translation port 1194

set nat destination rule 20 description 'DNAT HTTPS TCP 443 -> VPN-01'
set nat destination rule 20 inbound-interface name {IF_WAN}
set nat destination rule 20 destination address {IP_PUBLIC}
set nat destination rule 20 destination port 443
set nat destination rule 20 protocol tcp
set nat destination rule 20 translation address {IP_VPN01}
set nat destination rule 20 translation port 443

set nat destination rule 30 description 'DNAT SSH TCP 22 -> VPN-01'
set nat destination rule 30 inbound-interface name {IF_WAN}
set nat destination rule 30 destination address {IP_PUBLIC}
set nat destination rule 30 destination port 22
set nat destination rule 30 protocol tcp
set nat destination rule 30 translation address {IP_VPN01}
set nat destination rule 30 translation port 22

# ── NAT SNAT ─────────────────────────────────────────────
set nat source rule 10 description 'Masquerade DMZ -> WAN'
set nat source rule 10 outbound-interface name {IF_WAN}
set nat source rule 10 source address {SUBNET_DMZ}
set nat source rule 10 translation address masquerade

# ── NAMED RULESETS ────────────────────────────────────────
set firewall ipv4 name WAN-TO-DMZ description 'Internet verso DMZ'
set firewall ipv4 name WAN-TO-DMZ default-action drop
set firewall ipv4 name WAN-TO-DMZ default-log

set firewall ipv4 name WAN-TO-DMZ rule 10 description 'OpenVPN UDP 1194 -> VPN-01'
set firewall ipv4 name WAN-TO-DMZ rule 10 action accept
set firewall ipv4 name WAN-TO-DMZ rule 10 destination address {IP_VPN01}
set firewall ipv4 name WAN-TO-DMZ rule 10 destination port 1194
set firewall ipv4 name WAN-TO-DMZ rule 10 protocol udp

set firewall ipv4 name WAN-TO-DMZ rule 20 description 'HTTPS TCP 443 -> VPN-01'
set firewall ipv4 name WAN-TO-DMZ rule 20 action accept
set firewall ipv4 name WAN-TO-DMZ rule 20 destination address {IP_VPN01}
set firewall ipv4 name WAN-TO-DMZ rule 20 destination port 443
set firewall ipv4 name WAN-TO-DMZ rule 20 protocol tcp

set firewall ipv4 name WAN-TO-DMZ rule 30 description 'SSH TCP 22 -> VPN-01'
set firewall ipv4 name WAN-TO-DMZ rule 30 action accept
set firewall ipv4 name WAN-TO-DMZ rule 30 destination address {IP_VPN01}
set firewall ipv4 name WAN-TO-DMZ rule 30 destination port 22
set firewall ipv4 name WAN-TO-DMZ rule 30 protocol tcp

set firewall ipv4 name DMZ-TO-WAN description 'DMZ verso Internet'
set firewall ipv4 name DMZ-TO-WAN default-action drop

set firewall ipv4 name DMZ-TO-WAN rule 10 description 'DNS UDP 53 uscente'
set firewall ipv4 name DMZ-TO-WAN rule 10 action accept
set firewall ipv4 name DMZ-TO-WAN rule 10 destination port 53
set firewall ipv4 name DMZ-TO-WAN rule 10 protocol udp

set firewall ipv4 name DMZ-TO-WAN rule 20 description 'DNS TCP 53 uscente'
set firewall ipv4 name DMZ-TO-WAN rule 20 action accept
set firewall ipv4 name DMZ-TO-WAN rule 20 destination port 53
set firewall ipv4 name DMZ-TO-WAN rule 20 protocol tcp

set firewall ipv4 name DMZ-TO-WAN rule 30 description 'SERVICE TRAFFIC DMZ -> WAN 8500-9500'
set firewall ipv4 name DMZ-TO-WAN rule 30 action accept
set firewall ipv4 name DMZ-TO-WAN rule 30 source address 10.0.13.0/24
set firewall ipv4 name DMZ-TO-WAN rule 30 destination port 8500-9500
set firewall ipv4 name DMZ-TO-WAN rule 30 protocol tcp_udp

# ── FORWARD FILTER (sostituisce zone-policy) ──────────────
set firewall ipv4 forward filter default-action drop

set firewall ipv4 forward filter rule 1 description 'Allow established/related globally'
set firewall ipv4 forward filter rule 1 action accept
set firewall ipv4 forward filter rule 1 state established
set firewall ipv4 forward filter rule 1 state related

set firewall ipv4 forward filter rule 100 description 'WAN -> DMZ jump'
set firewall ipv4 forward filter rule 100 action jump
set firewall ipv4 forward filter rule 100 jump-target WAN-TO-DMZ
set firewall ipv4 forward filter rule 100 inbound-interface name {IF_WAN}
set firewall ipv4 forward filter rule 100 outbound-interface name {IF_DMZ}

set firewall ipv4 forward filter rule 110 description 'DMZ -> WAN jump'
set firewall ipv4 forward filter rule 110 action jump
set firewall ipv4 forward filter rule 110 jump-target DMZ-TO-WAN
set firewall ipv4 forward filter rule 110 inbound-interface name {IF_DMZ}
set firewall ipv4 forward filter rule 110 outbound-interface name {IF_WAN}
"""

def build_script(commands):
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
    print("  DMZ-EXTFW-01 — VyOS 1.5 Firewall + NAT")
    print(f"  IF_WAN={IF_WAN} ({IP_PUBLIC})  IF_DMZ={IF_DMZ}")
    print(f"  DNAT -> {IP_VPN01}  (1194/udp, 443/tcp, 22/tcp)")
    print("=" * 60)
    script = build_script(COMMANDS)
    print("\n[INFO] Comandi:\n")
    for l in script.splitlines(): print(f"  {l}")
    print("\n" + "─"*60)
    if input("Procedere? [s/N]: ").strip().lower() not in ("s","si","y","yes"):
        print("[ANNULLATO]"); sys.exit(0)
    with tempfile.NamedTemporaryFile(mode="w",suffix=".sh",delete=False,prefix="vyos_") as f:
        f.write(script); tmp=f.name
    os.chmod(tmp,0o755)
    try:
        r = subprocess.run(["/bin/vbash",tmp],capture_output=True,text=True)
        if r.stdout: print("[OUT]\n"+r.stdout)
        if r.stderr: print("[ERR]\n"+r.stderr)
        print("\n[OK]" if r.returncode==0 else f"\n[ERRORE] rc={r.returncode}")
        if r.returncode!=0: sys.exit(r.returncode)
    finally: os.unlink(tmp)

if __name__=="__main__":
    if os.geteuid()!=0: print("[WARN] Esegui come root")
    run()
