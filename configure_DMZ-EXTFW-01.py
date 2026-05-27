#!/usr/bin/env python3
"""
=============================================================
  CYBER RANGE — VyOS 1.5 Firewall + NAT Configuration Script
  Device  : DMZ-EXTFW-01
  Role    : Firewall esterno + NAT — Internet (Red) <-> DMZ
  Run on  : localmente sul VyOS (sudo python3 configure_DMZ-EXTFW-01.py)

  NAT flow:
    IN  : 58.16.10.1:{1194/udp, 443/tcp}  --DNAT-->  10.0.13.30
    OUT : 10.0.13.0/24  --MASQUERADE-->  58.16.10.1
=============================================================
"""

import subprocess
import tempfile
import os
import sys

# ─────────────────────────────────────────────
#  CONFIGURAZIONE — modifica qui se necessario
# ─────────────────────────────────────────────

IF_WAN = "eth2"   # interfaccia verso Internet / Switch red  (58.16.10.1)
IF_DMZ = "eth1"   # interfaccia verso Switch dmz             (10.0.13.3)

IP_PUBLIC  = "58.16.10.1"    # IP pubblico su IF_WAN (esposto verso RED)
IP_VPN01   = "10.0.13.30"    # IP privato DMZ-VPN-01 (destinazione DNAT)
SUBNET_DMZ = "10.0.13.0/24"  # Subnet DMZ (sorgente masquerade)

# ─────────────────────────────────────────────
#  COMANDI VYOS
# ─────────────────────────────────────────────

COMMANDS = f"""
# ══════════════════════════════════════════════
#  ZONE POLICY
# ══════════════════════════════════════════════
set zone-policy zone WAN description 'Internet / Red Team'
set zone-policy zone WAN interface {IF_WAN}
set zone-policy zone DMZ description 'DMZ Network'
set zone-policy zone DMZ interface {IF_DMZ}

# ══════════════════════════════════════════════
#  NAT — DNAT (Destination NAT / Port Forwarding)
#  Il traffico arriva su {IP_PUBLIC} e viene
#  rediretto a {IP_VPN01} prima delle firewall rules.
#  VyOS valuta DNAT in prerouting (prima del firewall),
#  quindi le firewall rules vedono già l'IP privato.
# ══════════════════════════════════════════════

# DNAT: OpenVPN UDP 1194  ->  DMZ-VPN-01
set nat destination rule 10 description 'DNAT OpenVPN UDP 1194 -> DMZ-VPN-01'
set nat destination rule 10 inbound-interface name {IF_WAN}
set nat destination rule 10 destination address {IP_PUBLIC}
set nat destination rule 10 destination port 1194
set nat destination rule 10 protocol udp
set nat destination rule 10 translation address {IP_VPN01}
set nat destination rule 10 translation port 1194

# DNAT: HTTPS TCP 443  ->  DMZ-VPN-01
set nat destination rule 20 description 'DNAT HTTPS TCP 443 -> DMZ-VPN-01'
set nat destination rule 20 inbound-interface name {IF_WAN}
set nat destination rule 20 destination address {IP_PUBLIC}
set nat destination rule 20 destination port 443
set nat destination rule 20 protocol tcp
set nat destination rule 20 translation address {IP_VPN01}
set nat destination rule 20 translation port 443

# DNAT: SSH TCP 22  ->  DMZ-VPN-01
set nat destination rule 30 description 'DNAT SSH TCP 22 -> DMZ-VPN-01'
set nat destination rule 30 inbound-interface name {IF_WAN}
set nat destination rule 30 destination address {IP_PUBLIC}
set nat destination rule 30 destination port 22
set nat destination rule 30 protocol tcp
set nat destination rule 30 translation address {IP_VPN01}
set nat destination rule 30 translation port 22

# ══════════════════════════════════════════════
#  NAT — SNAT / MASQUERADE (Source NAT)
#  Il traffico uscente dalla DMZ verso WAN
#  viene mascherato con l'IP pubblico {IP_PUBLIC}.
#  Necessario per il corretto routing delle risposte.
# ══════════════════════════════════════════════

set nat source rule 10 description 'Masquerade DMZ -> WAN'
set nat source rule 10 outbound-interface name {IF_WAN}
set nat source rule 10 source address {SUBNET_DMZ}
set nat source rule 10 translation address masquerade

# ══════════════════════════════════════════════
#  FIREWALL — Ruleset WAN → DMZ
#  Le regole vedono l'IP post-DNAT (10.0.13.30)
#  perché il DNAT avviene in prerouting.
# ══════════════════════════════════════════════

set firewall ipv4 name WAN-TO-DMZ description 'Traffico Internet verso DMZ'
set firewall ipv4 name WAN-TO-DMZ default-action drop
set firewall ipv4 name WAN-TO-DMZ enable-default-log

# established/related: risposte a connessioni già aperte
set firewall ipv4 name WAN-TO-DMZ rule 5 description 'Allow established/related'
set firewall ipv4 name WAN-TO-DMZ rule 5 action accept
set firewall ipv4 name WAN-TO-DMZ rule 5 state established enable
set firewall ipv4 name WAN-TO-DMZ rule 5 state related enable

# OpenVPN UDP 1194 verso DMZ-VPN-01 (post-DNAT)
set firewall ipv4 name WAN-TO-DMZ rule 10 description 'Allow OpenVPN UDP 1194 to DMZ-VPN-01'
set firewall ipv4 name WAN-TO-DMZ rule 10 action accept
set firewall ipv4 name WAN-TO-DMZ rule 10 destination address {IP_VPN01}
set firewall ipv4 name WAN-TO-DMZ rule 10 destination port 1194
set firewall ipv4 name WAN-TO-DMZ rule 10 protocol udp

# HTTPS TCP 443 verso DMZ-VPN-01 (post-DNAT)
set firewall ipv4 name WAN-TO-DMZ rule 20 description 'Allow HTTPS TCP 443 to DMZ-VPN-01'
set firewall ipv4 name WAN-TO-DMZ rule 20 action accept
set firewall ipv4 name WAN-TO-DMZ rule 20 destination address {IP_VPN01}
set firewall ipv4 name WAN-TO-DMZ rule 20 destination port 443
set firewall ipv4 name WAN-TO-DMZ rule 20 protocol tcp

# SSH TCP 22 verso DMZ-VPN-01 (post-DNAT)
set firewall ipv4 name WAN-TO-DMZ rule 30 description 'Allow SSH TCP 22 to DMZ-VPN-01'
set firewall ipv4 name WAN-TO-DMZ rule 30 action accept
set firewall ipv4 name WAN-TO-DMZ rule 30 destination address {IP_VPN01}
set firewall ipv4 name WAN-TO-DMZ rule 30 destination port 22
set firewall ipv4 name WAN-TO-DMZ rule 30 protocol tcp

# ══════════════════════════════════════════════
#  FIREWALL — Ruleset DMZ → WAN
# ══════════════════════════════════════════════

set firewall ipv4 name DMZ-TO-WAN description 'Traffico DMZ verso Internet'
set firewall ipv4 name DMZ-TO-WAN default-action drop

# established/related
set firewall ipv4 name DMZ-TO-WAN rule 5 description 'Allow established/related'
set firewall ipv4 name DMZ-TO-WAN rule 5 action accept
set firewall ipv4 name DMZ-TO-WAN rule 5 state established enable
set firewall ipv4 name DMZ-TO-WAN rule 5 state related enable

# DNS UDP 53 uscente
set firewall ipv4 name DMZ-TO-WAN rule 10 description 'Allow DNS UDP outbound'
set firewall ipv4 name DMZ-TO-WAN rule 10 action accept
set firewall ipv4 name DMZ-TO-WAN rule 10 destination port 53
set firewall ipv4 name DMZ-TO-WAN rule 10 protocol udp

# DNS TCP 53 uscente
set firewall ipv4 name DMZ-TO-WAN rule 20 description 'Allow DNS TCP outbound'
set firewall ipv4 name DMZ-TO-WAN rule 20 action accept
set firewall ipv4 name DMZ-TO-WAN rule 20 destination port 53
set firewall ipv4 name DMZ-TO-WAN rule 20 protocol tcp

# ══════════════════════════════════════════════
#  APPLICA ZONE POLICY
# ══════════════════════════════════════════════
set zone-policy zone DMZ from WAN firewall name WAN-TO-DMZ
set zone-policy zone WAN from DMZ firewall name DMZ-TO-WAN
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
    print("  DMZ-EXTFW-01 — VyOS Firewall + NAT Configuration")
    print("=" * 60)
    print(f"\n  IP pubblico (WAN) : {IP_PUBLIC}  [{IF_WAN}]")
    print(f"  IP privato VPN-01 : {IP_VPN01}  [{IF_DMZ}]")
    print(f"  DNAT ports        : UDP 1194 (OpenVPN), TCP 443 (HTTPS), TCP 22 (SSH)")
    print(f"  SNAT              : masquerade su {SUBNET_DMZ} -> {IP_PUBLIC}")

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
