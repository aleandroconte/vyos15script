#!/usr/bin/env python3
"""
=============================================================
  CYBER RANGE — VyOS 1.5 Firewall Configuration Script
  Device  : cn-router
  Syntax  : VyOS 1.5 (circinus) — NO zone-policy
  Run on  : localmente sul VyOS (sudo python3 configure_CN-ROUTER.py)

  Interfacce:
    eth0 = management (DHCP, esclusa)
    eth1 = BLUE_TR   10.0.93.1  (transit Blue Team)
    eth2 = DMZ       10.0.13.1
    eth3 = IT        10.0.14.1
    eth4 = MANAGE    10.1.21.1
    eth5 = EMPLOY    10.2.150.1
    eth6 = SOC_TR    10.0.94.1  (transit SecMon)
=============================================================
"""
import subprocess, tempfile, os, sys

IF_BLUE_TR = "eth1"
IF_DMZ     = "eth2"
IF_IT      = "eth3"
IF_MANAGE  = "eth4"
IF_EMPLOY  = "eth5"
IF_SOC_TR  = "eth6"

SUBNET_BLUE   = "10.0.11.0/24"
SUBNET_DMZ    = "10.0.13.0/24"
SUBNET_IT     = "10.0.14.0/24"
SUBNET_MANAGE = "10.1.21.0/24"
SUBNET_EMPLOY = "10.2.150.0/24"
SUBNET_SOC    = "10.0.17.0/24"

IP_BAST01  = "10.0.13.20"
IP_VPN01   = "10.0.13.30"
IP_DC01    = "10.0.14.11"
IP_EMP_WS1 = "10.2.150.213"
IP_EMP_WS2 = "10.2.150.214"
IP_EMP_WS3 = "10.2.150.216"

COMMANDS = f"""
# ── ADDRESS GROUP ─────────────────────────────────────────
set firewall group address-group EMP-WORKSTATIONS description 'EMP Workstations'
set firewall group address-group EMP-WORKSTATIONS address {IP_EMP_WS1}
set firewall group address-group EMP-WORKSTATIONS address {IP_EMP_WS2}
set firewall group address-group EMP-WORKSTATIONS address {IP_EMP_WS3}

# ── DMZ <-> EMPLOY ────────────────────────────────────────
set firewall ipv4 name DMZ-TO-EMPLOY description 'DMZ verso EMPLOY (ex CN-MISFW-01)'
set firewall ipv4 name DMZ-TO-EMPLOY default-action drop
set firewall ipv4 name DMZ-TO-EMPLOY default-log

set firewall ipv4 name DMZ-TO-EMPLOY rule 10 description 'RDP BAST-01 -> EMPLOY'
set firewall ipv4 name DMZ-TO-EMPLOY rule 10 action accept
set firewall ipv4 name DMZ-TO-EMPLOY rule 10 source address {IP_BAST01}
set firewall ipv4 name DMZ-TO-EMPLOY rule 10 destination address {SUBNET_EMPLOY}
set firewall ipv4 name DMZ-TO-EMPLOY rule 10 destination port 3389
set firewall ipv4 name DMZ-TO-EMPLOY rule 10 protocol tcp

set firewall ipv4 name DMZ-TO-EMPLOY rule 20 description 'WinRM HTTP BAST-01 -> EMP-WS'
set firewall ipv4 name DMZ-TO-EMPLOY rule 20 action accept
set firewall ipv4 name DMZ-TO-EMPLOY rule 20 source address {IP_BAST01}
set firewall ipv4 name DMZ-TO-EMPLOY rule 20 destination group address-group EMP-WORKSTATIONS
set firewall ipv4 name DMZ-TO-EMPLOY rule 20 destination port 5985
set firewall ipv4 name DMZ-TO-EMPLOY rule 20 protocol tcp

set firewall ipv4 name DMZ-TO-EMPLOY rule 30 description 'WinRM HTTPS BAST-01 -> EMP-WS'
set firewall ipv4 name DMZ-TO-EMPLOY rule 30 action accept
set firewall ipv4 name DMZ-TO-EMPLOY rule 30 source address {IP_BAST01}
set firewall ipv4 name DMZ-TO-EMPLOY rule 30 destination group address-group EMP-WORKSTATIONS
set firewall ipv4 name DMZ-TO-EMPLOY rule 30 destination port 5986
set firewall ipv4 name DMZ-TO-EMPLOY rule 30 protocol tcp

set firewall ipv4 name EMPLOY-TO-DMZ description 'EMPLOY verso DMZ'
set firewall ipv4 name EMPLOY-TO-DMZ default-action drop

# ── DMZ <-> IT ────────────────────────────────────────────
set firewall ipv4 name DMZ-TO-IT description 'DMZ verso IT — solo DNS verso DC'
set firewall ipv4 name DMZ-TO-IT default-action drop
set firewall ipv4 name DMZ-TO-IT default-log

set firewall ipv4 name DMZ-TO-IT rule 10 description 'DNS UDP DMZ -> IT-DC-01'
set firewall ipv4 name DMZ-TO-IT rule 10 action accept
set firewall ipv4 name DMZ-TO-IT rule 10 destination address {IP_DC01}
set firewall ipv4 name DMZ-TO-IT rule 10 destination port 53
set firewall ipv4 name DMZ-TO-IT rule 10 protocol udp

set firewall ipv4 name DMZ-TO-IT rule 20 description 'DNS TCP DMZ -> IT-DC-01'
set firewall ipv4 name DMZ-TO-IT rule 20 action accept
set firewall ipv4 name DMZ-TO-IT rule 20 destination address {IP_DC01}
set firewall ipv4 name DMZ-TO-IT rule 20 destination port 53
set firewall ipv4 name DMZ-TO-IT rule 20 protocol tcp

set firewall ipv4 name IT-TO-DMZ description 'IT verso DMZ'
set firewall ipv4 name IT-TO-DMZ default-action drop

# ── DMZ <-> MANAGE ────────────────────────────────────────
set firewall ipv4 name DMZ-TO-MANAGE description 'DMZ verso MANAGE — DROP tutto'
set firewall ipv4 name DMZ-TO-MANAGE default-action drop
set firewall ipv4 name DMZ-TO-MANAGE default-log

set firewall ipv4 name MANAGE-TO-DMZ description 'MANAGE verso DMZ'
set firewall ipv4 name MANAGE-TO-DMZ default-action drop

# ── BLUE_TR <-> DMZ ───────────────────────────────────────
set firewall ipv4 name BLUE-TO-DMZ description 'Blue Team verso DMZ'
set firewall ipv4 name BLUE-TO-DMZ default-action drop

set firewall ipv4 name BLUE-TO-DMZ rule 10 description 'RDP Blue -> DMZ'
set firewall ipv4 name BLUE-TO-DMZ rule 10 action accept
set firewall ipv4 name BLUE-TO-DMZ rule 10 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-DMZ rule 10 destination address {SUBNET_DMZ}
set firewall ipv4 name BLUE-TO-DMZ rule 10 destination port 3389
set firewall ipv4 name BLUE-TO-DMZ rule 10 protocol tcp

set firewall ipv4 name BLUE-TO-DMZ rule 20 description 'SSH Blue -> DMZ-VPN-01'
set firewall ipv4 name BLUE-TO-DMZ rule 20 action accept
set firewall ipv4 name BLUE-TO-DMZ rule 20 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-DMZ rule 20 destination address {IP_VPN01}
set firewall ipv4 name BLUE-TO-DMZ rule 20 destination port 22
set firewall ipv4 name BLUE-TO-DMZ rule 20 protocol tcp

set firewall ipv4 name DMZ-TO-BLUE description 'DMZ verso Blue Team transit'
set firewall ipv4 name DMZ-TO-BLUE default-action drop

# ── BLUE_TR <-> EMPLOY ────────────────────────────────────
set firewall ipv4 name BLUE-TO-EMPLOY description 'Blue Team verso EMPLOY'
set firewall ipv4 name BLUE-TO-EMPLOY default-action drop

set firewall ipv4 name BLUE-TO-EMPLOY rule 10 description 'RDP Blue -> EMPLOY'
set firewall ipv4 name BLUE-TO-EMPLOY rule 10 action accept
set firewall ipv4 name BLUE-TO-EMPLOY rule 10 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-EMPLOY rule 10 destination address {SUBNET_EMPLOY}
set firewall ipv4 name BLUE-TO-EMPLOY rule 10 destination port 3389
set firewall ipv4 name BLUE-TO-EMPLOY rule 10 protocol tcp

set firewall ipv4 name EMPLOY-TO-BLUE description 'EMPLOY verso Blue Team transit'
set firewall ipv4 name EMPLOY-TO-BLUE default-action drop

# ── BLUE_TR <-> IT ────────────────────────────────────────
set firewall ipv4 name BLUE-TO-IT description 'Blue Team verso IT'
set firewall ipv4 name BLUE-TO-IT default-action drop

set firewall ipv4 name BLUE-TO-IT rule 10 description 'RDP Blue -> IT'
set firewall ipv4 name BLUE-TO-IT rule 10 action accept
set firewall ipv4 name BLUE-TO-IT rule 10 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-IT rule 10 destination address {SUBNET_IT}
set firewall ipv4 name BLUE-TO-IT rule 10 destination port 3389
set firewall ipv4 name BLUE-TO-IT rule 10 protocol tcp

set firewall ipv4 name BLUE-TO-IT rule 20 description 'DNS UDP Blue -> IT-DC-01'
set firewall ipv4 name BLUE-TO-IT rule 20 action accept
set firewall ipv4 name BLUE-TO-IT rule 20 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-IT rule 20 destination address {IP_DC01}
set firewall ipv4 name BLUE-TO-IT rule 20 destination port 53
set firewall ipv4 name BLUE-TO-IT rule 20 protocol udp

set firewall ipv4 name BLUE-TO-IT rule 30 description 'DNS TCP Blue -> IT-DC-01'
set firewall ipv4 name BLUE-TO-IT rule 30 action accept
set firewall ipv4 name BLUE-TO-IT rule 30 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-IT rule 30 destination address {IP_DC01}
set firewall ipv4 name BLUE-TO-IT rule 30 destination port 53
set firewall ipv4 name BLUE-TO-IT rule 30 protocol tcp

set firewall ipv4 name IT-TO-BLUE description 'IT verso Blue Team transit'
set firewall ipv4 name IT-TO-BLUE default-action drop

# ── BLUE_TR <-> MANAGE ────────────────────────────────────
set firewall ipv4 name BLUE-TO-MANAGE description 'Blue Team verso MANAGE'
set firewall ipv4 name BLUE-TO-MANAGE default-action drop

set firewall ipv4 name BLUE-TO-MANAGE rule 10 description 'RDP Blue -> MANAGE'
set firewall ipv4 name BLUE-TO-MANAGE rule 10 action accept
set firewall ipv4 name BLUE-TO-MANAGE rule 10 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-MANAGE rule 10 destination address {SUBNET_MANAGE}
set firewall ipv4 name BLUE-TO-MANAGE rule 10 destination port 3389
set firewall ipv4 name BLUE-TO-MANAGE rule 10 protocol tcp

set firewall ipv4 name MANAGE-TO-BLUE description 'MANAGE verso Blue Team transit'
set firewall ipv4 name MANAGE-TO-BLUE default-action drop

# ── SOC_TR <-> DMZ ────────────────────────────────────────
set firewall ipv4 name SOC-TO-DMZ description 'SecMon verso DMZ'
set firewall ipv4 name SOC-TO-DMZ default-action drop

set firewall ipv4 name SOC-TO-DMZ rule 10 description 'All SecMon -> DMZ'
set firewall ipv4 name SOC-TO-DMZ rule 10 action accept
set firewall ipv4 name SOC-TO-DMZ rule 10 source address {SUBNET_SOC}
set firewall ipv4 name SOC-TO-DMZ rule 10 destination address {SUBNET_DMZ}

set firewall ipv4 name DMZ-TO-SOC description 'DMZ verso SOC transit'
set firewall ipv4 name DMZ-TO-SOC default-action drop

# ── SOC_TR <-> EMPLOY ─────────────────────────────────────
set firewall ipv4 name SOC-TO-EMPLOY description 'SecMon verso EMPLOY'
set firewall ipv4 name SOC-TO-EMPLOY default-action drop

set firewall ipv4 name SOC-TO-EMPLOY rule 10 description 'All SecMon -> EMPLOY'
set firewall ipv4 name SOC-TO-EMPLOY rule 10 action accept
set firewall ipv4 name SOC-TO-EMPLOY rule 10 source address {SUBNET_SOC}
set firewall ipv4 name SOC-TO-EMPLOY rule 10 destination address {SUBNET_EMPLOY}

set firewall ipv4 name EMPLOY-TO-SOC description 'EMPLOY verso SOC transit'
set firewall ipv4 name EMPLOY-TO-SOC default-action drop

# ── SOC_TR <-> IT ─────────────────────────────────────────
set firewall ipv4 name SOC-TO-IT description 'SecMon verso IT'
set firewall ipv4 name SOC-TO-IT default-action drop

set firewall ipv4 name SOC-TO-IT rule 10 description 'All SecMon -> IT'
set firewall ipv4 name SOC-TO-IT rule 10 action accept
set firewall ipv4 name SOC-TO-IT rule 10 source address {SUBNET_SOC}
set firewall ipv4 name SOC-TO-IT rule 10 destination address {SUBNET_IT}

set firewall ipv4 name IT-TO-SOC description 'IT verso SOC transit'
set firewall ipv4 name IT-TO-SOC default-action drop

# ── SOC_TR <-> MANAGE ─────────────────────────────────────
set firewall ipv4 name SOC-TO-MANAGE description 'SecMon verso MANAGE'
set firewall ipv4 name SOC-TO-MANAGE default-action drop

set firewall ipv4 name SOC-TO-MANAGE rule 10 description 'All SecMon -> MANAGE'
set firewall ipv4 name SOC-TO-MANAGE rule 10 action accept
set firewall ipv4 name SOC-TO-MANAGE rule 10 source address {SUBNET_SOC}
set firewall ipv4 name SOC-TO-MANAGE rule 10 destination address {SUBNET_MANAGE}

set firewall ipv4 name MANAGE-TO-SOC description 'MANAGE verso SOC transit'
set firewall ipv4 name MANAGE-TO-SOC default-action drop

# ── SOC_TR <-> BLUE_TR ────────────────────────────────────
set firewall ipv4 name SOC-TO-BLUE description 'SecMon verso Blue Team'
set firewall ipv4 name SOC-TO-BLUE default-action drop

set firewall ipv4 name SOC-TO-BLUE rule 10 description 'All SecMon -> Blue'
set firewall ipv4 name SOC-TO-BLUE rule 10 action accept
set firewall ipv4 name SOC-TO-BLUE rule 10 source address {SUBNET_SOC}
set firewall ipv4 name SOC-TO-BLUE rule 10 destination address {SUBNET_BLUE}

set firewall ipv4 name BLUE-TO-SOC description 'Blue Team verso SOC transit'
set firewall ipv4 name BLUE-TO-SOC default-action drop

# ── EMPLOY <-> IT (DNS verso DC) ──────────────────────────
set firewall ipv4 name EMPLOY-TO-IT description 'EMPLOY verso IT — solo DNS'
set firewall ipv4 name EMPLOY-TO-IT default-action drop
set firewall ipv4 name EMPLOY-TO-IT default-log

set firewall ipv4 name EMPLOY-TO-IT rule 10 description 'DNS UDP EMPLOY -> IT-DC-01'
set firewall ipv4 name EMPLOY-TO-IT rule 10 action accept
set firewall ipv4 name EMPLOY-TO-IT rule 10 source address {SUBNET_EMPLOY}
set firewall ipv4 name EMPLOY-TO-IT rule 10 destination address {IP_DC01}
set firewall ipv4 name EMPLOY-TO-IT rule 10 destination port 53
set firewall ipv4 name EMPLOY-TO-IT rule 10 protocol udp

set firewall ipv4 name EMPLOY-TO-IT rule 20 description 'DNS TCP EMPLOY -> IT-DC-01'
set firewall ipv4 name EMPLOY-TO-IT rule 20 action accept
set firewall ipv4 name EMPLOY-TO-IT rule 20 source address {SUBNET_EMPLOY}
set firewall ipv4 name EMPLOY-TO-IT rule 20 destination address {IP_DC01}
set firewall ipv4 name EMPLOY-TO-IT rule 20 destination port 53
set firewall ipv4 name EMPLOY-TO-IT rule 20 protocol tcp

set firewall ipv4 name IT-TO-EMPLOY description 'IT verso EMPLOY'
set firewall ipv4 name IT-TO-EMPLOY default-action drop

# ── MANAGE <-> IT (DNS verso DC) ──────────────────────────
set firewall ipv4 name MANAGE-TO-IT description 'MANAGE verso IT — solo DNS'
set firewall ipv4 name MANAGE-TO-IT default-action drop
set firewall ipv4 name MANAGE-TO-IT default-log

set firewall ipv4 name MANAGE-TO-IT rule 10 description 'DNS UDP MANAGE -> IT-DC-01'
set firewall ipv4 name MANAGE-TO-IT rule 10 action accept
set firewall ipv4 name MANAGE-TO-IT rule 10 source address {SUBNET_MANAGE}
set firewall ipv4 name MANAGE-TO-IT rule 10 destination address {IP_DC01}
set firewall ipv4 name MANAGE-TO-IT rule 10 destination port 53
set firewall ipv4 name MANAGE-TO-IT rule 10 protocol udp

set firewall ipv4 name MANAGE-TO-IT rule 20 description 'DNS TCP MANAGE -> IT-DC-01'
set firewall ipv4 name MANAGE-TO-IT rule 20 action accept
set firewall ipv4 name MANAGE-TO-IT rule 20 source address {SUBNET_MANAGE}
set firewall ipv4 name MANAGE-TO-IT rule 20 destination address {IP_DC01}
set firewall ipv4 name MANAGE-TO-IT rule 20 destination port 53
set firewall ipv4 name MANAGE-TO-IT rule 20 protocol tcp

set firewall ipv4 name IT-TO-MANAGE description 'IT verso MANAGE'
set firewall ipv4 name IT-TO-MANAGE default-action drop

# ── FORWARD FILTER (sostituisce zone-policy) ──────────────
set firewall ipv4 forward filter default-action drop

set firewall ipv4 forward filter rule 1 description 'Allow established/related globally'
set firewall ipv4 forward filter rule 1 action accept
set firewall ipv4 forward filter rule 1 state established
set firewall ipv4 forward filter rule 1 state related

set firewall ipv4 forward filter rule 100 description 'DMZ -> EMPLOY jump'
set firewall ipv4 forward filter rule 100 inbound-interface name {IF_DMZ}
set firewall ipv4 forward filter rule 100 outbound-interface name {IF_EMPLOY}
set firewall ipv4 forward filter rule 100 action jump
set firewall ipv4 forward filter rule 100 jump-target DMZ-TO-EMPLOY

set firewall ipv4 forward filter rule 110 description 'EMPLOY -> DMZ jump'
set firewall ipv4 forward filter rule 110 inbound-interface name {IF_EMPLOY}
set firewall ipv4 forward filter rule 110 outbound-interface name {IF_DMZ}
set firewall ipv4 forward filter rule 110 action jump
set firewall ipv4 forward filter rule 110 jump-target EMPLOY-TO-DMZ

set firewall ipv4 forward filter rule 120 description 'DMZ -> IT jump'
set firewall ipv4 forward filter rule 120 inbound-interface name {IF_DMZ}
set firewall ipv4 forward filter rule 120 outbound-interface name {IF_IT}
set firewall ipv4 forward filter rule 120 action jump
set firewall ipv4 forward filter rule 120 jump-target DMZ-TO-IT

set firewall ipv4 forward filter rule 130 description 'IT -> DMZ jump'
set firewall ipv4 forward filter rule 130 inbound-interface name {IF_IT}
set firewall ipv4 forward filter rule 130 outbound-interface name {IF_DMZ}
set firewall ipv4 forward filter rule 130 action jump
set firewall ipv4 forward filter rule 130 jump-target IT-TO-DMZ

set firewall ipv4 forward filter rule 140 description 'DMZ -> MANAGE jump'
set firewall ipv4 forward filter rule 140 inbound-interface name {IF_DMZ}
set firewall ipv4 forward filter rule 140 outbound-interface name {IF_MANAGE}
set firewall ipv4 forward filter rule 140 action jump
set firewall ipv4 forward filter rule 140 jump-target DMZ-TO-MANAGE

set firewall ipv4 forward filter rule 150 description 'MANAGE -> DMZ jump'
set firewall ipv4 forward filter rule 150 inbound-interface name {IF_MANAGE}
set firewall ipv4 forward filter rule 150 outbound-interface name {IF_DMZ}
set firewall ipv4 forward filter rule 150 action jump
set firewall ipv4 forward filter rule 150 jump-target MANAGE-TO-DMZ

set firewall ipv4 forward filter rule 160 description 'BLUE_TR -> DMZ jump'
set firewall ipv4 forward filter rule 160 inbound-interface name {IF_BLUE_TR}
set firewall ipv4 forward filter rule 160 outbound-interface name {IF_DMZ}
set firewall ipv4 forward filter rule 160 action jump
set firewall ipv4 forward filter rule 160 jump-target BLUE-TO-DMZ

set firewall ipv4 forward filter rule 170 description 'DMZ -> BLUE_TR jump'
set firewall ipv4 forward filter rule 170 inbound-interface name {IF_DMZ}
set firewall ipv4 forward filter rule 170 outbound-interface name {IF_BLUE_TR}
set firewall ipv4 forward filter rule 170 action jump
set firewall ipv4 forward filter rule 170 jump-target DMZ-TO-BLUE

set firewall ipv4 forward filter rule 180 description 'BLUE_TR -> EMPLOY jump'
set firewall ipv4 forward filter rule 180 inbound-interface name {IF_BLUE_TR}
set firewall ipv4 forward filter rule 180 outbound-interface name {IF_EMPLOY}
set firewall ipv4 forward filter rule 180 action jump
set firewall ipv4 forward filter rule 180 jump-target BLUE-TO-EMPLOY

set firewall ipv4 forward filter rule 190 description 'EMPLOY -> BLUE_TR jump'
set firewall ipv4 forward filter rule 190 inbound-interface name {IF_EMPLOY}
set firewall ipv4 forward filter rule 190 outbound-interface name {IF_BLUE_TR}
set firewall ipv4 forward filter rule 190 action jump
set firewall ipv4 forward filter rule 190 jump-target EMPLOY-TO-BLUE

set firewall ipv4 forward filter rule 200 description 'BLUE_TR -> IT jump'
set firewall ipv4 forward filter rule 200 inbound-interface name {IF_BLUE_TR}
set firewall ipv4 forward filter rule 200 outbound-interface name {IF_IT}
set firewall ipv4 forward filter rule 200 action jump
set firewall ipv4 forward filter rule 200 jump-target BLUE-TO-IT

set firewall ipv4 forward filter rule 210 description 'IT -> BLUE_TR jump'
set firewall ipv4 forward filter rule 210 inbound-interface name {IF_IT}
set firewall ipv4 forward filter rule 210 outbound-interface name {IF_BLUE_TR}
set firewall ipv4 forward filter rule 210 action jump
set firewall ipv4 forward filter rule 210 jump-target IT-TO-BLUE

set firewall ipv4 forward filter rule 220 description 'BLUE_TR -> MANAGE jump'
set firewall ipv4 forward filter rule 220 inbound-interface name {IF_BLUE_TR}
set firewall ipv4 forward filter rule 220 outbound-interface name {IF_MANAGE}
set firewall ipv4 forward filter rule 220 action jump
set firewall ipv4 forward filter rule 220 jump-target BLUE-TO-MANAGE

set firewall ipv4 forward filter rule 230 description 'MANAGE -> BLUE_TR jump'
set firewall ipv4 forward filter rule 230 inbound-interface name {IF_MANAGE}
set firewall ipv4 forward filter rule 230 outbound-interface name {IF_BLUE_TR}
set firewall ipv4 forward filter rule 230 action jump
set firewall ipv4 forward filter rule 230 jump-target MANAGE-TO-BLUE

set firewall ipv4 forward filter rule 240 description 'SOC_TR -> DMZ jump'
set firewall ipv4 forward filter rule 240 inbound-interface name {IF_SOC_TR}
set firewall ipv4 forward filter rule 240 outbound-interface name {IF_DMZ}
set firewall ipv4 forward filter rule 240 action jump
set firewall ipv4 forward filter rule 240 jump-target SOC-TO-DMZ

set firewall ipv4 forward filter rule 250 description 'DMZ -> SOC_TR jump'
set firewall ipv4 forward filter rule 250 inbound-interface name {IF_DMZ}
set firewall ipv4 forward filter rule 250 outbound-interface name {IF_SOC_TR}
set firewall ipv4 forward filter rule 250 action jump
set firewall ipv4 forward filter rule 250 jump-target DMZ-TO-SOC

set firewall ipv4 forward filter rule 260 description 'SOC_TR -> EMPLOY jump'
set firewall ipv4 forward filter rule 260 inbound-interface name {IF_SOC_TR}
set firewall ipv4 forward filter rule 260 outbound-interface name {IF_EMPLOY}
set firewall ipv4 forward filter rule 260 action jump
set firewall ipv4 forward filter rule 260 jump-target SOC-TO-EMPLOY

set firewall ipv4 forward filter rule 270 description 'EMPLOY -> SOC_TR jump'
set firewall ipv4 forward filter rule 270 inbound-interface name {IF_EMPLOY}
set firewall ipv4 forward filter rule 270 outbound-interface name {IF_SOC_TR}
set firewall ipv4 forward filter rule 270 action jump
set firewall ipv4 forward filter rule 270 jump-target EMPLOY-TO-SOC

set firewall ipv4 forward filter rule 280 description 'SOC_TR -> IT jump'
set firewall ipv4 forward filter rule 280 inbound-interface name {IF_SOC_TR}
set firewall ipv4 forward filter rule 280 outbound-interface name {IF_IT}
set firewall ipv4 forward filter rule 280 action jump
set firewall ipv4 forward filter rule 280 jump-target SOC-TO-IT

set firewall ipv4 forward filter rule 290 description 'IT -> SOC_TR jump'
set firewall ipv4 forward filter rule 290 inbound-interface name {IF_IT}
set firewall ipv4 forward filter rule 290 outbound-interface name {IF_SOC_TR}
set firewall ipv4 forward filter rule 290 action jump
set firewall ipv4 forward filter rule 290 jump-target IT-TO-SOC

set firewall ipv4 forward filter rule 300 description 'SOC_TR -> MANAGE jump'
set firewall ipv4 forward filter rule 300 inbound-interface name {IF_SOC_TR}
set firewall ipv4 forward filter rule 300 outbound-interface name {IF_MANAGE}
set firewall ipv4 forward filter rule 300 action jump
set firewall ipv4 forward filter rule 300 jump-target SOC-TO-MANAGE

set firewall ipv4 forward filter rule 310 description 'MANAGE -> SOC_TR jump'
set firewall ipv4 forward filter rule 310 inbound-interface name {IF_MANAGE}
set firewall ipv4 forward filter rule 310 outbound-interface name {IF_SOC_TR}
set firewall ipv4 forward filter rule 310 action jump
set firewall ipv4 forward filter rule 310 jump-target MANAGE-TO-SOC

set firewall ipv4 forward filter rule 320 description 'SOC_TR -> BLUE_TR jump'
set firewall ipv4 forward filter rule 320 inbound-interface name {IF_SOC_TR}
set firewall ipv4 forward filter rule 320 outbound-interface name {IF_BLUE_TR}
set firewall ipv4 forward filter rule 320 action jump
set firewall ipv4 forward filter rule 320 jump-target SOC-TO-BLUE

set firewall ipv4 forward filter rule 330 description 'BLUE_TR -> SOC_TR jump'
set firewall ipv4 forward filter rule 330 inbound-interface name {IF_BLUE_TR}
set firewall ipv4 forward filter rule 330 outbound-interface name {IF_SOC_TR}
set firewall ipv4 forward filter rule 330 action jump
set firewall ipv4 forward filter rule 330 jump-target BLUE-TO-SOC

set firewall ipv4 forward filter rule 340 description 'EMPLOY -> IT jump'
set firewall ipv4 forward filter rule 340 inbound-interface name {IF_EMPLOY}
set firewall ipv4 forward filter rule 340 outbound-interface name {IF_IT}
set firewall ipv4 forward filter rule 340 action jump
set firewall ipv4 forward filter rule 340 jump-target EMPLOY-TO-IT

set firewall ipv4 forward filter rule 350 description 'IT -> EMPLOY jump'
set firewall ipv4 forward filter rule 350 inbound-interface name {IF_IT}
set firewall ipv4 forward filter rule 350 outbound-interface name {IF_EMPLOY}
set firewall ipv4 forward filter rule 350 action jump
set firewall ipv4 forward filter rule 350 jump-target IT-TO-EMPLOY

set firewall ipv4 forward filter rule 360 description 'MANAGE -> IT jump'
set firewall ipv4 forward filter rule 360 inbound-interface name {IF_MANAGE}
set firewall ipv4 forward filter rule 360 outbound-interface name {IF_IT}
set firewall ipv4 forward filter rule 360 action jump
set firewall ipv4 forward filter rule 360 jump-target MANAGE-TO-IT

set firewall ipv4 forward filter rule 370 description 'IT -> MANAGE jump'
set firewall ipv4 forward filter rule 370 inbound-interface name {IF_IT}
set firewall ipv4 forward filter rule 370 outbound-interface name {IF_MANAGE}
set firewall ipv4 forward filter rule 370 action jump
set firewall ipv4 forward filter rule 370 jump-target IT-TO-MANAGE
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
    print("  CN-ROUTER — VyOS 1.5 Firewall (ex CN-DMZFW-01 + CN-MISFW-01)")
    print("="*60)
    ifaces = [
        (IF_BLUE_TR,"BLUE_TR","10.0.93.1"),
        (IF_DMZ,    "DMZ",    "10.0.13.1"),
        (IF_IT,     "IT",     "10.0.14.1"),
        (IF_MANAGE, "MANAGE", "10.1.21.1"),
        (IF_EMPLOY, "EMPLOY", "10.2.150.1"),
        (IF_SOC_TR, "SOC_TR", "10.0.94.1"),
    ]
    for iface,zone,ip in ifaces:
        print(f"  {iface}  {zone:<10} {ip}")
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
