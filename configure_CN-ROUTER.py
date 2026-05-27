#!/usr/bin/env python3
"""
=============================================================
  CYBER RANGE — VyOS 1.5 Firewall Configuration Script
  Device  : cn-router
  Role    : Router centrale + Firewall inter-zona
            (sostituisce CN-DMZFW-01 e CN-MISFW-01)
  Run on  : localmente sul VyOS (sudo python3 configure_CN-ROUTER.py)

  Zone Policy implementate:
    DMZ      <-->  EMPLOY     (ex CN-MISFW-01)
    DMZ      <-->  IT         (ex CN-DMZFW-01 — drop)
    DMZ      <-->  MANAGE     (ex CN-DMZFW-01 — drop)
    BLUE_TR  <-->  DMZ        (defense in depth)
    BLUE_TR  <-->  EMPLOY     (defense in depth)
    BLUE_TR  <-->  IT         (defense in depth)
    BLUE_TR  <-->  MANAGE     (defense in depth)
    SOC_TR   <-->  DMZ        (defense in depth)
    SOC_TR   <-->  EMPLOY     (defense in depth)
    SOC_TR   <-->  IT         (defense in depth)
    SOC_TR   <-->  MANAGE     (defense in depth)
=============================================================
"""

import subprocess
import tempfile
import os
import sys

# ─────────────────────────────────────────────
#  CONFIGURAZIONE — modifica qui se necessario
# ─────────────────────────────────────────────

# Interfacce cn-router
IF_BLUE_TR = "eth1"   # 10.0.93.1  — transit verso BLUE-CNFW-01
IF_DMZ     = "eth2"   # 10.0.13.1  — DMZ subnet
IF_IT      = "eth3"   # 10.0.14.1  — IT subnet
IF_MANAGE  = "eth4"   # 10.1.21.1  — MANAGE subnet
IF_EMPLOY  = "eth5"   # 10.2.150.1 — EMPLOY/Mission subnet
IF_SOC_TR  = "eth6"   # 10.0.94.1  — transit verso SECMON-CNFW-01

# Subnet
SUBNET_BLUE   = "10.0.11.0/24"    # Blue Team (sorgente reale, arriva via BLUE_TR)
SUBNET_DMZ    = "10.0.13.0/24"    # DMZ
SUBNET_IT     = "10.0.14.0/24"    # IT
SUBNET_MANAGE = "10.1.21.0/24"    # MANAGE
SUBNET_EMPLOY = "10.2.150.0/24"   # EMPLOY / Mission
SUBNET_SOC    = "10.0.17.0/24"    # SecMon (sorgente reale, arriva via SOC_TR)

# Host specifici
IP_BAST01  = "10.0.13.20"   # DMZ-BAST-01
IP_VPN01   = "10.0.13.30"   # DMZ-VPN-01
IP_EMP_WS1 = "10.2.150.213" # EMP-WINWS-01
IP_EMP_WS2 = "10.2.150.214" # EMP-WINWS-02
IP_EMP_WS3 = "10.2.150.216" # EMP-WINWS-03
IP_DC01    = "10.0.14.11"    # IT-DC-01 (Domain Controller / DNS)

# ─────────────────────────────────────────────
#  COMANDI VYOS
# ─────────────────────────────────────────────

COMMANDS = f"""
# ══════════════════════════════════════════════
#  ZONE POLICY — definizione zone
# ══════════════════════════════════════════════

set zone-policy zone BLUE_TR description 'Transit Blue Team (via BLUE-CNFW-01)'
set zone-policy zone BLUE_TR interface {IF_BLUE_TR}

set zone-policy zone DMZ description 'DMZ subnet'
set zone-policy zone DMZ interface {IF_DMZ}

set zone-policy zone IT description 'IT subnet'
set zone-policy zone IT interface {IF_IT}

set zone-policy zone MANAGE description 'MANAGE subnet'
set zone-policy zone MANAGE interface {IF_MANAGE}

set zone-policy zone EMPLOY description 'EMPLOY / Mission subnet'
set zone-policy zone EMPLOY interface {IF_EMPLOY}

set zone-policy zone SOC_TR description 'Transit SecMon (via SECMON-CNFW-01)'
set zone-policy zone SOC_TR interface {IF_SOC_TR}

# ══════════════════════════════════════════════
#  ADDRESS GROUP — EMP Workstations
# ══════════════════════════════════════════════

set firewall group address-group EMP-WORKSTATIONS description 'EMP Workstations (WinRM target)'
set firewall group address-group EMP-WORKSTATIONS address {IP_EMP_WS1}
set firewall group address-group EMP-WORKSTATIONS address {IP_EMP_WS2}
set firewall group address-group EMP-WORKSTATIONS address {IP_EMP_WS3}

# ══════════════════════════════════════════════
#  DMZ <-> EMPLOY  (ex CN-MISFW-01)
#  - BAST-01 può fare RDP verso EMPLOY
#  - BAST-01 può fare WinRM verso EMP workstations
#  - Tutto il resto dalla DMZ verso EMPLOY: DROP
# ══════════════════════════════════════════════

set firewall ipv4 name DMZ-TO-EMPLOY description 'DMZ verso EMPLOY (ex CN-MISFW-01)'
set firewall ipv4 name DMZ-TO-EMPLOY default-action drop
set firewall ipv4 name DMZ-TO-EMPLOY enable-default-log

set firewall ipv4 name DMZ-TO-EMPLOY rule 5 description 'Allow established/related'
set firewall ipv4 name DMZ-TO-EMPLOY rule 5 action accept
set firewall ipv4 name DMZ-TO-EMPLOY rule 5 state established enable
set firewall ipv4 name DMZ-TO-EMPLOY rule 5 state related enable

set firewall ipv4 name DMZ-TO-EMPLOY rule 10 description 'RDP BAST-01 -> EMPLOY subnet'
set firewall ipv4 name DMZ-TO-EMPLOY rule 10 action accept
set firewall ipv4 name DMZ-TO-EMPLOY rule 10 source address {IP_BAST01}
set firewall ipv4 name DMZ-TO-EMPLOY rule 10 destination address {SUBNET_EMPLOY}
set firewall ipv4 name DMZ-TO-EMPLOY rule 10 destination port 3389
set firewall ipv4 name DMZ-TO-EMPLOY rule 10 protocol tcp

set firewall ipv4 name DMZ-TO-EMPLOY rule 20 description 'WinRM HTTP BAST-01 -> EMP workstations'
set firewall ipv4 name DMZ-TO-EMPLOY rule 20 action accept
set firewall ipv4 name DMZ-TO-EMPLOY rule 20 source address {IP_BAST01}
set firewall ipv4 name DMZ-TO-EMPLOY rule 20 destination group address-group EMP-WORKSTATIONS
set firewall ipv4 name DMZ-TO-EMPLOY rule 20 destination port 5985
set firewall ipv4 name DMZ-TO-EMPLOY rule 20 protocol tcp

set firewall ipv4 name DMZ-TO-EMPLOY rule 30 description 'WinRM HTTPS BAST-01 -> EMP workstations'
set firewall ipv4 name DMZ-TO-EMPLOY rule 30 action accept
set firewall ipv4 name DMZ-TO-EMPLOY rule 30 source address {IP_BAST01}
set firewall ipv4 name DMZ-TO-EMPLOY rule 30 destination group address-group EMP-WORKSTATIONS
set firewall ipv4 name DMZ-TO-EMPLOY rule 30 destination port 5986
set firewall ipv4 name DMZ-TO-EMPLOY rule 30 protocol tcp

# Ritorno EMPLOY -> DMZ: solo established/related
set firewall ipv4 name EMPLOY-TO-DMZ description 'EMPLOY verso DMZ'
set firewall ipv4 name EMPLOY-TO-DMZ default-action drop

set firewall ipv4 name EMPLOY-TO-DMZ rule 5 description 'Allow established/related'
set firewall ipv4 name EMPLOY-TO-DMZ rule 5 action accept
set firewall ipv4 name EMPLOY-TO-DMZ rule 5 state established enable
set firewall ipv4 name EMPLOY-TO-DMZ rule 5 state related enable

# ══════════════════════════════════════════════
#  DMZ -> IT  (ex CN-DMZFW-01)
#  La DMZ non deve raggiungere IT: DROP tutto
# ══════════════════════════════════════════════

set firewall ipv4 name DMZ-TO-IT description 'DMZ verso IT — solo DNS verso DC'
set firewall ipv4 name DMZ-TO-IT default-action drop
set firewall ipv4 name DMZ-TO-IT enable-default-log

set firewall ipv4 name DMZ-TO-IT rule 5 description 'Allow established/related'
set firewall ipv4 name DMZ-TO-IT rule 5 action accept
set firewall ipv4 name DMZ-TO-IT rule 5 state established enable
set firewall ipv4 name DMZ-TO-IT rule 5 state related enable

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

# Ritorno IT -> DMZ: solo established/related
set firewall ipv4 name IT-TO-DMZ description 'IT verso DMZ'
set firewall ipv4 name IT-TO-DMZ default-action drop

set firewall ipv4 name IT-TO-DMZ rule 5 description 'Allow established/related'
set firewall ipv4 name IT-TO-DMZ rule 5 action accept
set firewall ipv4 name IT-TO-DMZ rule 5 state established enable
set firewall ipv4 name IT-TO-DMZ rule 5 state related enable

# ══════════════════════════════════════════════
#  DMZ -> MANAGE  (ex CN-DMZFW-01)
#  La DMZ non deve raggiungere MANAGE: DROP tutto
# ══════════════════════════════════════════════

set firewall ipv4 name DMZ-TO-MANAGE description 'DMZ verso MANAGE — DROP (ex CN-DMZFW-01)'
set firewall ipv4 name DMZ-TO-MANAGE default-action drop
set firewall ipv4 name DMZ-TO-MANAGE enable-default-log

set firewall ipv4 name DMZ-TO-MANAGE rule 5 description 'Allow established/related'
set firewall ipv4 name DMZ-TO-MANAGE rule 5 action accept
set firewall ipv4 name DMZ-TO-MANAGE rule 5 state established enable
set firewall ipv4 name DMZ-TO-MANAGE rule 5 state related enable

# Ritorno MANAGE -> DMZ: solo established/related
set firewall ipv4 name MANAGE-TO-DMZ description 'MANAGE verso DMZ'
set firewall ipv4 name MANAGE-TO-DMZ default-action drop

set firewall ipv4 name MANAGE-TO-DMZ rule 5 description 'Allow established/related'
set firewall ipv4 name MANAGE-TO-DMZ rule 5 action accept
set firewall ipv4 name MANAGE-TO-DMZ rule 5 state established enable
set firewall ipv4 name MANAGE-TO-DMZ rule 5 state related enable

# ══════════════════════════════════════════════
#  BLUE_TR -> DMZ/EMPLOY/IT/MANAGE
#  Defense in depth: ridondante con BLUE-CNFW-01
#  ma aggiunge un secondo livello di controllo
# ══════════════════════════════════════════════

# BLUE_TR -> DMZ
set firewall ipv4 name BLUE-TO-DMZ description 'Blue Team verso DMZ (defense in depth)'
set firewall ipv4 name BLUE-TO-DMZ default-action drop

set firewall ipv4 name BLUE-TO-DMZ rule 5 description 'Allow established/related'
set firewall ipv4 name BLUE-TO-DMZ rule 5 action accept
set firewall ipv4 name BLUE-TO-DMZ rule 5 state established enable
set firewall ipv4 name BLUE-TO-DMZ rule 5 state related enable

set firewall ipv4 name BLUE-TO-DMZ rule 10 description 'RDP Blue -> DMZ subnet'
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

# DMZ -> BLUE_TR: solo established/related
set firewall ipv4 name DMZ-TO-BLUE description 'DMZ verso Blue Team transit'
set firewall ipv4 name DMZ-TO-BLUE default-action drop

set firewall ipv4 name DMZ-TO-BLUE rule 5 description 'Allow established/related'
set firewall ipv4 name DMZ-TO-BLUE rule 5 action accept
set firewall ipv4 name DMZ-TO-BLUE rule 5 state established enable
set firewall ipv4 name DMZ-TO-BLUE rule 5 state related enable

# BLUE_TR -> EMPLOY
set firewall ipv4 name BLUE-TO-EMPLOY description 'Blue Team verso EMPLOY (defense in depth)'
set firewall ipv4 name BLUE-TO-EMPLOY default-action drop

set firewall ipv4 name BLUE-TO-EMPLOY rule 5 description 'Allow established/related'
set firewall ipv4 name BLUE-TO-EMPLOY rule 5 action accept
set firewall ipv4 name BLUE-TO-EMPLOY rule 5 state established enable
set firewall ipv4 name BLUE-TO-EMPLOY rule 5 state related enable

set firewall ipv4 name BLUE-TO-EMPLOY rule 10 description 'RDP Blue -> EMPLOY subnet'
set firewall ipv4 name BLUE-TO-EMPLOY rule 10 action accept
set firewall ipv4 name BLUE-TO-EMPLOY rule 10 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-EMPLOY rule 10 destination address {SUBNET_EMPLOY}
set firewall ipv4 name BLUE-TO-EMPLOY rule 10 destination port 3389
set firewall ipv4 name BLUE-TO-EMPLOY rule 10 protocol tcp

# EMPLOY -> BLUE_TR: solo established/related
set firewall ipv4 name EMPLOY-TO-BLUE description 'EMPLOY verso Blue Team transit'
set firewall ipv4 name EMPLOY-TO-BLUE default-action drop

set firewall ipv4 name EMPLOY-TO-BLUE rule 5 description 'Allow established/related'
set firewall ipv4 name EMPLOY-TO-BLUE rule 5 action accept
set firewall ipv4 name EMPLOY-TO-BLUE rule 5 state established enable
set firewall ipv4 name EMPLOY-TO-BLUE rule 5 state related enable

# BLUE_TR -> IT
set firewall ipv4 name BLUE-TO-IT description 'Blue Team verso IT (defense in depth)'
set firewall ipv4 name BLUE-TO-IT default-action drop

set firewall ipv4 name BLUE-TO-IT rule 5 description 'Allow established/related'
set firewall ipv4 name BLUE-TO-IT rule 5 action accept
set firewall ipv4 name BLUE-TO-IT rule 5 state established enable
set firewall ipv4 name BLUE-TO-IT rule 5 state related enable

set firewall ipv4 name BLUE-TO-IT rule 10 description 'RDP Blue -> IT subnet'
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

# IT -> BLUE_TR: solo established/related
set firewall ipv4 name IT-TO-BLUE description 'IT verso Blue Team transit'
set firewall ipv4 name IT-TO-BLUE default-action drop

set firewall ipv4 name IT-TO-BLUE rule 5 description 'Allow established/related'
set firewall ipv4 name IT-TO-BLUE rule 5 action accept
set firewall ipv4 name IT-TO-BLUE rule 5 state established enable
set firewall ipv4 name IT-TO-BLUE rule 5 state related enable

# BLUE_TR -> MANAGE
set firewall ipv4 name BLUE-TO-MANAGE description 'Blue Team verso MANAGE (defense in depth)'
set firewall ipv4 name BLUE-TO-MANAGE default-action drop

set firewall ipv4 name BLUE-TO-MANAGE rule 5 description 'Allow established/related'
set firewall ipv4 name BLUE-TO-MANAGE rule 5 action accept
set firewall ipv4 name BLUE-TO-MANAGE rule 5 state established enable
set firewall ipv4 name BLUE-TO-MANAGE rule 5 state related enable

set firewall ipv4 name BLUE-TO-MANAGE rule 10 description 'RDP Blue -> MANAGE subnet'
set firewall ipv4 name BLUE-TO-MANAGE rule 10 action accept
set firewall ipv4 name BLUE-TO-MANAGE rule 10 source address {SUBNET_BLUE}
set firewall ipv4 name BLUE-TO-MANAGE rule 10 destination address {SUBNET_MANAGE}
set firewall ipv4 name BLUE-TO-MANAGE rule 10 destination port 3389
set firewall ipv4 name BLUE-TO-MANAGE rule 10 protocol tcp

# MANAGE -> BLUE_TR: solo established/related
set firewall ipv4 name MANAGE-TO-BLUE description 'MANAGE verso Blue Team transit'
set firewall ipv4 name MANAGE-TO-BLUE default-action drop

set firewall ipv4 name MANAGE-TO-BLUE rule 5 description 'Allow established/related'
set firewall ipv4 name MANAGE-TO-BLUE rule 5 action accept
set firewall ipv4 name MANAGE-TO-BLUE rule 5 state established enable
set firewall ipv4 name MANAGE-TO-BLUE rule 5 state related enable

# ══════════════════════════════════════════════
#  SOC_TR -> DMZ/EMPLOY/IT/MANAGE/BLUE_TR
#  Defense in depth: ridondante con SECMON-CNFW-01
#  SecMon raggiunge tutto (tranne RED)
# ══════════════════════════════════════════════

# SOC_TR -> DMZ
set firewall ipv4 name SOC-TO-DMZ description 'SecMon verso DMZ (defense in depth)'
set firewall ipv4 name SOC-TO-DMZ default-action drop

set firewall ipv4 name SOC-TO-DMZ rule 5 description 'Allow established/related'
set firewall ipv4 name SOC-TO-DMZ rule 5 action accept
set firewall ipv4 name SOC-TO-DMZ rule 5 state established enable
set firewall ipv4 name SOC-TO-DMZ rule 5 state related enable

set firewall ipv4 name SOC-TO-DMZ rule 10 description 'Allow all SecMon -> DMZ'
set firewall ipv4 name SOC-TO-DMZ rule 10 action accept
set firewall ipv4 name SOC-TO-DMZ rule 10 source address {SUBNET_SOC}
set firewall ipv4 name SOC-TO-DMZ rule 10 destination address {SUBNET_DMZ}

# DMZ -> SOC_TR: solo established/related
set firewall ipv4 name DMZ-TO-SOC description 'DMZ verso SOC transit'
set firewall ipv4 name DMZ-TO-SOC default-action drop

set firewall ipv4 name DMZ-TO-SOC rule 5 description 'Allow established/related'
set firewall ipv4 name DMZ-TO-SOC rule 5 action accept
set firewall ipv4 name DMZ-TO-SOC rule 5 state established enable
set firewall ipv4 name DMZ-TO-SOC rule 5 state related enable

# SOC_TR -> EMPLOY
set firewall ipv4 name SOC-TO-EMPLOY description 'SecMon verso EMPLOY (defense in depth)'
set firewall ipv4 name SOC-TO-EMPLOY default-action drop

set firewall ipv4 name SOC-TO-EMPLOY rule 5 description 'Allow established/related'
set firewall ipv4 name SOC-TO-EMPLOY rule 5 action accept
set firewall ipv4 name SOC-TO-EMPLOY rule 5 state established enable
set firewall ipv4 name SOC-TO-EMPLOY rule 5 state related enable

set firewall ipv4 name SOC-TO-EMPLOY rule 10 description 'Allow all SecMon -> EMPLOY'
set firewall ipv4 name SOC-TO-EMPLOY rule 10 action accept
set firewall ipv4 name SOC-TO-EMPLOY rule 10 source address {SUBNET_SOC}
set firewall ipv4 name SOC-TO-EMPLOY rule 10 destination address {SUBNET_EMPLOY}

# EMPLOY -> SOC_TR: solo established/related
set firewall ipv4 name EMPLOY-TO-SOC description 'EMPLOY verso SOC transit'
set firewall ipv4 name EMPLOY-TO-SOC default-action drop

set firewall ipv4 name EMPLOY-TO-SOC rule 5 description 'Allow established/related'
set firewall ipv4 name EMPLOY-TO-SOC rule 5 action accept
set firewall ipv4 name EMPLOY-TO-SOC rule 5 state established enable
set firewall ipv4 name EMPLOY-TO-SOC rule 5 state related enable

# SOC_TR -> IT
set firewall ipv4 name SOC-TO-IT description 'SecMon verso IT (defense in depth)'
set firewall ipv4 name SOC-TO-IT default-action drop

set firewall ipv4 name SOC-TO-IT rule 5 description 'Allow established/related'
set firewall ipv4 name SOC-TO-IT rule 5 action accept
set firewall ipv4 name SOC-TO-IT rule 5 state established enable
set firewall ipv4 name SOC-TO-IT rule 5 state related enable

set firewall ipv4 name SOC-TO-IT rule 10 description 'Allow all SecMon -> IT'
set firewall ipv4 name SOC-TO-IT rule 10 action accept
set firewall ipv4 name SOC-TO-IT rule 10 source address {SUBNET_SOC}
set firewall ipv4 name SOC-TO-IT rule 10 destination address {SUBNET_IT}

# IT -> SOC_TR: solo established/related
set firewall ipv4 name IT-TO-SOC description 'IT verso SOC transit'
set firewall ipv4 name IT-TO-SOC default-action drop

set firewall ipv4 name IT-TO-SOC rule 5 description 'Allow established/related'
set firewall ipv4 name IT-TO-SOC rule 5 action accept
set firewall ipv4 name IT-TO-SOC rule 5 state established enable
set firewall ipv4 name IT-TO-SOC rule 5 state related enable

# SOC_TR -> MANAGE
set firewall ipv4 name SOC-TO-MANAGE description 'SecMon verso MANAGE (defense in depth)'
set firewall ipv4 name SOC-TO-MANAGE default-action drop

set firewall ipv4 name SOC-TO-MANAGE rule 5 description 'Allow established/related'
set firewall ipv4 name SOC-TO-MANAGE rule 5 action accept
set firewall ipv4 name SOC-TO-MANAGE rule 5 state established enable
set firewall ipv4 name SOC-TO-MANAGE rule 5 state related enable

set firewall ipv4 name SOC-TO-MANAGE rule 10 description 'Allow all SecMon -> MANAGE'
set firewall ipv4 name SOC-TO-MANAGE rule 10 action accept
set firewall ipv4 name SOC-TO-MANAGE rule 10 source address {SUBNET_SOC}
set firewall ipv4 name SOC-TO-MANAGE rule 10 destination address {SUBNET_MANAGE}

# MANAGE -> SOC_TR: solo established/related
set firewall ipv4 name MANAGE-TO-SOC description 'MANAGE verso SOC transit'
set firewall ipv4 name MANAGE-TO-SOC default-action drop

set firewall ipv4 name MANAGE-TO-SOC rule 5 description 'Allow established/related'
set firewall ipv4 name MANAGE-TO-SOC rule 5 action accept
set firewall ipv4 name MANAGE-TO-SOC rule 5 state established enable
set firewall ipv4 name MANAGE-TO-SOC rule 5 state related enable

# SOC_TR -> BLUE_TR
set firewall ipv4 name SOC-TO-BLUE description 'SecMon verso Blue Team transit'
set firewall ipv4 name SOC-TO-BLUE default-action drop

set firewall ipv4 name SOC-TO-BLUE rule 5 description 'Allow established/related'
set firewall ipv4 name SOC-TO-BLUE rule 5 action accept
set firewall ipv4 name SOC-TO-BLUE rule 5 state established enable
set firewall ipv4 name SOC-TO-BLUE rule 5 state related enable

set firewall ipv4 name SOC-TO-BLUE rule 10 description 'Allow all SecMon -> Blue subnet'
set firewall ipv4 name SOC-TO-BLUE rule 10 action accept
set firewall ipv4 name SOC-TO-BLUE rule 10 source address {SUBNET_SOC}
set firewall ipv4 name SOC-TO-BLUE rule 10 destination address {SUBNET_BLUE}

# BLUE_TR -> SOC_TR: solo established/related
set firewall ipv4 name BLUE-TO-SOC description 'Blue Team verso SOC transit'
set firewall ipv4 name BLUE-TO-SOC default-action drop

set firewall ipv4 name BLUE-TO-SOC rule 5 description 'Allow established/related'
set firewall ipv4 name BLUE-TO-SOC rule 5 action accept
set firewall ipv4 name BLUE-TO-SOC rule 5 state established enable
set firewall ipv4 name BLUE-TO-SOC rule 5 state related enable

# ══════════════════════════════════════════════
#  EMPLOY <-> IT — DNS verso IT-DC-01
# ══════════════════════════════════════════════

set firewall ipv4 name EMPLOY-TO-IT description 'EMPLOY verso IT — solo DNS verso DC'
set firewall ipv4 name EMPLOY-TO-IT default-action drop
set firewall ipv4 name EMPLOY-TO-IT enable-default-log

set firewall ipv4 name EMPLOY-TO-IT rule 5 description 'Allow established/related'
set firewall ipv4 name EMPLOY-TO-IT rule 5 action accept
set firewall ipv4 name EMPLOY-TO-IT rule 5 state established enable
set firewall ipv4 name EMPLOY-TO-IT rule 5 state related enable

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

set firewall ipv4 name IT-TO-EMPLOY rule 5 description 'Allow established/related'
set firewall ipv4 name IT-TO-EMPLOY rule 5 action accept
set firewall ipv4 name IT-TO-EMPLOY rule 5 state established enable
set firewall ipv4 name IT-TO-EMPLOY rule 5 state related enable

# ══════════════════════════════════════════════
#  MANAGE <-> IT — DNS verso IT-DC-01
# ══════════════════════════════════════════════

set firewall ipv4 name MANAGE-TO-IT description 'MANAGE verso IT — solo DNS verso DC'
set firewall ipv4 name MANAGE-TO-IT default-action drop
set firewall ipv4 name MANAGE-TO-IT enable-default-log

set firewall ipv4 name MANAGE-TO-IT rule 5 description 'Allow established/related'
set firewall ipv4 name MANAGE-TO-IT rule 5 action accept
set firewall ipv4 name MANAGE-TO-IT rule 5 state established enable
set firewall ipv4 name MANAGE-TO-IT rule 5 state related enable

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

set firewall ipv4 name IT-TO-MANAGE rule 5 description 'Allow established/related'
set firewall ipv4 name IT-TO-MANAGE rule 5 action accept
set firewall ipv4 name IT-TO-MANAGE rule 5 state established enable
set firewall ipv4 name IT-TO-MANAGE rule 5 state related enable

# ══════════════════════════════════════════════
#  APPLICA ZONE POLICY
# ══════════════════════════════════════════════

# DMZ <-> EMPLOY
set zone-policy zone EMPLOY  from DMZ     firewall name DMZ-TO-EMPLOY
set zone-policy zone DMZ     from EMPLOY  firewall name EMPLOY-TO-DMZ

# DMZ <-> IT (drop)
set zone-policy zone IT      from DMZ     firewall name DMZ-TO-IT
set zone-policy zone DMZ     from IT      firewall name IT-TO-DMZ

# DMZ <-> MANAGE (drop)
set zone-policy zone MANAGE  from DMZ     firewall name DMZ-TO-MANAGE
set zone-policy zone DMZ     from MANAGE  firewall name MANAGE-TO-DMZ

# BLUE_TR <-> DMZ
set zone-policy zone DMZ     from BLUE_TR firewall name BLUE-TO-DMZ
set zone-policy zone BLUE_TR from DMZ     firewall name DMZ-TO-BLUE

# BLUE_TR <-> EMPLOY
set zone-policy zone EMPLOY  from BLUE_TR firewall name BLUE-TO-EMPLOY
set zone-policy zone BLUE_TR from EMPLOY  firewall name EMPLOY-TO-BLUE

# BLUE_TR <-> IT
set zone-policy zone IT      from BLUE_TR firewall name BLUE-TO-IT
set zone-policy zone BLUE_TR from IT      firewall name IT-TO-BLUE

# BLUE_TR <-> MANAGE
set zone-policy zone MANAGE  from BLUE_TR firewall name BLUE-TO-MANAGE
set zone-policy zone BLUE_TR from MANAGE  firewall name MANAGE-TO-BLUE

# SOC_TR <-> DMZ
set zone-policy zone DMZ     from SOC_TR  firewall name SOC-TO-DMZ
set zone-policy zone SOC_TR  from DMZ     firewall name DMZ-TO-SOC

# SOC_TR <-> EMPLOY
set zone-policy zone EMPLOY  from SOC_TR  firewall name SOC-TO-EMPLOY
set zone-policy zone SOC_TR  from EMPLOY  firewall name EMPLOY-TO-SOC

# SOC_TR <-> IT
set zone-policy zone IT      from SOC_TR  firewall name SOC-TO-IT
set zone-policy zone SOC_TR  from IT      firewall name IT-TO-SOC

# SOC_TR <-> MANAGE
set zone-policy zone MANAGE  from SOC_TR  firewall name SOC-TO-MANAGE
set zone-policy zone SOC_TR  from MANAGE  firewall name MANAGE-TO-SOC

# SOC_TR <-> BLUE_TR
set zone-policy zone BLUE_TR from SOC_TR  firewall name SOC-TO-BLUE
set zone-policy zone SOC_TR  from BLUE_TR firewall name BLUE-TO-SOC

# EMPLOY <-> IT
set zone-policy zone IT      from EMPLOY  firewall name EMPLOY-TO-IT
set zone-policy zone EMPLOY  from IT      firewall name IT-TO-EMPLOY

# MANAGE <-> IT
set zone-policy zone IT      from MANAGE  firewall name MANAGE-TO-IT
set zone-policy zone MANAGE  from IT      firewall name IT-TO-MANAGE
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
    print("  CN-ROUTER — VyOS Firewall Configuration")
    print("  (sostituisce CN-DMZFW-01 e CN-MISFW-01)")
    print("=" * 60)
    print("\n[INFO] Zone configurate:")
    zones = [
        (IF_BLUE_TR, "BLUE_TR", "Transit Blue Team (10.0.93.0/24)"),
        (IF_DMZ,     "DMZ",     "DMZ subnet (10.0.13.0/24)"),
        (IF_IT,      "IT",      "IT subnet (10.0.14.0/24)"),
        (IF_MANAGE,  "MANAGE",  "MANAGE subnet (10.1.21.0/24)"),
        (IF_EMPLOY,  "EMPLOY",  "EMPLOY subnet (10.2.150.0/24)"),
        (IF_SOC_TR,  "SOC_TR",  "Transit SecMon (10.0.94.0/24)"),
    ]
    for iface, zone, desc in zones:
        print(f"  {iface}  ->  {zone:<10} {desc}")

    print("\n[INFO] Regole chiave:")
    print("  DMZ-BAST-01 -> EMPLOY : RDP 3389, WinRM 5985/5986  [ALLOW]")
    print("  DMZ generica -> IT     :                             [DROP]")
    print("  DMZ generica -> MANAGE :                             [DROP]")
    print("  Blue Team -> tutte     : RDP 3389, SSH 22 (VPN-01)  [ALLOW]")
    print("  SecMon -> tutte        : tutto                       [ALLOW]")

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
