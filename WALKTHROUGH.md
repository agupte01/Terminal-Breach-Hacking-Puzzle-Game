# Terminal Breach — Detailed Walkthrough (v4.0)

Exact command sequences for all **35 levels**. Every sequence in this file is run against the real binary and checked to win cleanly: no wrong logins, no honeypots, and no sentinel catches. The *Peak* column is the highest detection reached on that clean line.

> **Spoilers.** Every password is below. Try each level yourself first and use `hint` if you get stuck (from L26 on, hints cost detection).

## How to read this

- Each `command` block can be typed exactly as shown. The note beside a step is what you should see.
- Lines like `connect host` may also be written with the IP. Both work.
- The inventory is cleared at every level transition, so `combine 1 2 3` always refers to the fragments you saved on that level, in order.
- **Sentinel sweeps** (L28, L31–L35) count *every* command, including typos and `status`. The sequences below are timed so you are never on a watched host when a sweep fires. If you add or skip a command, check `status` before entering a watched host.
- Practice any level directly: `TB_START_LEVEL=31 ./terminal_breach` (add `TB_FAST=1` to skip the typing animation).

## Quick reference

| # | Level | Difficulty | User password | Solution | Peak |
|---|---|---|---|---|---|
| 1 | [Tutorial System](#level-1--tutorial-system) | EASY | — | `beginner` | 0% |
| 2 | [Employee PC](#level-2--employee-pc) | EASY | — | `Sp3ctrum_42` | 0% |
| 3 | [Office Server](#level-3--office-server) | MEDIUM | `staff_2024` | `0ff1c3_@dm1n` | 0% |
| 4 | [Bank Network](#level-4--bank-network) | MEDIUM | `staff_access` | `$Bank_M@ster99` | 0% |
| 5 | [Secure Vault](#level-5--secure-vault) | HARD | — | `V@ULT_K3Y_7749` | 48% |
| 6 | [Darknet Node](#level-6--darknet-node) | HARD | `anon_user` | `d4rkn3t_gh0st` | 0% |
| 7 | [Prometheus Military Grid](#level-7--prometheus-military-grid) | HARD | — | `ZEPHYR-7-ECHO` | 0% |
| 8 | [AI Core System](#level-8--ai-core-system) | EXTREME | `AI_Guest01` | `NEURAL_0VERRIDE_7` | 90% |
| 9 | [Corporate Espionage](#level-9--corporate-espionage) | HARD | `h&r_staff` | `HELIOS_GENESIS` | 0% |
| 10 | [Power Grid Control](#level-10--power-grid-control) | HARD | `meridian_eng` | `GRID_SIGMA_04` | 0% |
| 11 | [Intelligence Agency](#level-11--intelligence-agency) | VERY HARD | `analyst_delta` | `MOLE_EXPOSED_11` | 0% |
| 12 | [Satellite Network](#level-12--satellite-network) | VERY HARD | `sat_technician` | `ORION_SAT_7721` | 0% |
| 13 | [Underground Market](#level-13--underground-market) | EXTREME | `market_vendor` | `SHADOWMARKET_KEY` | 68% |
| 14 | [Quantum Research Lab](#level-14--quantum-research-lab) | EXTREME | `lab_access_7` | `QUANTUM_BREACH_9` | 80% |
| 15 | [GHOST Protocol](#level-15--ghost-protocol) | LEGENDARY | `ghost_zero` | `ZERO_DAY_BLACKOUT` | 93% |
| 16 | [Crypto Exchange Heist](#level-16--crypto-exchange-heist) | MYTHIC | `trader_oa` | `ZEN1TH_C0LD_V@ULT` | 0% |
| 17 | [Industrial SCADA Sabotage](#level-17--industrial-scada-sabotage) | MYTHIC | `plc_op_3` | `SET_P01NT_OVERRIDE` | 0% |
| 18 | [Telecom Backbone Hijack](#level-18--telecom-backbone-hijack) | MYTHIC++ | `net_eng_99` | `BGP_HIJACK_PRIME` | 0% |
| 19 | [Spy Satellite Imagery Vault](#level-19--spy-satellite-imagery-vault) | APEX | `ground_op_7` | `KEYHOLE_RECON_X9` | 0% |
| 20 | [Forensic Counter-Hack](#level-20--forensic-counter-hack) | APEX | `ir_analyst` | `BURN_THE_C2_NOW` | 0% |
| 21 | [Darknet Auction](#level-21--darknet-auction) | APEX+ | `dn_bidder` | `Z3R0D@Y_W1NN3R` | 76% |
| 22 | [Black Site Dossier](#level-22--black-site-dossier) | LEGENDARY+ | `classified_a` | `BLACK_SITE_BURN_03` | 0% |
| 23 | [Pacemaker Killswitch](#level-23--pacemaker-killswitch) | LEGENDARY+ | `med_admin_x` | `K1LLSWITCH_ARMED` | 0% |
| 24 | [Cobalt Mirage Showdown](#level-24--cobalt-mirage-showdown) | LEGENDARY++ | `agent_apt` | `COBALT_M1RAGE_END` | 75% |
| 25 | [The Architect](#level-25--the-architect) | TRANSCENDENT | `architect_mirror` | `ARCH1TECT_DECOMM_INF` | 76% |
| 26 | [Lazarus Seed](#level-26--lazarus-seed) | OMEGA | `lazarus_hunter` | `LAZ4RUS_S33D_PURGE` | 0% |
| 27 | [Onion Relay](#level-27--onion-relay) | OMEGA | `tor_exit_9` | `0N10N_TR4P_D00R` | 0% |
| 28 | [Sentinel Grid](#level-28--sentinel-grid) | OMEGA+ | `grid_ghost` | `S3NT1NEL_BL1ND_SP0T` | 0% |
| 29 | [Silent Alarm](#level-29--silent-alarm) | OMEGA+ | `night_shift` | `QU13T_H4NDS_0NLY` | 50% |
| 30 | [Mirror Maze](#level-30--mirror-maze) | SINGULARITY | `maze_runner` | `M1RR0R_M4Z3_3X1T` | 0% |
| 31 | [Deadman's Vault](#level-31--deadmans-vault) | SINGULARITY | `vault_warden` | `D3ADM4N_SW1TCH_0FF` | 66% |
| 32 | [Hydra Botnet](#level-32--hydra-botnet) | SINGULARITY+ | `hydra_slayer` | `HYDR4_H3ADS_SEVERED` | 75% |
| 33 | [Quantum Ghost](#level-33--quantum-ghost) | EVENT HORIZON | `observer_zero` | `QU4NTUM_GH0ST_C0LL4PSE` | 0% |
| 34 | [Lazarus Core](#level-34--lazarus-core) | EVENT HORIZON+ | `final_witness` | `L4ZARUS_N3VER_R1SES` | 66% |
| 35 | [Zero Point](#level-35--zero-point) | ZERO POINT | `GHOST` | `GH0ST_1S_TH3_ARCH1TECT` | 70% |

---

## Act I — Breaking In

Levels 1–8 teach the basics: reading files, decrypting, scanning and connecting, the user-password tier, then `bruteforce` and `override`.

### Level 1 — Tutorial System

**Difficulty:** EASY · **Peak detection on this line:** 0%

Single node and no puzzles. You learn `ls`, `cat`, `ls -a` and `login` here.

| Step | Command | What happens |
|---:|---|---|
| 1 | `ls` | shows welcome.txt, readme.txt, system.log |
| 2 | `cat system.log` | the password is in a log entry |
| 3 | `ls -a` | optional: reveals .bash_history, which has `login beginner` in it |
| 4 | `login beginner` | level complete |

<details><summary>Copy-paste version</summary>

```
ls
cat system.log
ls -a
login beginner
```
</details>

### Level 2 — Employee PC

**Difficulty:** EASY · **Peak detection on this line:** 0%

Introduces `decrypt`. The message is just reversed text.

| Step | Command | What happens |
|---:|---|---|
| 1 | `decrypt message.enc` | Hi Jamie. Your password is the project code: Sp3ctrum_42. |
| 2 | `save Sp3ctrum_42` | optional inventory practice |
| 3 | `login Sp3ctrum_42` | level complete |

<details><summary>Copy-paste version</summary>

```
decrypt message.enc
save Sp3ctrum_42
login Sp3ctrum_42
```
</details>

### Level 3 — Office Server

**Difficulty:** MEDIUM · **Peak detection on this line:** 0%

First multi-node level and first user password.

| Step | Command | What happens |
|---:|---|---|
| 1 | `cat staff_memo.txt` | credential format is [role]_[year] |
| 2 | `login staff_2024` | USER access |
| 3 | `scan` | finds hr-server 172.16.0.20 |
| 4 | `connect 172.16.0.20` |  |
| 5 | `cat cipher_info.txt` | Caesar shift 13 |
| 6 | `decrypt config_backup.enc` | Root auth code: 0ff1c3_@dm1n |
| 7 | `login 0ff1c3_@dm1n` | level complete |

<details><summary>Copy-paste version</summary>

```
cat staff_memo.txt
login staff_2024
scan
connect 172.16.0.20
cat cipher_info.txt
decrypt config_backup.enc
login 0ff1c3_@dm1n
```
</details>

### Level 4 — Bank Network

**Difficulty:** MEDIUM · **Peak detection on this line:** 0%

The cipher key is in a separate file from the ciphertext.

| Step | Command | What happens |
|---:|---|---|
| 1 | `cat access_info.txt` | credential staff_access |
| 2 | `login staff_access` | USER access |
| 3 | `scan` |  |
| 4 | `connect 10.10.0.5` | vault-server |
| 5 | `cat cipher_key.txt` | shift 7 |
| 6 | `decrypt vault.enc` | master_code: $Bank_M@ster99 |
| 7 | `login $Bank_M@ster99` | level complete |

<details><summary>Copy-paste version</summary>

```
cat access_info.txt
login staff_access
scan
connect 10.10.0.5
cat cipher_key.txt
decrypt vault.enc
login $Bank_M@ster99
```
</details>

### Level 5 — Secure Vault

**Difficulty:** HARD · **Peak detection on this line:** 48%

Introduces `bruteforce` (costs 2× per-fail) and binary decoding. 300s timer.

| Step | Command | What happens |
|---:|---|---|
| 1 | `cat keypad.txt` | lock format |
| 2 | `bruteforce` | +24 detection, unlocks vault_access.txt |
| 3 | `cat vault_access.txt` | prefix V@ULT_K3Y_ |
| 4 | `decrypt system_dump.bin` | suffix 7749 |
| 5 | `login V@ULT_K3Y_7749` | level complete |

<details><summary>Copy-paste version</summary>

```
cat keypad.txt
bruteforce
cat vault_access.txt
decrypt system_dump.bin
login V@ULT_K3Y_7749
```
</details>

### Level 6 — Darknet Node

**Difficulty:** HARD · **Peak detection on this line:** 0%

Tiny detection budget: 40 max, and each wrong login costs 35. Get it right first time.

| Step | Command | What happens |
|---:|---|---|
| 1 | `cat welcome.onion` | base credential anon_user |
| 2 | `login anon_user` | USER access |
| 3 | `cat darknet_key.txt` | shift 17 |
| 4 | `decrypt encrypted_manifesto.enc` | The ghost protocol: d4rkn3t_gh0st |
| 5 | `login d4rkn3t_gh0st` | level complete |

<details><summary>Copy-paste version</summary>

```
cat welcome.onion
login anon_user
cat darknet_key.txt
decrypt encrypted_manifesto.enc
login d4rkn3t_gh0st
```
</details>

### Level 7 — Prometheus Military Grid

**Difficulty:** HARD · **Peak detection on this line:** 0%

Connect side-effect: reaching firebase unlocks the classified procedure.

| Step | Command | What happens |
|---:|---|---|
| 1 | `scan` | firebase 10.200.0.5, warhead-ctrl 10.200.0.99 |
| 2 | `connect 10.200.0.5` | classified.txt auto-unlocks |
| 3 | `cat classified.txt` | four-step procedure |
| 4 | `decrypt orders.enc` | ZEPHYR-7-ECHO |
| 5 | `connect 10.200.0.99` | warhead-ctrl |
| 6 | `login ZEPHYR-7-ECHO` | launch aborted, level complete |

<details><summary>Copy-paste version</summary>

```
scan
connect 10.200.0.5
cat classified.txt
decrypt orders.enc
connect 10.200.0.99
login ZEPHYR-7-ECHO
```
</details>

### Level 8 — AI Core System

**Difficulty:** EXTREME · **Peak detection on this line:** 90%

Introduces `override` (3× per-fail = 90 of 100). Don't use bruteforce here: the user password already gives USER, and bruteforce + override would exceed the budget. 180s timer.

| Step | Command | What happens |
|---:|---|---|
| 1 | `decrypt binary.sys` | fragment 1: NEURAL_ |
| 2 | `save NEURAL_` |  |
| 3 | `login AI_Guest01` | USER access |
| 4 | `scan` |  |
| 5 | `connect 10.0.0.2` | neural-net |
| 6 | `cat core_manual.txt` | shift 9 |
| 7 | `decrypt cipher_fragment.enc` | fragment 2: 0VERRIDE_ |
| 8 | `override` | +90 detection, unlocks .genesis_key |
| 9 | `cat .genesis_key` | fragment 3: 7 |
| 10 | `login NEURAL_0VERRIDE_7` | level complete |

<details><summary>Copy-paste version</summary>

```
decrypt binary.sys
save NEURAL_
login AI_Guest01
scan
connect 10.0.0.2
cat core_manual.txt
decrypt cipher_fragment.enc
override
cat .genesis_key
login NEURAL_0VERRIDE_7
```
</details>

> **Tip:** With 90/100 detection after the override, you can't afford a single wrong login.

---

## Act II — Going Deeper

Levels 9–15 spread keys and fragments across more nodes and tighten the timers and detection budgets.

### Level 9 — Corporate Espionage

**Difficulty:** HARD · **Peak detection on this line:** 0%

The cipher key and the ciphertext are on different nodes.

| Step | Command | What happens |
|---:|---|---|
| 1 | `cat staff_directory.txt` | department + role naming |
| 2 | `login h&r_staff` | USER access |
| 3 | `scan` |  |
| 4 | `connect 10.50.0.10` | records-srv |
| 5 | `cat cipher_protocol.txt` | shift 11 |
| 6 | `connect 10.50.0.25` | archive-srv |
| 7 | `decrypt project_code.enc` | HELIOS_GENESIS |
| 8 | `login HELIOS_GENESIS` | level complete |

<details><summary>Copy-paste version</summary>

```
cat staff_directory.txt
login h&r_staff
scan
connect 10.50.0.10
cat cipher_protocol.txt
connect 10.50.0.25
decrypt project_code.enc
login HELIOS_GENESIS
```
</details>

### Level 10 — Power Grid Control

**Difficulty:** HARD · **Peak detection on this line:** 0%

Four nodes, two fragments, 240s timer.

| Step | Command | What happens |
|---:|---|---|
| 1 | `cat engineer_memo.txt` | credential meridian_eng |
| 2 | `login meridian_eng` | USER access |
| 3 | `scan` |  |
| 4 | `connect 192.168.200.10` | scada-relay |
| 5 | `cat protocol_log.txt` | shift 6 |
| 6 | `decrypt grid_fragment.enc` | GRID_SIGMA |
| 7 | `connect 192.168.200.99` | emergency-backup |
| 8 | `decrypt suffix.bin` | 04 |
| 9 | `login GRID_SIGMA_04` | level complete |

<details><summary>Copy-paste version</summary>

```
cat engineer_memo.txt
login meridian_eng
scan
connect 192.168.200.10
cat protocol_log.txt
decrypt grid_fragment.enc
connect 192.168.200.99
decrypt suffix.bin
login GRID_SIGMA_04
```
</details>

### Level 11 — Intelligence Agency

**Difficulty:** VERY HARD · **Peak detection on this line:** 0%

Two-step decode chain: the first decoded file tells you the shift for the second.

| Step | Command | What happens |
|---:|---|---|
| 1 | `cat personnel_manifest.txt` | credential analyst_delta |
| 2 | `login analyst_delta` | USER access |
| 3 | `scan` |  |
| 4 | `connect 172.31.0.10` | ops-terminal |
| 5 | `decrypt shift_table.enc` | Director cipher protocol: shift 19 |
| 6 | `connect 172.31.0.50` | director-pc |
| 7 | `decrypt mole_file.enc` | MOLE_EXPOSED_11 |
| 8 | `login MOLE_EXPOSED_11` | level complete |

<details><summary>Copy-paste version</summary>

```
cat personnel_manifest.txt
login analyst_delta
scan
connect 172.31.0.10
decrypt shift_table.enc
connect 172.31.0.50
decrypt mole_file.enc
login MOLE_EXPOSED_11
```
</details>

### Level 12 — Satellite Network

**Difficulty:** VERY HARD · **Peak detection on this line:** 0%

Five nodes, a connect side-effect, 200s timer.

| Step | Command | What happens |
|---:|---|---|
| 1 | `cat operator_guide.txt` | credential sat_technician |
| 2 | `login sat_technician` | USER access |
| 3 | `scan` |  |
| 4 | `connect 10.77.0.20` | sat-hub |
| 5 | `cat partial_code.txt` | prefix ORION_SAT_ |
| 6 | `connect 10.77.0.30` | telemetry |
| 7 | `decrypt sat_dump.bin` | 7721 |
| 8 | `connect 10.77.0.99` | orion-core, override_code.txt auto-unlocks |
| 9 | `login ORION_SAT_7721` | level complete |

<details><summary>Copy-paste version</summary>

```
cat operator_guide.txt
login sat_technician
scan
connect 10.77.0.20
cat partial_code.txt
connect 10.77.0.30
decrypt sat_dump.bin
connect 10.77.0.99
login ORION_SAT_7721
```
</details>

### Level 13 — Underground Market

**Difficulty:** EXTREME · **Peak detection on this line:** 68%

Three fragments, bruteforce required on vendor-hub (and only there, since it's refused anywhere else).

| Step | Command | What happens |
|---:|---|---|
| 1 | `decrypt shadow.bin` | SHADOW |
| 2 | `cat welcome.onion` | credential market_vendor |
| 3 | `login market_vendor` | USER access |
| 4 | `scan` |  |
| 5 | `connect vendor-hub` |  |
| 6 | `bruteforce` | +24 detection, unlocks locked_comms.enc |
| 7 | `decrypt locked_comms.enc` | MARKET_ |
| 8 | `connect admin-vault` |  |
| 9 | `decrypt key.enc` | KEY |
| 10 | `login SHADOWMARKET_KEY` | level complete |

<details><summary>Copy-paste version</summary>

```
decrypt shadow.bin
cat welcome.onion
login market_vendor
scan
connect vendor-hub
bruteforce
decrypt locked_comms.enc
connect admin-vault
decrypt key.enc
login SHADOWMARKET_KEY
```
</details>

### Level 14 — Quantum Research Lab

**Difficulty:** EXTREME · **Peak detection on this line:** 80%

First level that needs both bruteforce and override. 200s timer.

| Step | Command | What happens |
|---:|---|---|
| 1 | `cat staff_access.txt` | credential lab_access_7 |
| 2 | `login lab_access_7` | USER access |
| 3 | `scan` |  |
| 4 | `connect lab-terminal` |  |
| 5 | `decrypt quantum.bin` | QUANTUM_ |
| 6 | `connect quantum-relay` |  |
| 7 | `bruteforce` | unlocks locked_manifest.txt |
| 8 | `cat locked_manifest.txt` | points you at quantum-core |
| 9 | `connect quantum-core` |  |
| 10 | `override` | unlocks .classified_key |
| 11 | `decrypt breach.enc` | BREACH_9 |
| 12 | `cat .classified_key` | confirms the full key |
| 13 | `login QUANTUM_BREACH_9` | level complete |

<details><summary>Copy-paste version</summary>

```
cat staff_access.txt
login lab_access_7
scan
connect lab-terminal
decrypt quantum.bin
connect quantum-relay
bruteforce
cat locked_manifest.txt
connect quantum-core
override
decrypt breach.enc
cat .classified_key
login QUANTUM_BREACH_9
```
</details>

### Level 15 — GHOST Protocol

**Difficulty:** LEGENDARY · **Peak detection on this line:** 93%

Six nodes, four fragments, bruteforce + override, 120s timer.

| Step | Command | What happens |
|---:|---|---|
| 1 | `cat zero_day.txt` | credential ghost_zero |
| 2 | `login ghost_zero` | USER access |
| 3 | `scan` |  |
| 4 | `connect fragment-alpha` |  |
| 5 | `decrypt zero.bin` | ZERO_ |
| 6 | `connect fragment-beta` |  |
| 7 | `bruteforce` | unlocks day.enc |
| 8 | `decrypt day.enc` | DAY_ |
| 9 | `connect fragment-delta` | blackout_info.txt auto-unlocks (shift 21) |
| 10 | `connect fragment-gamma` |  |
| 11 | `decrypt black.enc` | BLACK |
| 12 | `connect omega-core` |  |
| 13 | `override` | unlocks .deactivation_key |
| 14 | `cat .deactivation_key` | OUT and the full key |
| 15 | `login ZERO_DAY_BLACKOUT` | level complete |

<details><summary>Copy-paste version</summary>

```
cat zero_day.txt
login ghost_zero
scan
connect fragment-alpha
decrypt zero.bin
connect fragment-beta
bruteforce
decrypt day.enc
connect fragment-delta
connect fragment-gamma
decrypt black.enc
connect omega-core
override
cat .deactivation_key
login ZERO_DAY_BLACKOUT
```
</details>

---

## Act III — The Architect

Levels 16–25 add hex, XOR, Vigenère and Base64, routing chains, honeypots, `grep` forensics and `combine`, and end with adaptive detection.

### Level 16 — Crypto Exchange Heist

**Difficulty:** MYTHIC · **Peak detection on this line:** 0%

New ciphers: hex and XOR. `combine` assembles inventory fragments.

| Step | Command | What happens |
|---:|---|---|
| 1 | `login trader_oa` | USER access (from staff_memo.txt) |
| 2 | `scan` |  |
| 3 | `connect trading-engine` |  |
| 4 | `decrypt frag1.hex` | ZEN1TH_ |
| 5 | `save ZEN1TH_` |  |
| 6 | `connect hsm-bridge` |  |
| 7 | `decrypt frag2.xor` | C0LD_ |
| 8 | `save C0LD_` |  |
| 9 | `connect cold-vault` |  |
| 10 | `decrypt frag3.enc` | V@ULT |
| 11 | `save V@ULT` |  |
| 12 | `combine 1 2 3` | ZEN1TH_C0LD_V@ULT |
| 13 | `login ZEN1TH_C0LD_V@ULT` | level complete |

<details><summary>Copy-paste version</summary>

```
login trader_oa
scan
connect trading-engine
decrypt frag1.hex
save ZEN1TH_
connect hsm-bridge
decrypt frag2.xor
save C0LD_
connect cold-vault
decrypt frag3.enc
save V@ULT
combine 1 2 3
login ZEN1TH_C0LD_V@ULT
```
</details>

> **Tip:** The inventory is cleared at every level transition, so slot numbers always start at 1. `drop <n>` removes a mistaken `save` mid-level.

### Level 17 — Industrial SCADA Sabotage

**Difficulty:** MYTHIC · **Peak detection on this line:** 0%

Vigenère cipher plus a routing rule: plc-core only accepts sessions that came through historian.

| Step | Command | What happens |
|---:|---|---|
| 1 | `login plc_op_3` | USER access (login_banner.txt) |
| 2 | `scan` |  |
| 3 | `connect rtu-1` |  |
| 4 | `decrypt setpoint.vig` | SET_P01NT_ |
| 5 | `save SET_P01NT_` |  |
| 6 | `connect rtu-2` |  |
| 7 | `decrypt token.rev` | OVERRIDE |
| 8 | `save OVERRIDE` |  |
| 9 | `connect historian` | routing prerequisite |
| 10 | `connect plc-core` | accepted now |
| 11 | `combine 1 2` | SET_P01NT_OVERRIDE |
| 12 | `login SET_P01NT_OVERRIDE` | level complete |

<details><summary>Copy-paste version</summary>

```
login plc_op_3
scan
connect rtu-1
decrypt setpoint.vig
save SET_P01NT_
connect rtu-2
decrypt token.rev
save OVERRIDE
connect historian
connect plc-core
combine 1 2
login SET_P01NT_OVERRIDE
```
</details>

### Level 18 — Telecom Backbone Hijack

**Difficulty:** MYTHIC++ · **Peak detection on this line:** 0%

Base64 + hex + XOR. transit-core requires a prior bgp-reflector visit.

| Step | Command | What happens |
|---:|---|---|
| 1 | `login net_eng_99` | USER access |
| 2 | `scan` |  |
| 3 | `connect bgp-reflector` |  |
| 4 | `decrypt frag1.b64` | BGP_ |
| 5 | `save BGP_` |  |
| 6 | `connect transit-core` |  |
| 7 | `decrypt frag2.hex` | HIJACK_ |
| 8 | `save HIJACK_` |  |
| 9 | `connect peering-x` |  |
| 10 | `decrypt frag3.xor` | PRIME |
| 11 | `save PRIME` |  |
| 12 | `combine 1 2 3` |  |
| 13 | `login BGP_HIJACK_PRIME` | level complete |

<details><summary>Copy-paste version</summary>

```
login net_eng_99
scan
connect bgp-reflector
decrypt frag1.b64
save BGP_
connect transit-core
decrypt frag2.hex
save HIJACK_
connect peering-x
decrypt frag3.xor
save PRIME
combine 1 2 3
login BGP_HIJACK_PRIME
```
</details>

### Level 19 — Spy Satellite Imagery Vault

**Difficulty:** APEX · **Peak detection on this line:** 0%

Decoy: vault-B holds a stale fragment (7Q). Use vault-A.

| Step | Command | What happens |
|---:|---|---|
| 1 | `login ground_op_7` | USER access |
| 2 | `scan` |  |
| 3 | `connect uplink-relay` |  |
| 4 | `decrypt keyhole.vig` | KEYHOLE_ |
| 5 | `save KEYHOLE_` |  |
| 6 | `connect decryption-rig` |  |
| 7 | `decrypt recon.hex` | RECON_ |
| 8 | `save RECON_` |  |
| 9 | `connect vault-A` |  |
| 10 | `decrypt tail.rev` | X9 |
| 11 | `save X9` |  |
| 12 | `combine 1 2 3` |  |
| 13 | `login KEYHOLE_RECON_X9` | level complete |

<details><summary>Copy-paste version</summary>

```
login ground_op_7
scan
connect uplink-relay
decrypt keyhole.vig
save KEYHOLE_
connect decryption-rig
decrypt recon.hex
save RECON_
connect vault-A
decrypt tail.rev
save X9
combine 1 2 3
login KEYHOLE_RECON_X9
```
</details>

### Level 20 — Forensic Counter-Hack

**Difficulty:** APEX · **Peak detection on this line:** 0%

Introduces `grep`. The seconds field of the KEY_MISMATCH log line is the Caesar shift.

| Step | Command | What happens |
|---:|---|---|
| 1 | `login ir_analyst` | USER access |
| 2 | `scan` |  |
| 3 | `connect relay-honey` |  |
| 4 | `grep KEY_MISMATCH auth.log` | timestamp 03:14:09, so shift 9 |
| 5 | `connect attacker-relay` |  |
| 6 | `decrypt burn.enc` | BURN_THE_ |
| 7 | `save BURN_THE_` |  |
| 8 | `connect attacker-c2` |  |
| 9 | `decrypt c2.hex` | C2_NOW |
| 10 | `save C2_NOW` |  |
| 11 | `combine 1 2` |  |
| 12 | `login BURN_THE_C2_NOW` | level complete |

<details><summary>Copy-paste version</summary>

```
login ir_analyst
scan
connect relay-honey
grep KEY_MISMATCH auth.log
connect attacker-relay
decrypt burn.enc
save BURN_THE_
connect attacker-c2
decrypt c2.hex
save C2_NOW
combine 1 2
login BURN_THE_C2_NOW
```
</details>

### Level 21 — Darknet Auction

**Difficulty:** APEX+ · **Peak detection on this line:** 76%

Honeypots: escrow and buyer-mirror (2× per-fail each). Bruteforce + override required.

| Step | Command | What happens |
|---:|---|---|
| 1 | `login dn_bidder` | USER access |
| 2 | `scan` |  |
| 3 | `connect staging` |  |
| 4 | `bruteforce` | +40, unlocks hidden stake.locked |
| 5 | `decrypt stake.locked` | Z3R0D@Y_ |
| 6 | `save Z3R0D@Y_` |  |
| 7 | `connect payload-vault` |  |
| 8 | `override` | +60, unlocks .winner_frag |
| 9 | `decrypt .winner_frag` | W1NN3R |
| 10 | `save W1NN3R` |  |
| 11 | `combine 1 2` |  |
| 12 | `login Z3R0D@Y_W1NN3R` | level complete |

<details><summary>Copy-paste version</summary>

```
login dn_bidder
scan
connect staging
bruteforce
decrypt stake.locked
save Z3R0D@Y_
connect payload-vault
override
decrypt .winner_frag
save W1NN3R
combine 1 2
login Z3R0D@Y_W1NN3R
```
</details>

### Level 22 — Black Site Dossier

**Difficulty:** LEGENDARY+ · **Peak detection on this line:** 0%

Vigenère + binary + Caesar-23 in a 180s window.

| Step | Command | What happens |
|---:|---|---|
| 1 | `login classified_a` | USER access |
| 2 | `scan` |  |
| 3 | `connect vault-alpha` |  |
| 4 | `decrypt alpha.vig` | BLACK_ |
| 5 | `save BLACK_` |  |
| 6 | `connect vault-bravo` |  |
| 7 | `decrypt bravo.bin` | SITE_ |
| 8 | `save SITE_` |  |
| 9 | `connect vault-charlie` |  |
| 10 | `decrypt charlie.enc` | BURN_03 |
| 11 | `save BURN_03` |  |
| 12 | `combine 1 2 3` |  |
| 13 | `login BLACK_SITE_BURN_03` | level complete |

<details><summary>Copy-paste version</summary>

```
login classified_a
scan
connect vault-alpha
decrypt alpha.vig
save BLACK_
connect vault-bravo
decrypt bravo.bin
save SITE_
connect vault-charlie
decrypt charlie.enc
save BURN_03
combine 1 2 3
login BLACK_SITE_BURN_03
```
</details>

### Level 23 — Pacemaker Killswitch

**Difficulty:** LEGENDARY+ · **Peak detection on this line:** 0%

Six-hop routing chain: ER → ICU → imaging → pharmacy → mdm → pacemaker-net.

| Step | Command | What happens |
|---:|---|---|
| 1 | `login med_admin_x` | USER access |
| 2 | `scan` |  |
| 3 | `connect ER` |  |
| 4 | `decrypt kill.hex` | K1LLSWITCH_ |
| 5 | `save K1LLSWITCH_` |  |
| 6 | `connect ICU` |  |
| 7 | `connect imaging` |  |
| 8 | `connect pharmacy` |  |
| 9 | `decrypt armed.vig` | ARMED |
| 10 | `save ARMED` |  |
| 11 | `connect mdm` |  |
| 12 | `connect pacemaker-net` | end of the chain |
| 13 | `combine 1 2` |  |
| 14 | `login K1LLSWITCH_ARMED` | level complete |

<details><summary>Copy-paste version</summary>

```
login med_admin_x
scan
connect ER
decrypt kill.hex
save K1LLSWITCH_
connect ICU
connect imaging
connect pharmacy
decrypt armed.vig
save ARMED
connect mdm
connect pacemaker-net
combine 1 2
login K1LLSWITCH_ARMED
```
</details>

### Level 24 — Cobalt Mirage Showdown

**Difficulty:** LEGENDARY++ · **Peak detection on this line:** 75%

Three enclaves, bruteforce on enclave-b, override on phantom-c2. 180s.

| Step | Command | What happens |
|---:|---|---|
| 1 | `login agent_apt` | USER access |
| 2 | `scan` |  |
| 3 | `connect enclave-a` |  |
| 4 | `decrypt frag_a.b64` | COBALT_ |
| 5 | `save COBALT_` |  |
| 6 | `connect enclave-b` |  |
| 7 | `bruteforce` | +60 |
| 8 | `decrypt frag_b.locked` | M1RAGE_ |
| 9 | `save M1RAGE_` |  |
| 10 | `connect phantom-c2` |  |
| 11 | `override` | +90 |
| 12 | `decrypt .frag_c` | END |
| 13 | `save END` |  |
| 14 | `combine 1 2 3` |  |
| 15 | `login COBALT_M1RAGE_END` | level complete |

<details><summary>Copy-paste version</summary>

```
login agent_apt
scan
connect enclave-a
decrypt frag_a.b64
save COBALT_
connect enclave-b
bruteforce
decrypt frag_b.locked
save M1RAGE_
connect phantom-c2
override
decrypt .frag_c
save END
combine 1 2 3
login COBALT_M1RAGE_END
```
</details>

### Level 25 — The Architect

**Difficulty:** TRANSCENDENT · **Peak detection on this line:** 76%

Adaptive detection: repeating a command 3+ times in a row costs extra. Avoid shard-daleth (honeypot). 120s, 2 attempts.

| Step | Command | What happens |
|---:|---|---|
| 1 | `login architect_mirror` | USER access |
| 2 | `scan` |  |
| 3 | `connect shard-aleph` |  |
| 4 | `decrypt aleph.b64` | ARCH |
| 5 | `save ARCH` |  |
| 6 | `connect shard-beth` |  |
| 7 | `decrypt beth.hex` | 1TECT_ |
| 8 | `save 1TECT_` |  |
| 9 | `connect shard-gimel` |  |
| 10 | `bruteforce` | +80 |
| 11 | `decrypt mirror.locked` | DECOMM |
| 12 | `save DECOMM` |  |
| 13 | `connect architect-core` |  |
| 14 | `override` | +120 |
| 15 | `decrypt .final_frag` | _INF |
| 16 | `save _INF` |  |
| 17 | `combine 1 2 3 4` |  |
| 18 | `login ARCH1TECT_DECOMM_INF` | Act III complete. LAZARUS wakes. |

<details><summary>Copy-paste version</summary>

```
login architect_mirror
scan
connect shard-aleph
decrypt aleph.b64
save ARCH
connect shard-beth
decrypt beth.hex
save 1TECT_
connect shard-gimel
bruteforce
decrypt mirror.locked
save DECOMM
connect architect-core
override
decrypt .final_frag
save _INF
combine 1 2 3 4
login ARCH1TECT_DECOMM_INF
```
</details>

---

## Act IV — The Lazarus Protocol

Levels 26–35 add Atbash and rail fence, onion files, port knocking, keypads, log wiping, sentinel sweeps and silent-alarm tripwires, then put them all together.

### Level 26 — Lazarus Seed

**Difficulty:** OMEGA · **Peak detection on this line:** 0%

New: Atbash, rail fence, `wipe`, `drop`. `hint` now costs 10 detection.

| Step | Command | What happens |
|---:|---|---|
| 1 | `login lazarus_hunter` | USER access (welcome.txt) |
| 2 | `scan` |  |
| 3 | `connect seed-mirror-a` |  |
| 4 | `decrypt seed.atb` | LAZ4RUS_ |
| 5 | `save LAZ4RUS_` |  |
| 6 | `connect seed-mirror-b` |  |
| 7 | `decrypt seed.rail` | S33D_ (3 rails) |
| 8 | `save S33D_` |  |
| 9 | `connect audit-sink` | routing prerequisite for purge-console |
| 10 | `connect purge-console` |  |
| 11 | `decrypt purge.hex` | PURGE |
| 12 | `save PURGE` |  |
| 13 | `combine 1 2 3` | LAZ4RUS_S33D_PURGE |
| 14 | `login LAZ4RUS_S33D_PURGE` | level complete |

<details><summary>Copy-paste version</summary>

```
login lazarus_hunter
scan
connect seed-mirror-a
decrypt seed.atb
save LAZ4RUS_
connect seed-mirror-b
decrypt seed.rail
save S33D_
connect audit-sink
connect purge-console
decrypt purge.hex
save PURGE
combine 1 2 3
login LAZ4RUS_S33D_PURGE
```
</details>

> **Tip:** `wipe` only helps once you've actually taken detection. Wiping at 0% gains nothing.

### Level 27 — Onion Relay

**Difficulty:** OMEGA · **Peak detection on this line:** 0%

New: onion files (one layer per `decrypt`, `ls` shows `[ONI k/n]`) and port knocking. directory-auth is a honeypot.

| Step | Command | What happens |
|---:|---|---|
| 1 | `login tor_exit_9` | USER access |
| 2 | `scan` |  |
| 3 | `connect middle-relay` |  |
| 4 | `decrypt frag1.oni` | shell 1 Base64, which leaves reversed hex |
| 5 | `decrypt frag1.oni` | shell 2 reversal, which leaves hex |
| 6 | `decrypt frag1.oni` | shell 3 hex: 0N10N_ |
| 7 | `save 0N10N_` |  |
| 8 | `connect hidden-service` |  |
| 9 | `decrypt knock.rail` | knock exit-relay: 9001 9030 9050 |
| 10 | `knock exit-relay 9001` | 1/3 |
| 11 | `knock exit-relay 9030` | 2/3 |
| 12 | `knock exit-relay 9050` | firewall opened |
| 13 | `connect exit-relay` |  |
| 14 | `decrypt frag2.oni` | hex shell |
| 15 | `decrypt frag2.oni` | Atbash shell: TR4P_D00R |
| 16 | `save TR4P_D00R` |  |
| 17 | `combine 1 2` |  |
| 18 | `login 0N10N_TR4P_D00R` | level complete |

<details><summary>Copy-paste version</summary>

```
login tor_exit_9
scan
connect middle-relay
decrypt frag1.oni
decrypt frag1.oni
decrypt frag1.oni
save 0N10N_
connect hidden-service
decrypt knock.rail
knock exit-relay 9001
knock exit-relay 9030
knock exit-relay 9050
connect exit-relay
decrypt frag2.oni
decrypt frag2.oni
save TR4P_D00R
combine 1 2
login 0N10N_TR4P_D00R
```
</details>

> **Tip:** A wrong port resets the whole sequence and costs ½ per-fail. Connecting before the knock is finished costs ½ per-fail too.

### Level 28 — Sentinel Grid

**Difficulty:** OMEGA+ · **Peak detection on this line:** 0%

New: sentinel sweeps every 6 commands (watched: watchtower, patrol-hub) and keypads with escalating penalties.

| Step | Command | What happens |
|---:|---|---|
| 1 | `login grid_ghost` | USER access |
| 2 | `scan` |  |
| 3 | `connect camera-loop` |  |
| 4 | `grep PIN cam.log` | digit1=4 digit2=4 digit3=7 digit4=1, so 4471 |
| 5 | `connect vault-door` | sweep 1 passes here (unwatched) |
| 6 | `decrypt blind.vig` | BL1ND_ |
| 7 | `unlock spot.pin 4471` | click |
| 8 | `decrypt spot.pin` | SP0T |
| 9 | `connect watchtower` | watched: you have 4 commands before the next sweep |
| 10 | `decrypt watch.rail` | S3NT1NEL_ (4 rails) |
| 11 | `connect vault-door` | out before sweep 2 |
| 12 | `save S3NT1NEL_` |  |
| 13 | `save BL1ND_` |  |
| 14 | `save SP0T` |  |
| 15 | `combine 1 2 3` |  |
| 16 | `login S3NT1NEL_BL1ND_SP0T` | level complete |

<details><summary>Copy-paste version</summary>

```
login grid_ghost
scan
connect camera-loop
grep PIN cam.log
connect vault-door
decrypt blind.vig
unlock spot.pin 4471
decrypt spot.pin
connect watchtower
decrypt watch.rail
connect vault-door
save S3NT1NEL_
save BL1ND_
save SP0T
combine 1 2 3
login S3NT1NEL_BL1ND_SP0T
```
</details>

> **Tip:** Every command counts toward the sweep, including `ls`, `status` and typos. `status` shows how many commands are left. patrol-hub has nothing you need.

### Level 29 — Silent Alarm

**Difficulty:** OMEGA+ · **Peak detection on this line:** 50%

New: tripwire. The first connect to vault-core starts a 60s reverse trace (shown in the prompt as `[TRACE n]`).

| Step | Command | What happens |
|---:|---|---|
| 1 | `login night_shift` | USER access |
| 2 | `scan` |  |
| 3 | `connect security-office` |  |
| 4 | `grep keypad guard.log` | straight down the middle column, so 2580 |
| 5 | `connect locker-room` |  |
| 6 | `decrypt quiet.oni` | Base64 shell |
| 7 | `decrypt quiet.oni` | Atbash shell: QU13T_ |
| 8 | `save QU13T_` |  |
| 9 | `connect server-closet` |  |
| 10 | `decrypt hands.rail` | H4NDS_ |
| 11 | `save H4NDS_` |  |
| 12 | `connect antechamber` | needs server-closet first |
| 13 | `bruteforce` | +50, door released |
| 14 | `connect vault-core` | TRACE STARTS: 60 seconds |
| 15 | `unlock only.pin 2580` |  |
| 16 | `decrypt only.pin` | 0NLY |
| 17 | `save 0NLY` |  |
| 18 | `combine 1 2 3` |  |
| 19 | `login QU13T_H4NDS_0NLY` | level complete |

<details><summary>Copy-paste version</summary>

```
login night_shift
scan
connect security-office
grep keypad guard.log
connect locker-room
decrypt quiet.oni
decrypt quiet.oni
save QU13T_
connect server-closet
decrypt hands.rail
save H4NDS_
connect antechamber
bruteforce
connect vault-core
unlock only.pin 2580
decrypt only.pin
save 0NLY
combine 1 2 3
login QU13T_H4NDS_0NLY
```
</details>

> **Tip:** Prepare every other fragment before you touch vault-core. The trace keeps running after you leave.

### Level 30 — Mirror Maze

**Difficulty:** SINGULARITY · **Peak detection on this line:** 0%

Six identical-looking mirrors, three of them unlabelled honeypots (50 detection each).

| Step | Command | What happens |
|---:|---|---|
| 1 | `login maze_runner` | USER access |
| 2 | `grep TTL=1 dns.log` | mirror-b, mirror-d, mirror-e are spoofed sinkholes |
| 3 | `scan` |  |
| 4 | `connect mirror-a` |  |
| 5 | `decrypt m1.oni` | hex shell |
| 6 | `decrypt m1.oni` | reversal: M1RR0R_ |
| 7 | `save M1RR0R_` |  |
| 8 | `connect mirror-c` | needs mirror-a first |
| 9 | `decrypt maze.atb` | M4Z3_ |
| 10 | `save M4Z3_` |  |
| 11 | `decrypt knock.oni` | reversal shell |
| 12 | `decrypt knock.oni` | knock mirror-exit 4815 1623 4200 |
| 13 | `knock mirror-exit 4815` |  |
| 14 | `knock mirror-exit 1623` |  |
| 15 | `knock mirror-exit 4200` | opened |
| 16 | `connect mirror-exit` |  |
| 17 | `decrypt exit.rail` | 3X1T |
| 18 | `save 3X1T` |  |
| 19 | `combine 1 2 3` |  |
| 20 | `login M1RR0R_M4Z3_3X1T` | level complete |

<details><summary>Copy-paste version</summary>

```
login maze_runner
grep TTL=1 dns.log
scan
connect mirror-a
decrypt m1.oni
decrypt m1.oni
save M1RR0R_
connect mirror-c
decrypt maze.atb
save M4Z3_
decrypt knock.oni
decrypt knock.oni
knock mirror-exit 4815
knock mirror-exit 1623
knock mirror-exit 4200
connect mirror-exit
decrypt exit.rail
save 3X1T
combine 1 2 3
login M1RR0R_M4Z3_3X1T
```
</details>

### Level 31 — Deadman's Vault

**Difficulty:** SINGULARITY · **Peak detection on this line:** 66%

Sweeps every 7 (heartbeat-mon watched), PIN rotations, bruteforce + override, dead-drop honeypot.

| Step | Command | What happens |
|---:|---|---|
| 1 | `login vault_warden` | USER access |
| 2 | `scan` |  |
| 3 | `connect warden-log` |  |
| 4 | `grep ACTIVE warden.log` | PIN rotation 3: 7719 |
| 5 | `connect switch-room` |  |
| 6 | `bruteforce` | +50, unlocks switch.locked |
| 7 | `decrypt switch.locked` | Base64 shell; sweep 1 passes here (unwatched) |
| 8 | `connect heartbeat-mon` | watched: now 6 commands until sweep 2 |
| 9 | `decrypt pulse.vig` | D3ADM4N_ |
| 10 | `connect warden-log` | out |
| 11 | `wipe` | -25 |
| 12 | `save D3ADM4N_` |  |
| 13 | `connect switch-room` |  |
| 14 | `decrypt switch.locked` | hex shell: SW1TCH_; sweep 2 passes |
| 15 | `save SW1TCH_` |  |
| 16 | `unlock keyring.pin 7719` | optional intel |
| 17 | `connect vault-heart` | needs switch-room first |
| 18 | `override` | +75, unlocks .heart_frag |
| 19 | `decrypt .heart_frag` | 0FF |
| 20 | `save 0FF` |  |
| 21 | `combine 1 2 3` |  |
| 22 | `login D3ADM4N_SW1TCH_0FF` | level complete |

<details><summary>Copy-paste version</summary>

```
login vault_warden
scan
connect warden-log
grep ACTIVE warden.log
connect switch-room
bruteforce
decrypt switch.locked
connect heartbeat-mon
decrypt pulse.vig
connect warden-log
wipe
save D3ADM4N_
connect switch-room
decrypt switch.locked
save SW1TCH_
unlock keyring.pin 7719
connect vault-heart
override
decrypt .heart_frag
save 0FF
combine 1 2 3
login D3ADM4N_SW1TCH_0FF
```
</details>

> **Tip:** Only the [ACTIVE] PIN works. Wrong codes escalate (12, 24, 36…).

### Level 32 — Hydra Botnet

**Difficulty:** SINGULARITY+ · **Peak detection on this line:** 75%

Adaptive detection, sweeps every 8 (head-2 watched), routing head-1 → head-2 → head-4, knock + override. head-3 is a honeypot.

| Step | Command | What happens |
|---:|---|---|
| 1 | `login hydra_slayer` | USER access |
| 2 | `scan` |  |
| 3 | `connect head-1` |  |
| 4 | `decrypt h1.hex` | HYDR4_ |
| 5 | `save HYDR4_` |  |
| 6 | `connect c2-ledger` |  |
| 7 | `grep knock ledger.log` | 8080 then 4444 then 1337 |
| 8 | `knock hydra-heart 8080` | 1/3; sweep 1 passes on c2-ledger |
| 9 | `connect head-2` | watched: 7 commands until sweep 2 |
| 10 | `decrypt h2.rail` | H3ADS_ |
| 11 | `connect head-4` | needs head-2 first |
| 12 | `save H3ADS_` |  |
| 13 | `decrypt venom.oni` | Base64 shell |
| 14 | `decrypt venom.oni` | XOR shell: SEV |
| 15 | `save SEV` |  |
| 16 | `knock hydra-heart 4444` | 2/3 (knock progress is kept between other commands) |
| 17 | `knock hydra-heart 1337` | opened |
| 18 | `connect hydra-heart` |  |
| 19 | `override` | +90, unlocks .heart |
| 20 | `decrypt .heart` | ERED |
| 21 | `save ERED` |  |
| 22 | `connect c2-ledger` |  |
| 23 | `wipe` | -30 |
| 24 | `combine 1 2 3 4` |  |
| 25 | `login HYDR4_H3ADS_SEVERED` | level complete |

<details><summary>Copy-paste version</summary>

```
login hydra_slayer
scan
connect head-1
decrypt h1.hex
save HYDR4_
connect c2-ledger
grep knock ledger.log
knock hydra-heart 8080
connect head-2
decrypt h2.rail
connect head-4
save H3ADS_
decrypt venom.oni
decrypt venom.oni
save SEV
knock hydra-heart 4444
knock hydra-heart 1337
connect hydra-heart
override
decrypt .heart
save ERED
connect c2-ledger
wipe
combine 1 2 3 4
login HYDR4_H3ADS_SEVERED
```
</details>

> **Tip:** Three knocks in a row are fine. A 4th repeat of the same command would trigger the pattern penalty.

### Level 33 — Quantum Ghost

**Difficulty:** EVENT HORIZON · **Peak detection on this line:** 0%

Sweeps every 7 (entangle-b watched), knock + keypad riddle, superposition is alarmed (75s). schrodinger-box is a honeypot.

| Step | Command | What happens |
|---:|---|---|
| 1 | `login observer_zero` | USER access |
| 2 | `scan` |  |
| 3 | `connect entangle-a` |  |
| 4 | `decrypt qa.oni` | Base64 |
| 5 | `decrypt qa.oni` | reversal |
| 6 | `decrypt qa.oni` | hex: QU4NTUM_ |
| 7 | `save QU4NTUM_` |  |
| 8 | `connect decoherence-log` | sweep 1 passes |
| 9 | `grep knock q.log` | 6626, 1054, 2998 |
| 10 | `grep collapse q.log` | Fibonacci after 8 is 13, 21, so the PIN is 1321 |
| 11 | `connect entangle-b` | watched |
| 12 | `decrypt qb.oni` | rail-fence shell |
| 13 | `decrypt qb.oni` | Vigenère shell: GH0ST_ |
| 14 | `connect decoherence-log` | out before sweep 2 |
| 15 | `save GH0ST_` |  |
| 16 | `knock superposition 6626` |  |
| 17 | `knock superposition 1054` |  |
| 18 | `knock superposition 2998` | opened |
| 19 | `connect superposition` | TRACE STARTS: 75 seconds |
| 20 | `unlock collapse.pin 1321` |  |
| 21 | `decrypt collapse.pin` | Base64 |
| 22 | `decrypt collapse.pin` | Atbash: C0LL4PSE |
| 23 | `save C0LL4PSE` |  |
| 24 | `combine 1 2 3` |  |
| 25 | `login QU4NTUM_GH0ST_C0LL4PSE` | level complete |

<details><summary>Copy-paste version</summary>

```
login observer_zero
scan
connect entangle-a
decrypt qa.oni
decrypt qa.oni
decrypt qa.oni
save QU4NTUM_
connect decoherence-log
grep knock q.log
grep collapse q.log
connect entangle-b
decrypt qb.oni
decrypt qb.oni
connect decoherence-log
save GH0ST_
knock superposition 6626
knock superposition 1054
knock superposition 2998
connect superposition
unlock collapse.pin 1321
decrypt collapse.pin
decrypt collapse.pin
save C0LL4PSE
combine 1 2 3
login QU4NTUM_GH0ST_C0LL4PSE
```
</details>

### Level 34 — Lazarus Core

**Difficulty:** EVENT HORIZON+ · **Peak detection on this line:** 66%

Everything at once: 8 nodes, adaptive, sweeps every 6 (reliquary and lazarus-core watched), 60s trip, 2 attempts. Honeypots crypt-mirror and ghost-choir are only named in the log.

| Step | Command | What happens |
|---:|---|---|
| 1 | `login final_witness` | USER access |
| 2 | `scan` |  |
| 3 | `connect ossuary` |  |
| 4 | `grep DECOY lazarus.log` | crypt-mirror, ghost-choir |
| 5 | `grep gate lazarus.log` | knock 1666 6661 6616; PIN = Architect's level twice = 2525 |
| 6 | `knock soul-gate 1666` | 1/3; sweep 1 passes on ossuary |
| 7 | `connect reliquary` | watched: 5 commands until sweep 2 |
| 8 | `decrypt relic.oni` | Base64 |
| 9 | `decrypt relic.oni` | hex |
| 10 | `decrypt relic.oni` | Atbash: L4ZARUS_ |
| 11 | `connect resurrection-lab` | out before sweep 2 |
| 12 | `save L4ZARUS_` |  |
| 13 | `bruteforce` | +60 |
| 14 | `decrypt rebirth.locked` | N3VER_ |
| 15 | `save N3VER_` |  |
| 16 | `connect ossuary` |  |
| 17 | `wipe` | -30 |
| 18 | `knock soul-gate 6661` | 2/3 |
| 19 | `knock soul-gate 6616` | opened |
| 20 | `connect soul-gate` |  |
| 21 | `unlock gate.pin 2525` |  |
| 22 | `decrypt gate.pin` | R1 |
| 23 | `save R1` |  |
| 24 | `status` | sweep 4 passes here; 5 commands until the next one |
| 25 | `connect lazarus-core` | watched + TRACE 60s |
| 26 | `override` | +90 |
| 27 | `decrypt .core_frag` | SES |
| 28 | `connect soul-gate` | out before the next sweep |
| 29 | `save SES` |  |
| 30 | `combine 1 2 3 4` |  |
| 31 | `login L4ZARUS_N3VER_R1SES` | level complete |

<details><summary>Copy-paste version</summary>

```
login final_witness
scan
connect ossuary
grep DECOY lazarus.log
grep gate lazarus.log
knock soul-gate 1666
connect reliquary
decrypt relic.oni
decrypt relic.oni
decrypt relic.oni
connect resurrection-lab
save L4ZARUS_
bruteforce
decrypt rebirth.locked
save N3VER_
connect ossuary
wipe
knock soul-gate 6661
knock soul-gate 6616
connect soul-gate
unlock gate.pin 2525
decrypt gate.pin
save R1
status
connect lazarus-core
override
decrypt .core_frag
connect soul-gate
save SES
combine 1 2 3 4
login L4ZARUS_N3VER_R1SES
```
</details>

> **Tip:** Use cheap different commands (`status`, `whoami`, `inventory`) to shift the sweep phase without tripping the adaptive repeat penalty.

### Level 35 — Zero Point

**Difficulty:** ZERO POINT · **Peak detection on this line:** 70%

Final level: sweeps every 5 (memory-2 and origin watched), 90s trip on origin, adaptive, 2 attempts. The user credential is your own name.

| Step | Command | What happens |
|---:|---|---|
| 1 | `whoami` | Identity: GHOST |
| 2 | `login GHOST` | USER access |
| 3 | `scan` |  |
| 4 | `connect memory-1` |  |
| 5 | `grep echo origin.log` | decoys memory-3 and recursion |
| 6 | `grep gate origin.log` | knock 1010 0101 1111; PIN = 34 breached, twice = 3434 |
| 7 | `status` | filler to line up the sweep |
| 8 | `whoami` |  |
| 9 | `status` |  |
| 10 | `whoami` | sweep 2 passes on memory-1 |
| 11 | `connect memory-2` | watched: 4 commands max |
| 12 | `decrypt self.oni` | 1/4 |
| 13 | `decrypt self.oni` | 2/4 |
| 14 | `decrypt self.oni` | 3/4 |
| 15 | `connect memory-4` | leave! peel progress is kept |
| 16 | `bruteforce` | +70 |
| 17 | `decrypt self.locked` | 1S_ |
| 18 | `save 1S_` |  |
| 19 | `connect memory-1` |  |
| 20 | `wipe` | -35 |
| 21 | `knock origin-gate 1010` |  |
| 22 | `knock origin-gate 0101` |  |
| 23 | `knock origin-gate 1111` | opened |
| 24 | `status` |  |
| 25 | `whoami` | sweep passes on memory-1 |
| 26 | `connect memory-2` |  |
| 27 | `decrypt self.oni` | 4/4: GH0ST_ |
| 28 | `connect origin-gate` |  |
| 29 | `unlock core.pin 3434` |  |
| 30 | `decrypt core.pin` | TH3_ |
| 31 | `connect origin` | watched + TRACE 90s |
| 32 | `override` | +105 |
| 33 | `decrypt .origin_frag` | hex shell |
| 34 | `connect origin-gate` | out before the sweep |
| 35 | `save GH0ST_` |  |
| 36 | `connect origin` |  |
| 37 | `decrypt .origin_frag` | XOR shell: ARCH1TECT |
| 38 | `connect origin-gate` |  |
| 39 | `save TH3_` |  |
| 40 | `save ARCH1TECT` |  |
| 41 | `combine 2 1 3 4` | slot order: 1S_, GH0ST_, TH3_, ARCH1TECT |
| 42 | `login GH0ST_1S_TH3_ARCH1TECT` | GAME COMPLETE |

<details><summary>Copy-paste version</summary>

```
whoami
login GHOST
scan
connect memory-1
grep echo origin.log
grep gate origin.log
status
whoami
status
whoami
connect memory-2
decrypt self.oni
decrypt self.oni
decrypt self.oni
connect memory-4
bruteforce
decrypt self.locked
save 1S_
connect memory-1
wipe
knock origin-gate 1010
knock origin-gate 0101
knock origin-gate 1111
status
whoami
connect memory-2
decrypt self.oni
connect origin-gate
unlock core.pin 3434
decrypt core.pin
connect origin
override
decrypt .origin_frag
connect origin-gate
save GH0ST_
connect origin
decrypt .origin_frag
connect origin-gate
save TH3_
save ARCH1TECT
combine 2 1 3 4
login GH0ST_1S_TH3_ARCH1TECT
```
</details>

> **Tip:** A clean run ends around 70% detection. One sweep catch (35) or one wrong keypad code is survivable. Two usually aren't.

---

*Generated from the verified scripts. All 35 levels were also played back-to-back in a single session: 35/35 breached, 0 fails, rank GHOST LEGEND.*
