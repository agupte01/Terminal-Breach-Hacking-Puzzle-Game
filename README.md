# Terminal Breach v2.0

A terminal-based hacking puzzle game written in C. You play as **GHOST** — an elite black-hat operator working through 16 escalating network intrusion scenarios. Each level introduces new commands, tighter detection limits, multi-step puzzles, and higher stakes.

```
  ████████╗███████╗██████╗ ███╗   ███╗██╗███╗   ██╗ █████╗ ██╗
     ██╔══╝██╔════╝██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗██║
     ██║   █████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║███████║██║
     ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██╔══██║██║
     ██║   ███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██║  ██║███████╗
     ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝
  ██████╗ ██████╗ ███████╗ █████╗  ██████╗██╗  ██╗  v2.0
  ██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║
  ██████╔╝██████╔╝█████╗  ███████║██║     ███████║
  ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██║     ██╔══██║
  ██████╔╝██║  ██║███████╗██║  ██║╚██████╗██║  ██║
  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
```

---

## Table of Contents

- [Quick Start](#quick-start)
- [File Structure](#file-structure)
- [How the Game Works](#how-the-game-works)
  - [The Prompt](#the-prompt)
  - [Permission System](#permission-system)
  - [Detection System](#detection-system)
  - [Command Progression](#command-progression)
  - [Puzzle Types](#puzzle-types)
  - [Network Navigation](#network-navigation)
  - [Inventory System](#inventory-system)
  - [Timer System](#timer-system)
  - [Save / Load](#save--load)
  - [Scoring](#scoring)
  - [Ranks](#ranks)
- [All Commands](#all-commands)
- [Levels](#levels)
  - [Level 1 — Tutorial System](#level-1--tutorial-system-easy)
  - [Level 2 — Employee PC](#level-2--employee-pc-easy)
  - [Level 3 — Office Server](#level-3--office-server-medium)
  - [Level 4 — Bank Network](#level-4--bank-network-medium)
  - [Level 5 — Secure Vault](#level-5--secure-vault-hard)
  - [Level 6 — Darknet Node](#level-6--darknet-node-hard)
  - [Level 7 — Prometheus Military Grid](#level-7--prometheus-military-grid-hard)
  - [Level 8 — AI Core System](#level-8--ai-core-system-extreme)
  - [Level 9 — Corporate Espionage](#level-9--corporate-espionage-hard)
  - [Level 10 — Power Grid Control](#level-10--power-grid-control-hard)
  - [Level 11 — Intelligence Agency](#level-11--intelligence-agency-very-hard)
  - [Level 12 — Satellite Network](#level-12--satellite-network-very-hard)
  - [Level 13 — Underground Market](#level-13--underground-market-extreme)
  - [Level 14 — Quantum Research Lab](#level-14--quantum-research-lab-extreme)
  - [Level 15 — GHOST Protocol](#level-15--ghost-protocol-legendary)
- [Detection Math Reference](#detection-math-reference)
- [Adding New Levels](#adding-new-levels)

---

## Quick Start

**Requirements:** GCC and `make` (standard on Linux/macOS).

```bash
git clone <repo-url>
cd TerminalBreach
make
./terminal_breach
```

To rebuild from scratch:

```bash
make clean && make
```

---

## File Structure

```
TerminalBreach/
├── main.c          Game loop, boot sequence, win/loss screens, score
├── commands.c      All command handlers and the command dispatcher
├── commands.h      Command declarations and bitmask definitions
├── levels.c        All 16 level definitions with nodes, files, puzzles
├── levels.h        Core data structures: GameFile, NetworkNode, Level, GameState
├── network.c       Node navigation helpers, file unlock/decrypt bitmask logic
├── network.h       network.c public API
├── puzzles.c       Caesar cipher, reverse text, and binary decoders
├── puzzles.h       puzzles.c public API
├── utils.c         Detection bar, slow_print, boot sequence, mission briefing
├── utils.h         utils.c public API
├── save.c          Save/load game state to terminal_breach.sav
├── save.h          save.c public API
└── Makefile        Build configuration
```

**Build produces:** `terminal_breach` — a single self-contained binary with no runtime dependencies beyond the C standard library.

**Compiler flags:** `-Wall -Wextra -std=c11 -O2` — zero warnings.

---

## How the Game Works

### The Prompt

The prompt updates dynamically to reflect your current location and access level:

```
ghost@192.168.1.1[guest]:~$
ghost@172.16.0.20[user]:~$
ghost@10.200.0.99[root]:~$
```

Format: `ghost@<node-ip>[<permission>]:~$`

- `guest` — base access, limited file visibility
- `user` — elevated access, unlocks restricted files and secondary nodes
- `root` — admin access, granted on level completion

### Permission System

Three access tiers control what files you can read and which nodes you can connect to:

| Level  | Label | How to Obtain                     |
|--------|-------|-----------------------------------|
| GUEST  | guest | Default on every level start      |
| USER   | user  | `login <user_password>`           |
| ADMIN  | root  | `login <solution_password>` (wins level) |

Files and network nodes each have a `min_perm` requirement. Attempting to `cat` a USER-restricted file as GUEST returns `PERMISSION DENIED`. Attempting to `connect` to a USER-restricted node as GUEST is blocked and adds detection.

### Detection System

Every level has a detection meter — a visual bar that fills as you make mistakes. When it reaches 100%, the game ends:

```
  [DETECT] [████████████░░░░░░░░░░░░]  50%
```

Bar colour:
- Green — below 50%
- Yellow — 50%–79%
- Red — 80%+

**Actions that increase detection:**

| Action                             | Detection Cost             |
|------------------------------------|----------------------------|
| Wrong password (`login`)           | `detection_per_fail`       |
| Unknown command                    | `detection_per_fail / 4`   |
| Locked command used                | `detection_per_fail / 4`   |
| Failed `connect` (wrong host)      | `detection_per_fail / 2`   |
| Failed `connect` (insufficient perm) | `detection_per_fail / 2` |
| `bruteforce`                       | `detection_per_fail × 2`   |
| `override`                         | `detection_per_fail × 3`   |

When detection hits max: `[!!!] TRACE COMPLETE -- SYSTEM LOCKED` — session terminated, game over.

The bar is displayed after every detection-triggering action and via `status`.

### Command Progression

Commands unlock cumulatively as you advance through levels. You cannot use a command before it's unlocked — attempting it costs a small detection penalty and prints `COMMAND LOCKED`. New commands are announced at each level transition.

| Unlocked at Level | New Commands Added                                |
|-------------------|---------------------------------------------------|
| Level 1 (Tutorial)| `help`, `ls [-a]`, `cat`, `clear`, `whoami`, `status`, `hint`, `login`, `savegame`, `loadgame`, `exit` |
| Level 2 (Employee PC) | `logout`, `decrypt`, `save`, `inventory`      |
| Level 3 (Office Server) | `scan`, `connect`                           |
| Level 5 (Secure Vault) | `bruteforce`                                 |
| Level 7 (Prometheus) | `override`                                    |

### Puzzle Types

Three types of encoding are used across the levels:

**Caesar Cipher (`PUZZLE_CAESAR`)**
Each alphabetic character is shifted by a fixed number of positions. Non-alpha characters (digits, `@`, `_`, spaces) pass through unchanged. The shift value varies per level and is always hinted at in a nearby file.

Example — shift 13:
```
Plaintext : Root auth code: 0ff1c3_@dm1n
Encoded   : Ebbg nhgu pbqr: 0ss1p3_@qz1a
```

**Reverse Text (`PUZZLE_REVERSE`)**
The entire string is reversed character by character.

Example:
```
Plaintext : Hi Jamie. Your password is the project code: Sp3ctrum_42.
Encoded   : .24_murtc3pS :edoc tcejorp eht si drowssap ruoY .eimaJ iH
```

**Binary to ASCII (`PUZZLE_BINARY`)**
Space-separated 8-bit binary tokens are converted to their ASCII characters.

Example:
```
Encoded   : 00110111 00110111 00110100 00111001
Decoded   : 7749
```

All puzzles are solved using `decrypt <filename>`. The game auto-detects the encoding type and displays the decoded output. Once decrypted, `cat` on the same file also shows the decoded content.

### Network Navigation

Some levels span multiple machines. Each machine is a **network node** with its own IP address, hostname, and set of files.

```
scan              → discover all live hosts on the current segment
connect <ip>      → switch context to a discovered node
```

You start on the entry node each level. `scan` must be run before `connect` will work. Some nodes require USER-level access to connect — you'll be blocked as GUEST.

Connecting to certain nodes can have **side effects** — for example, connecting to the `firebase` node on Level 7 automatically unlocks the `classified.txt` file on that node.

Your current node IP is always shown in the prompt.

### Inventory System

You can store strings between commands using the inventory:

```
save <data>     → store a string (up to 20 items)
inventory       → list all stored items
```

Useful for noting partial passwords while navigating multi-node levels. Example:

```
ghost@10.0.0.1[guest]:~$ decrypt binary.sys
[+] DECODED: NEURAL_

ghost@10.0.0.1[guest]:~$ save NEURAL_
[+] Saved: "NEURAL_" (slot 1/20)
```

### Timer System

Two levels have countdown timers. If the timer expires, the session terminates immediately regardless of detection level:

```
[!!!] TIME EXPIRED -- session terminated.
```

The remaining time is always visible via `status`. Plan your commands before starting these levels.

### Save / Load

```
savegame    → writes progress to terminal_breach.sav
loadgame    → restores from terminal_breach.sav
```

The save file stores your current level, score, total fails, command count, and inventory. On load, the game transitions to the saved level so you resume exactly where you left off.

### Scoring

Score is calculated per level when you successfully `login` with the solution password:

```
Level score = (level_number × 1000) - (failed_attempts × 100) - (detection × 5)
```

Minimum level score is 0 (no negative contributions to total).

A perfect run with zero fails and zero detection scores **136,000 points** total.

Per-level base scores: L1=1000, L2=2000, … L8=8000, L9=9000, … L16=16000.

### Ranks

Your final rank is determined by total failed login attempts across all 16 levels:

| Total Fails | Rank                              |
|-------------|-----------------------------------|
| 0           | **GHOST LEGEND** — Flawless run!  |
| 1–3         | **PHANTOM** — Near perfect!       |
| 4–8         | **SPECTRE** — Well played.        |
| 9–15        | **AGENT** — Good effort.          |
| 16+         | **ROOKIE** — Keep training.       |

---

## All Commands

| Command            | Unlocked | Description                                     |
|--------------------|----------|-------------------------------------------------|
| `help`             | Level 1  | Show all currently available commands           |
| `ls`               | Level 1  | List files in the current node                  |
| `ls -a`            | Level 1  | List all files including hidden ones            |
| `cat <file>`       | Level 1  | Read a file's contents                          |
| `clear`            | Level 1  | Clear the terminal screen                       |
| `whoami`           | Level 1  | Display current identity and access level       |
| `status`           | Level 1  | Show level info, detection bar, timer, score    |
| `hint`             | Level 1  | Get a hint for the current level                |
| `login <password>` | Level 1  | Authenticate — user password or solution        |
| `exit` / `quit`    | Level 1  | Quit the game                                   |
| `savegame`         | Level 1  | Save current progress to file                   |
| `loadgame`         | Level 1  | Load progress from save file                    |
| `logout`           | Level 2  | Drop back to GUEST access                       |
| `decrypt <file>`   | Level 2  | Decode an encrypted file                        |
| `save <data>`      | Level 2  | Store a string in inventory                     |
| `inventory`        | Level 2  | List all stored inventory items                 |
| `scan`             | Level 3  | Discover all live hosts on the network segment  |
| `connect <ip>`     | Level 3  | Connect to a discovered host                    |
| `bruteforce`       | Level 5  | Force-bypass authentication (high detection!)   |
| `override`         | Level 7  | Override neural security (AI Core only, very high detection!) |

---

## Levels

### Level 1 — Tutorial System `EASY`

**Target:** `192.168.1.1` (tutorial-pc)
**Detection max:** 100 | **Per-fail cost:** 10 | **Max attempts:** 6

Your first machine. No puzzles, no timer, no network to navigate — just get comfortable with the interface.

**Files on node:**
- `welcome.txt` — introduction to the interface
- `readme.txt` — clues about the password format (8-letter word, synonym for novice)
- `system.log` — mentions "beginner" account type in plain sight
- `.bash_history` *(hidden — use `ls -a`)* — shows the exact login command used previously

**Password:** `beginner`

**Walkthrough:**
1. `ls` → read the visible files
2. `cat readme.txt` → clues about the password
3. `cat system.log` → password visible in log entry
4. *Optional:* `ls -a` → `.bash_history` shows `login beginner` directly
5. `login beginner` → level complete

---

### Level 2 — Employee PC `EASY`

**Target:** `10.0.0.42` (jamie-pc)
**Detection max:** 80 | **Per-fail cost:** 15 | **Max attempts:** 5
**New commands unlocked:** `decrypt`, `save`, `inventory`, `logout`

Jamie Chen's personal workstation. IT stored the project access code in a reverse-encoded file. Your first puzzle level.

**Files on node:**
- `readme.txt` — ownership notice
- `inbox.txt` — email from IT mentioning `message.enc`
- `about.txt` — employee info (project: Spectrum)
- `message.enc` *(reverse text puzzle)* — `".24_murtc3pS :edoc tcejorp eht si drowssap ruoY .eimaJ iH"`
- `.hidden_notes` *(hidden — use `ls -a`)* — contains the password directly

**Password:** `Sp3ctrum_42`

**Walkthrough:**
1. `ls` → see `message.enc`
2. `decrypt message.enc` → decoded: `Hi Jamie. Your password is the project code: Sp3ctrum_42.`
3. `save Sp3ctrum_42` *(optional — practice using inventory)*
4. `login Sp3ctrum_42` → level complete

---

### Level 3 — Office Server `MEDIUM`

**Target:** `172.16.0.10` (office-srv) + `172.16.0.20` (hr-server)
**Detection max:** 70 | **Per-fail cost:** 20 | **Max attempts:** 6
**New commands unlocked:** `scan`, `connect`

Thornfield Corp's internal network. You need USER-level access to reach the HR server, where an encrypted config backup holds the admin code. First multi-node level.

**Nodes:**
- `172.16.0.10` — office-srv *(entry)*
- `172.16.0.20` — hr-server *(requires USER to connect)*

**Key files:**
- `staff_memo.txt` — hints at password format `[role]_[year]`
- `system_info.txt` — mentions ROT-13 encryption standard
- `network_info.txt` *(USER only)* — confirms hr-server at `172.16.0.20`
- On hr-server: `cipher_info.txt` — confirms shift is 13
- On hr-server: `config_backup.enc` *(Caesar-13 puzzle)* — `"Ebbg nhgu pbqr: 0ss1p3_@qz1a"`

**User password:** `staff_2024`
**Solution password:** `0ff1c3_@dm1n`

**Walkthrough:**
1. `cat staff_memo.txt` → format is `[role]_[year]`
2. `login staff_2024` → USER access granted
3. `scan` → discover hr-server at `172.16.0.20`
4. `connect 172.16.0.20` → switch to hr-server
5. `cat cipher_info.txt` → shift = 13
6. `decrypt config_backup.enc` → decoded: `Root auth code: 0ff1c3_@dm1n`
7. `login 0ff1c3_@dm1n` → level complete

---

### Level 4 — Bank Network `MEDIUM`

**Target:** `10.10.0.1` (bank-gateway) + `10.10.0.5` (vault-server)
**Detection max:** 60 | **Per-fail cost:** 25 | **Max attempts:** 5

Iron Bank's internal network. Higher stakes, tighter detection. The vault master code is encrypted on the vault node — you need employee credentials to reach it.

**Nodes:**
- `10.10.0.1` — bank-gateway *(entry)*
- `10.10.0.5` — vault-server *(requires USER to connect)*

**Key files:**
- `access_info.txt` — staff default credential is `staff_access`
- `network_map.txt` *(USER only)* — shows vault-server at `10.10.0.5`
- On vault-server: `cipher_key.txt` — shift = 7
- On vault-server: `vault.enc` *(Caesar-7 puzzle)* — `"thzaly_jvkl: $Ihur_T@zaly99"`

**User password:** `staff_access`
**Solution password:** `$Bank_M@ster99`

**Walkthrough:**
1. `cat access_info.txt` → credential is `staff_access`
2. `login staff_access` → USER access granted
3. `scan` → discover vault-server at `10.10.0.5`
4. `connect 10.10.0.5` → switch to vault-server
5. `cat cipher_key.txt` → shift = 7
6. `decrypt vault.enc` → decoded: `master_code: $Bank_M@ster99`
7. `login $Bank_M@ster99` → level complete

---

### Level 5 — Secure Vault `HARD`

**Target:** `192.168.99.1` (vault-entry)
**Detection max:** 50 | **Per-fail cost:** 12 | **Max attempts:** 4 | **Timer:** 300s
**New commands unlocked:** `bruteforce`

A high-security standalone vault system with a countdown timer. The password is split across two sources — you must use `bruteforce` to unlock one part and decode a binary dump for the other, then combine them.

**Key files:**
- `warning.txt` — confirms 300s timer and max sensitivity
- `keypad.txt` — explains the lock format: `[PREFIX]_K3Y_[4 digits]`
- `system_dump.bin` *(binary puzzle)* — `"00110111 00110111 00110100 00111001"` → decodes to `7749`
- `vault_access.txt` *(locked until bruteforce used)* — reveals prefix `V@ULT_K3Y_`

**Solution password:** `V@ULT_K3Y_7749`

**Detection note:** `bruteforce` costs 24 detection (detection_per_fail × 2 = 12 × 2). With a max of 50, you can survive it but have little room for login mistakes afterward.

**Walkthrough:**
1. `cat keypad.txt` → understand the lock format
2. `bruteforce` → costs 24 detection; unlocks `vault_access.txt`
3. `cat vault_access.txt` → prefix: `V@ULT_K3Y_`
4. `decrypt system_dump.bin` → suffix: `7749`
5. `login V@ULT_K3Y_7749` → level complete

---

### Level 6 — Darknet Node `HARD`

**Target:** `10.13.37.1` (darknet-node)
**Detection max:** 40 | **Per-fail cost:** 35 | **Max attempts:** 4

The darknet level. One wrong login = 35 detection out of 40 max. You have essentially no margin for error. The base credentials are left in a public file — the challenge is reading carefully, finding the cipher key, and executing flawlessly.

**Key files:**
- `welcome.onion` — base credentials visible: `anon_user`
- `darknet_key.txt` *(USER only)* — cipher shift = 17
- `encrypted_manifesto.enc` *(USER + Caesar-17 puzzle)* — `"Kyv xyfjk gifkftfc: u4ibe3k_xy0jk"`
- `access_log.txt` — warns about 3-failure lockout

**User password:** `anon_user`
**Solution password:** `d4rkn3t_gh0st`

**Walkthrough:**
1. `cat welcome.onion` → base credential is `anon_user`
2. `login anon_user` → USER access granted
3. `cat darknet_key.txt` → shift = 17
4. `decrypt encrypted_manifesto.enc` → decoded: `The ghost protocol: d4rkn3t_gh0st`
5. `login d4rkn3t_gh0st` → level complete

---

### Level 7 — Prometheus Military Grid `HARD`

**Target:** `10.200.0.1` (prometheus) + `10.200.0.5` (firebase) + `10.200.0.99` (warhead-ctrl)
**Detection max:** 60 | **Per-fail cost:** 20 | **Max attempts:** 3
**New commands unlocked:** `override` *(available, but only functional on Level 8)*

A three-node military network. No user password — you navigate purely through network connections. Connecting to `firebase` is a prerequisite and automatically unlocks a classified document with the full procedure. The encoded codename is on firebase; the final login is on warhead-ctrl.

**Nodes:**
- `10.200.0.1` — prometheus *(entry)*
- `10.200.0.5` — firebase *(scan-discoverable)*
- `10.200.0.99` — warhead-ctrl *(scan-discoverable)*

**Key files:**
- `personnel.txt` — reveals codename format: `[WORD]-[DIGIT]-[NATO phonetic]`
- On firebase: `classified.txt` *(locked — auto-unlocked when you connect to firebase)*
- On firebase: `orders.enc` *(Caesar-3 puzzle)* — `"CHSKBU-7-HFKR"`
- On warhead-ctrl: `system_status.txt` — confirms launch countdown, authentication required

**Solution password:** `ZEPHYR-7-ECHO`

**Walkthrough:**
1. `scan` → discover firebase (`10.200.0.5`) and warhead-ctrl (`10.200.0.99`)
2. `connect 10.200.0.5` → firebase; `classified.txt` auto-unlocked
3. `cat classified.txt` → full 4-step procedure
4. `decrypt orders.enc` → decoded: `ZEPHYR-7-ECHO`
5. `connect 10.200.0.99` → switch to warhead-ctrl
6. `login ZEPHYR-7-ECHO` → launch aborted, level complete

---

### Level 8 — AI Core System `EXTREME`

**Target:** `10.0.0.1` (ai-core) + `10.0.0.2` (neural-net)
**Detection max:** 100 | **Per-fail cost:** 30 | **Max attempts:** 3 | **Timer:** 180s

Three password fragments scattered across two nodes. Collect and assemble them:

| Fragment | Source             | Method            | Result     |
|----------|--------------------|-------------------|------------|
| 1        | `binary.sys`       | Binary decode     | `NEURAL_`  |
| 2        | `cipher_fragment.enc` | Caesar-9 decrypt | `0VERRIDE_` |
| 3        | `.genesis_key`     | Override + `ls -a` | `7`        |

**Nodes:**
- `10.0.0.1` — ai-core *(entry)*
- `10.0.0.2` — neural-net *(requires USER to connect)*

**Key files:**
- `ai_boot.txt` — reveals guest credential: `AI_Guest01`
- `system_manual.txt` — explains the three-fragment system
- `binary.sys` *(binary puzzle)* — `"01001110 01000101 01010101 01010010 01000001 01001100 01011111"` → `NEURAL_`
- On neural-net: `core_manual.txt` — cipher shift = 9
- On neural-net: `cipher_fragment.enc` *(Caesar-9 puzzle)* — `"0ENAARMN_"` → `0VERRIDE_`
- On neural-net: `.genesis_key` *(hidden + locked — requires `override`)* — `Final fragment: 7`

**User password:** `AI_Guest01`
**Solution password:** `NEURAL_0VERRIDE_7`

**Detection note:** `override` costs 90 detection (detection_per_fail × 3 = 30 × 3). This is unavoidable — it's a required step. With a max of 100, you can survive it but a login mistake afterward will end the run.

**Walkthrough:**
1. `decrypt binary.sys` → fragment 1: `NEURAL_`
2. `save NEURAL_` *(recommended — note it for later)*
3. `login AI_Guest01` → USER access granted
4. `scan` → discover neural-net at `10.0.0.2`
5. `connect 10.0.0.2` → switch to neural-net
6. `cat core_manual.txt` → shift = 9
7. `decrypt cipher_fragment.enc` → fragment 2: `0VERRIDE_`
8. `override` → costs 90 detection; unlocks `.genesis_key`
9. `ls -a` → see hidden `.genesis_key`
10. `cat .genesis_key` → fragment 3: `7`
11. `login NEURAL_0VERRIDE_7` → **YOU WIN**

---

### Level 9 — Corporate Espionage `HARD`

**Target:** `10.50.0.1` (firm-gateway) + `10.50.0.10` (records-srv) + `10.50.0.25` (archive-srv)
**Detection max:** 55 | **Per-fail cost:** 18 | **Max attempts:** 5

Law firm Harrington & Reed holds stolen biotech IP. The project codename is encrypted on `archive-srv` — but the cipher key (shift 11) lives on `records-srv`. First time you must *carry information across a hop* before you can decrypt.

**Nodes:**
- `10.50.0.1` — firm-gateway *(entry)*
- `10.50.0.10` — records-srv *(requires USER)*
- `10.50.0.25` — archive-srv *(requires USER)*

**Key files:**
- `reception.txt` — staff account format: `h&r_[role]`
- `staff_directory.txt` — role "staff" listed
- On records-srv: `cipher_protocol.txt` — confirms shift = 11
- On archive-srv: `project_code.enc` *(Caesar-11)* — `"SPWTZD_RPYPDTD"`

**User password:** `h&r_staff`
**Solution password:** `HELIOS_GENESIS`

**Walkthrough:**
1. `cat reception.txt` + `cat staff_directory.txt` → deduce `h&r_staff`
2. `login h&r_staff` → USER access
3. `scan` → discover records-srv and archive-srv
4. `connect 10.50.0.10` → records-srv; `cat cipher_protocol.txt` → shift = 11
5. `connect 10.50.0.25` → archive-srv
6. `decrypt project_code.enc` → decoded: `HELIOS_GENESIS`
7. `login HELIOS_GENESIS` → level complete

---

### Level 10 — Power Grid Control `HARD`

**Target:** `192.168.200.1` (meridian-hq) + 3 subsystem nodes
**Detection max:** 50 | **Per-fail cost:** 15 | **Max attempts:** 5 | **Timer:** 240s

Meridian Energy's SCADA system is 4 minutes from a cascading blackout. The override code is assembled from two decoded fragments on separate nodes: a Caesar-6 word from `scada-relay` and a binary 2-digit suffix from `emergency-backup`.

**Nodes:**
- `192.168.200.1` — meridian-hq *(entry)*
- `192.168.200.10` — scada-relay *(requires USER)*
- `192.168.200.20` — grid-ctrl *(requires USER)*
- `192.168.200.99` — emergency-backup *(requires USER)*

**Key files:**
- `engineer_memo.txt` — format `meridian_[role]`, role is `eng`
- On scada-relay: `protocol_log.txt` — shift = 6; `grid_fragment.enc` *(Caesar-6)*
- On emergency-backup: `suffix.bin` *(binary)* → `04`

**User password:** `meridian_eng`
**Solution password:** `GRID_SIGMA_04`

**Walkthrough:**
1. `cat engineer_memo.txt` → `meridian_eng`
2. `login meridian_eng` → USER; `status` → check timer
3. `scan` → discover all 3 subsystem nodes
4. `connect 192.168.200.10` → scada-relay; `cat protocol_log.txt` → shift 6
5. `decrypt grid_fragment.enc` → `GRID_SIGMA`; `save GRID_SIGMA`
6. `connect 192.168.200.99` → emergency-backup
7. `decrypt suffix.bin` → `04`; combine → `GRID_SIGMA_04`
8. `login GRID_SIGMA_04` → level complete

---

### Level 11 — Intelligence Agency `VERY HARD`

**Target:** `172.31.0.1` (cipher-gateway) + 3 nodes
**Detection max:** 45 | **Per-fail cost:** 22 | **Max attempts:** 4

CIPHER Bureau has a mole leaking field agent identities. The two-step decode chain: decrypting `shift_table.enc` (reverse text) on `ops-terminal` reveals shift 19, which you then use to decrypt `mole_file.enc` (Caesar-19) on `director-pc`. Two wrong logins = game over.

**Nodes:**
- `172.31.0.1` — cipher-gateway *(entry)*
- `172.31.0.10` — ops-terminal *(requires USER)*
- `172.31.0.20` — records-vault *(requires USER)*
- `172.31.0.50` — director-pc *(requires USER)*

**Key files:**
- `personnel_manifest.txt` — role `delta`; password deducible as `analyst_delta`
- On ops-terminal: `shift_table.enc` *(reverse)* → `"Director cipher protocol: shift 19"`
- On director-pc: `mole_file.enc` *(Caesar-19)* → `MOLE_EXPOSED_11`

**User password:** `analyst_delta`
**Solution password:** `MOLE_EXPOSED_11`

**Detection note:** Per-fail = 22 on a 45 max. Two login failures = 44/45 — effectively game over.

**Walkthrough:**
1. `cat personnel_manifest.txt` → `analyst_delta`
2. `login analyst_delta` → USER
3. `scan` → discover all nodes
4. `connect 172.31.0.10` → ops-terminal; `decrypt shift_table.enc` → `Director cipher protocol: shift 19`; `save 19`
5. `connect 172.31.0.50` → director-pc
6. `decrypt mole_file.enc` → `MOLE_EXPOSED_11`
7. `login MOLE_EXPOSED_11` → level complete

---

### Level 12 — Satellite Network `VERY HARD`

**Target:** `10.77.0.1` (ground-ctrl) + 4 nodes
**Detection max:** 40 | **Per-fail cost:** 20 | **Max attempts:** 4 | **Timer:** 200s

ORION satellite array is being hijacked. Five-node level requiring a three-part password assembly: prefix from `sat-hub`, binary suffix from `telemetry`, with `orion-core` auto-unlocking `override_code.txt` on connect (confirming the format).

**Nodes:**
- `10.77.0.1` — ground-ctrl *(entry)*
- `10.77.0.10` — comms-relay *(requires USER)*
- `10.77.0.20` — sat-hub *(requires USER)*
- `10.77.0.30` — telemetry *(requires USER)*
- `10.77.0.99` — orion-core *(requires USER; connecting unlocks `override_code.txt`)*

**Key files:**
- `operator_guide.txt` — credential: `sat_technician`
- On sat-hub: `partial_code.txt` *(USER only)* — prefix `ORION_SAT_`
- On telemetry: `sat_dump.bin` *(binary)* → `7721`
- On orion-core: `override_code.txt` *(auto-unlocked on connect)* — confirms format

**User password:** `sat_technician`
**Solution password:** `ORION_SAT_7721`

**Walkthrough:**
1. `cat operator_guide.txt` → `sat_technician`; `login sat_technician`; `status` → timer
2. `scan` → all 4 non-entry nodes
3. `connect 10.77.0.10` → comms-relay *(optional — cipher_standard.txt lore)*
4. `connect 10.77.0.20` → sat-hub; `cat partial_code.txt` → `ORION_SAT_`; `save ORION_SAT_`
5. `connect 10.77.0.30` → telemetry; `decrypt sat_dump.bin` → `7721`; `save 7721`
6. `connect 10.77.0.99` → orion-core; `override_code.txt` auto-unlocked (connect side-effect)
7. `login ORION_SAT_7721` → level complete

---

### Level 13 — Underground Market `EXTREME`

**Target:** `10.dark.0.1` (market-entry) + 3 nodes
**Detection max:** 35 | **Per-fail cost:** 12 | **Max attempts:** 3

SHADOWMARKET darknet marketplace. The admin master key is split into three fragments across three puzzle types. Fragment 2 is locked behind `bruteforce` — the only way to unlock it. With 35 detection and 12 per-fail, one wrong login after bruteforce leaves you with 11 detection left. Zero room.

**Nodes:**
- `10.dark.0.1` — market-entry *(entry)*
- `10.dark.0.10` — vendor-hub *(requires USER)*
- `10.dark.0.20` — escrow-srv *(requires USER)*
- `10.dark.0.50` — admin-vault *(requires USER)*

| Fragment | Node | File | Puzzle | Result |
|----------|------|------|--------|--------|
| 1 | market-entry | `shadow.bin` | Binary | `SHADOW` |
| 2 | vendor-hub | `locked_comms.enc` | Reverse + bruteforce | `MARKET_` |
| 3 | admin-vault | `key.enc` | Caesar-23 | `KEY` |

**Detection note:** `bruteforce` costs 24 (12 × 2). After bruteforce you have 11 detection left — one wrong login = game over.

**User password:** `market_vendor`
**Solution password:** `SHADOWMARKET_KEY`

**Walkthrough:**
1. `decrypt shadow.bin` → `SHADOW`; `save SHADOW`
2. `cat welcome.onion` → `market_vendor`; `login market_vendor` → USER
3. `scan` → discover all nodes
4. `connect 10.dark.0.10` → vendor-hub; `cat cipher_note.txt` → shift 23
5. `bruteforce` → costs 24 detection; `locked_comms.enc` unlocked
6. `decrypt locked_comms.enc` → `MARKET_`; `save MARKET_`
7. `connect 10.dark.0.50` → admin-vault
8. `decrypt key.enc` → `KEY`
9. `login SHADOWMARKET_KEY` → level complete

---

### Level 14 — Quantum Research Lab `EXTREME`

**Target:** `10.nova.0.1` (research-hq) + 4 nodes
**Detection max:** 50 | **Per-fail cost:** 8 | **Max attempts:** 3 | **Timer:** 200s

NovaTech Quantum's facility holds experiment BREACH. **First level requiring both `bruteforce` and `override`.** Bruteforce on `quantum-relay` unlocks a manifest pointing you to override on `quantum-core` to unlock `.classified_key`. Detection is calibrated so both mandatory actions consume 40 of 50 — one wrong login is nearly lethal.

**Nodes:**
- `10.nova.0.1` — research-hq *(entry)*
- `10.nova.0.10` — lab-terminal *(requires USER)*
- `10.nova.0.20` — data-core *(requires USER)*
- `10.nova.0.30` — quantum-relay *(requires USER; `bruteforce` unlocks `locked_manifest.txt`)*
- `10.nova.0.99` — quantum-core *(requires USER; `override` unlocks `.classified_key`)*

**Key files:**
- `staff_access.txt` — credential: `lab_access_7`
- On lab-terminal: `quantum.bin` *(binary)* → `QUANTUM_`
- On data-core: `cipher_spec.txt` — shift = 23
- On quantum-relay: `locked_manifest.txt` *(locked — bruteforce required)* — confirms override on quantum-core
- On quantum-core: `breach.enc` *(Caesar-23)* → `BREACH_9`; `.classified_key` *(hidden + locked — override required)*

**Detection note:** Bruteforce = 16 (8 × 2), override = 24 (8 × 3). Total mandatory = 40/50. One wrong login (8) → 48/50. A second login mistake = game over.

**User password:** `lab_access_7`
**Solution password:** `QUANTUM_BREACH_9`

**Walkthrough:**
1. `cat staff_access.txt` → `lab_access_7`; `login lab_access_7`; `status` → timer
2. `scan` → all 4 non-entry nodes
3. `connect 10.nova.0.10` → lab-terminal; `decrypt quantum.bin` → `QUANTUM_`; `save QUANTUM_`
4. `connect 10.nova.0.20` → data-core; `cat cipher_spec.txt` → shift 23
5. `connect 10.nova.0.30` → quantum-relay; `bruteforce` → `locked_manifest.txt` unlocked; read it → confirms override on quantum-core
6. `connect 10.nova.0.99` → quantum-core; `override` → `.classified_key` unlocked
7. `decrypt breach.enc` → `BREACH_9`; `ls -a` → see `.classified_key`; `cat .classified_key` → confirms `QUANTUM_BREACH_9`
8. `login QUANTUM_BREACH_9` → level complete

---

### Level 15 — GHOST Protocol `LEGENDARY`

**Target:** `0.zero.0.1` (day-zero-entry) + 5 nodes
**Detection max:** 80 | **Per-fail cost:** 15 | **Max attempts:** 3 | **Timer:** 120s

**ZERO DAY.** A state-sponsored logic bomb is buried in global financial clearing infrastructure. It triggers in 2 minutes. Four fragments across 5 nodes, three puzzle types, mandatory `bruteforce` AND `override`. Both mandatory actions together cost 75 of 80 detection — **one wrong login ends the run.** This is the final level.

**Nodes:**
- `0.zero.0.1` — day-zero-entry *(entry)*
- `0.zero.0.10` — fragment-alpha *(requires USER)*
- `0.zero.0.20` — fragment-beta *(requires USER; `bruteforce` unlocks `day.enc`)*
- `0.zero.0.30` — fragment-gamma *(requires USER)*
- `0.zero.0.40` — fragment-delta *(requires USER; connecting auto-unlocks `blackout_info.txt`)*
- `0.zero.0.99` — omega-core *(requires USER; `override` unlocks `.deactivation_key`)*

| Fragment | Node | File | Puzzle | Result |
|----------|------|------|--------|--------|
| 1 | fragment-alpha | `zero.bin` | Binary | `ZERO_` |
| 2 | fragment-beta | `day.enc` | Reverse + bruteforce | `DAY_` |
| 3 | fragment-gamma | `black.enc` | Caesar-21 | `BLACK` |
| 4 | omega-core | `.deactivation_key` | Override + `ls -a` | `OUT` |

**Detection budget:**

| Action | Cost | Running total |
|--------|------|---------------|
| `bruteforce` on fragment-beta | 30 (15 × 2) | 30/80 |
| `override` on omega-core | 45 (15 × 3) | 75/80 |
| One wrong `login` | 15 | 90/80 — **GAME OVER** |

**User password:** `ghost_zero`
**Solution password:** `ZERO_DAY_BLACKOUT`

**Optimal walkthrough (must fit in 120s):**
1. `cat zero_day.txt` → `ghost_zero`; `login ghost_zero` → USER
2. `scan` → all 5 nodes visible
3. `connect 0.zero.0.10` → fragment-alpha; `decrypt zero.bin` → `ZERO_`; `save ZERO_`
4. `connect 0.zero.0.20` → fragment-beta; `bruteforce` → `day.enc` unlocked; `decrypt day.enc` → `DAY_`; `save DAY_`
5. `connect 0.zero.0.40` → fragment-delta; `cat delta_ops.txt` → shift 21 (`blackout_info.txt` auto-unlocked)
6. `connect 0.zero.0.30` → fragment-gamma; `decrypt black.enc` → `BLACK`; `save BLACK`
7. `connect 0.zero.0.99` → omega-core; `override` → `.deactivation_key` unlocked; `ls -a`; `cat .deactivation_key` → `OUT`
8. `login ZERO_DAY_BLACKOUT` → **GAME COMPLETE**

---

## Detection Math Reference

| Level | Target                   | Max | Per-fail | Bruteforce cost | Override cost | Timer |
|-------|--------------------------|-----|----------|-----------------|---------------|-------|
| 1     | Tutorial System          | 100 | 10       | —               | —             | —     |
| 2     | Employee PC              | 80  | 15       | —               | —             | —     |
| 3     | Office Server            | 70  | 20       | —               | —             | —     |
| 4     | Bank Network             | 60  | 25       | —               | —             | —     |
| 5     | Secure Vault             | 50  | 12       | 24              | —             | 300s  |
| 6     | Darknet Node             | 40  | 35       | 70 *(lethal!)*  | —             | —     |
| 7     | Prometheus Military Grid | 60  | 20       | 40              | 60            | —     |
| 8     | AI Core                  | 100 | 30       | 60              | 90            | 180s  |
| 9     | Corporate Espionage      | 55  | 18       | 36              | 54            | —     |
| 10    | Power Grid Control       | 50  | 15       | 30              | 45            | 240s  |
| 11    | Intelligence Agency      | 45  | 22       | 44 *(lethal!)*  | 66 *(lethal!)* | —    |
| 12    | Satellite Network        | 40  | 20       | 40 *(lethal!)*  | 60 *(lethal!)* | 200s |
| 13    | Underground Market       | 35  | 12       | 24              | 36 *(lethal!)* | —    |
| 14    | Quantum Research Lab     | 50  | 8        | 16              | 24            | 200s  |
| 15    | GHOST Protocol           | 80  | 15       | 30              | 45            | 120s  |

---

## Adding New Levels

1. **Bump the level count** in `levels.h`:
   ```c
   #define TOTAL_LEVELS 17
   ```

2. **Add an `init_levelN()` function** in `levels.c`. Use the shorthand macros to define files:

   ```c
   static void init_level15(void) {
       Level *l = &levels[15];
       memset(l, 0, sizeof(*l));
       l->id = 15;
       strncpy(l->name, "My New Level", MAX_LEVEL_NAME - 1);
       strncpy(l->difficulty, "HARD", 15);
       strncpy(l->objective, "Break into the new target.", 511);
       strncpy(l->solution_password, "s3cr3t_pw", 63);
       strncpy(l->user_password, "user_pw", 63);  /* "" if none */
       l->max_attempts      = 5;
       l->detection_max     = 60;
       l->detection_per_fail = 20;
       l->has_timer         = 0;
       l->available_cmds    = CMD_BASIC | CMD_HINT | CMD_LOGIN | CMD_LOGOUT
                            | CMD_DECRYPT | CMD_SAVE | CMD_INVENTORY
                            | CMD_SCAN    | CMD_CONNECT;

       int n = 0;
       add_node(l, "10.99.0.1", "new-target", "Description.", PUB, 1);

       F("info.txt", "A plain public file.");
       FH("secret.txt", "A hidden file (ls -a).");
       FC("encoded.enc", "<caesar-encoded-text>", 5);   /* shift 5 */
       FR("backwards.enc", "<reversed-text>");           /* reverse */
       FB("data.bin", "01001000 01101001");               /* binary */
       FL("locked.txt", "Locked until bruteforce.");      /* locked */
   }
   ```

   **File macro reference:**

   | Macro              | Visibility | Encrypted | Type       | Locked |
   |--------------------|------------|-----------|------------|--------|
   | `F(name, content)` | Public     | No        | Plain      | No     |
   | `FH(name, content)`| Hidden     | No        | Plain      | No     |
   | `FL(name, content)`| Public     | No        | Plain      | Yes    |
   | `FHL(name, content)`| Hidden    | No        | Plain      | Yes    |
   | `FU(name, content)`| USER+ only | No        | Plain      | No     |
   | `FC(name, content, shift)` | Public | Yes   | Caesar     | No     |
   | `FUC(name, content, shift)`| USER+ | Yes    | Caesar     | No     |
   | `FR(name, content)`| Public     | Yes       | Reverse    | No     |
   | `FLR(name, content)`| Public    | Yes       | Reverse    | Yes    |
   | `FB(name, content)`| Public     | Yes       | Binary     | No     |

3. **Call it from `init_levels()`** in `levels.c`:
   ```c
   void init_levels(void) {
       init_level0();
       /* ... */
       init_level15(); /* add this */
   }
   ```

4. **Rebuild:**
   ```bash
   make clean && make
   ```

---


*Terminal Breach v2.0 — All 16 levels tested end-to-end. Zero compiler warnings.*
