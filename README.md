# Terminal Breach v4.0

A terminal-based hacking puzzle game written in C. You play as **GHOST** — an elite black-hat operator working through **35 escalating network intrusion scenarios**. Each level introduces new commands, tighter detection limits, multi-step puzzles, and higher stakes.

> **v3.0 adds 10 new levels (16–25)** introducing four new cipher families
> (XOR, Vigenère, hex, base64), routing-order constraints, honeypot decoy
> nodes, log-grep forensics, multi-fragment key assembly via `combine`, and
> on the final stage adaptive detection that punishes repeated commands.
>
> **v4.0 adds Act IV, The Lazarus Protocol (levels 26–35).** The Architect is
> dead, but its dead-man seed fired. New mechanics: Atbash and rail-fence
> ciphers, multi-layer **onion** payloads peeled one `decrypt` at a time,
> **port knocking** (`knock`), **keypad locks** (`unlock`), **log wiping**
> (`wipe`), **sentinel sweeps** that punish lingering on watched hosts,
> **silent-alarm tripwires** that start a reverse-trace countdown, and hints
> that cost detection. Each level adds one more mechanic on top of the last.
> v4.0 also fixes several long-standing bugs (see *Changelog v4.0* below).

```
  ████████╗███████╗██████╗ ███╗   ███╗██╗███╗   ██╗ █████╗ ██╗
     ██╔══╝██╔════╝██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗██║
     ██║   █████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║███████║██║
     ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██╔══██║██║
     ██║   ███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██║  ██║███████╗
     ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝
  ██████╗ ██████╗ ███████╗ █████╗  ██████╗██╗  ██╗  v4.0
  ██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║
  ██████╔╝██████╔╝█████╗  ███████║██║     ███████║
  ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██║     ██╔══██║
  ██████╔╝██║  ██║███████╗██║  ██║╚██████╗██║  ██║
  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
```

---

> 📘 **Stuck?** [WALKTHROUGH.md](WALKTHROUGH.md) has exact, tested command sequences for all 35 levels.

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
  - [Level 16 — Crypto Exchange Heist](#level-16--crypto-exchange-heist-mythic)
  - [Level 17 — Industrial SCADA Sabotage](#level-17--industrial-scada-sabotage-mythic)
  - [Level 18 — Telecom Backbone Hijack](#level-18--telecom-backbone-hijack-mythic)
  - [Level 19 — Spy Satellite Imagery Vault](#level-19--spy-satellite-imagery-vault-apex)
  - [Level 20 — Forensic Counter-Hack](#level-20--forensic-counter-hack-apex)
  - [Level 21 — Darknet Auction](#level-21--darknet-auction-apex)
  - [Level 22 — Black Site Dossier](#level-22--black-site-dossier-legendary)
  - [Level 23 — Pacemaker Killswitch](#level-23--pacemaker-killswitch-legendary)
  - [Level 24 — Cobalt Mirage Showdown](#level-24--cobalt-mirage-showdown-legendary)
  - [Level 25 — The Architect](#level-25--the-architect-transcendent)
  - [Act IV — The Lazarus Protocol (L26–L35)](#act-iv--the-lazarus-protocol-levels-2635)
- [Detection Math Reference](#detection-math-reference)
- [Adding New Levels](#adding-new-levels)
- [Changelog v4.0](#changelog-v40)

---

## Quick Start

**Requirements:** GCC (or Clang) and `make`, which come standard on Linux and macOS.

```bash
git clone https://github.com/agupte01/Terminal-Breach-Hacking-Puzzle-Game.git
cd Terminal-Breach-Hacking-Puzzle-Game/src
make
./terminal_breach
```

To rebuild from scratch:

```bash
make clean && make
```

Jump to a level for practice (1-based), optionally without the typing animation:

```bash
TB_START_LEVEL=26 TB_FAST=1 ./terminal_breach
```

---

## File Structure

```
Terminal-Breach-Hacking-Puzzle-Game/
├── README.md                              This file
├── WALKTHROUGH.md                         Tested step-by-step solutions for all 35 levels
├── COMPACT_README.md                      One-page reference card
├── REPORT.md                              Technical design report (source of the .docx)
├── Terminal_Breach_Technical_Report.docx  Formatted report, generated from REPORT.md
└── src/
    ├── main.c          Game loop, level transitions, win/loss screens, score
    ├── commands.c/h    All command handlers, sweeps/trace ticks, dispatcher
    ├── levels.c/h      All 35 level definitions; core data structures
    ├── network.c/h     Node lookup, file unlock/decrypt bitmask helpers
    ├── puzzles.c/h     Caesar, reverse, binary, hex, XOR, Vigenère, Base64,
    │                   Atbash, rail-fence and onion (multi-layer) decoders
    ├── utils.c/h       Detection bar, prompt with live timers, slow_print, briefings
    ├── save.c/h        Save/load to terminal_breach.sav
    ├── gen_report.py   Builds the .docx from ../REPORT.md (needs python-docx)
    └── Makefile
```

**Build produces:** `terminal_breach`, a single self-contained binary with no runtime dependencies beyond the C standard library.

**Compiler flags:** `-Wall -Wextra -std=c11 -O2`, and the build has zero warnings.

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
save <data>     → store a string (up to 30 items)
inventory       → list all stored items
combine [a b]   → join slots into a new item (L16+)
drop <n|all>    → remove a slot / clear everything (L16+)
```

The inventory is **cleared at every level transition**, because fragments never carry between targets. That way `combine 1 2 3` always refers to what you saved on the current level. (`loadgame` keeps the inventory it restores.)

Useful for noting partial passwords while navigating multi-node levels. Example:

```
ghost@10.0.0.1[guest]:~$ decrypt binary.sys
[+] DECODED: NEURAL_

ghost@10.0.0.1[guest]:~$ save NEURAL_
[+] Saved: "NEURAL_" (slot 1/30)
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

The save file stores your current level, score, per-level scores, total fails, command count, and inventory. On load, the game restarts the saved level (not the one after it, which was a v3 bug) with your score and inventory intact.

### Scoring

Score is calculated per level when you successfully `login` with the solution password:

```
Level score = (level_number × 1000) - (failed_attempts × 100) - (detection × 5)
```

Minimum level score is 0 (no negative contributions to total).

The theoretical maximum (zero fails and zero detection on every level) is **630,000 points** (1,000 + 2,000 + … + 35,000). Bruteforce and override are mandatory on some levels, so real runs land a little lower: the verified clean playthrough in [WALKTHROUGH.md](WALKTHROUGH.md) scores **624,135**.

Per-level base scores: L1=1000, L2=2000, … L25=25000, … L35=35000.

### Ranks

Your final rank is determined by total failed login attempts across all 35 levels:

| Total Fails | Rank                              |
|-------------|-----------------------------------|
| 0           | **GHOST LEGEND** — Flawless run!  |
| 1–4         | **PHANTOM** — Near perfect!       |
| 5–10        | **SPECTRE** — Well played.        |
| 11–20       | **AGENT** — Good effort.          |
| 21+         | **ROOKIE** — Keep training.       |

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
| `override`         | Level 7  | Override neural security (very high detection!) |
| `combine [a b ..]` | Level 16 | Concatenate inventory items into a new entry    |
| `grep <pat> <file>`| Level 20 | Filter file lines by substring pattern          |
| `drop <slot\|all>` | Level 16 | Remove an inventory slot (or clear all)         |
| `wipe`             | Level 26 | Scrub logs on a host that keeps them (once per host); refunds one per-fail of detection |
| `knock <host> <port>` | Level 27 | Port-knock a FILTERED host; the right order opens it, a wrong port resets the sequence and costs ½ per-fail |
| `unlock <file> <code>` | Level 28 | Enter a keypad code; each wrong code this level costs more than the last |

### Puzzle types

| Type         | First level | Decoder                                              |
|--------------|-------------|------------------------------------------------------|
| Caesar       | L2          | Letter shift (decode = subtract shift)               |
| Reverse      | L2          | String reversal                                      |
| Binary       | L8          | 8-bit binary tokens → ASCII                          |
| **Hex**      | **L16**     | Hex byte pairs → ASCII                               |
| **XOR**      | **L16**     | Hex bytes XOR'd against repeating ASCII key          |
| **Vigenère** | **L17**     | Letter-by-letter shift using a repeating keyword     |
| **Base64**   | **L18**     | Standard base64 → ASCII                              |
| **Atbash**   | **L26**     | Mirror alphabet A↔Z, B↔Y … (self-inverse)            |
| **Rail fence** | **L26**   | Zig-zag transposition across N rails                 |
| **Onion**    | **L27**     | Stacked layers; each `decrypt` peels ONE (`ls` shows `[ONI k/n]`) |

### Special node mechanics

- **Honeypot** *(L21, L25)* — Connecting fires `2 × detection_per_fail` extra detection. Read the topology before you scan-and-connect.
- **Routing order** *(L17, L18, L22, L23, L25)* — Some nodes refuse a connection unless a specific prerequisite hop was visited earlier this level. Skipping the route costs detection.
- **Adaptive detection** *(L25, L32, L34, L35)* — Repeating the same command name in a row charges escalating extra detection.
- **Writable logs** *(L26+)* — `wipe` on such a host refunds one per-fail of detection, once per host. Wiping at 0% detection gains nothing.
- **Port knocking** *(L27, L30, L32–L35)* — FILTERED hosts refuse `connect` (½ per-fail) until you `knock` their ports in order.
- **Keypads** *(L28, L29, L31, L33–L35)* — `[PIN]` files show up in `ls`. The codes are hidden in logs and riddles.
- **Sentinel sweeps** *(L28, L31–L35)* — every N commands (any command counts) a sweep runs, and if you're on a WATCHED host you pay one per-fail. `status` shows the countdown, and you get a warning one command before. Onion peel progress is kept, so you can split long peels across visits.
- **Silent alarm / tripwire** *(L29, L33–L35)* — the first connect to an ALARMED host starts a reverse-trace countdown (shown in the prompt as `[TRACE n]`) that runs for the rest of the level.
- **Hint cost** *(L26+)* — `hint` charges detection. The automatic hint on your last login attempt is still free.
- **Bruteforce safety** *(all levels)* — running `bruteforce` on the wrong host is refused **without using up** its single use.

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
8. `login ZERO_DAY_BLACKOUT` → **L15 complete — proceed to MYTHIC tier**

---

### Level 16 — Crypto Exchange Heist `MYTHIC`

**Target:** ZenithCoin cold-wallet vault — drain via the HSM bridge.
**Topology:** 4 nodes — `gateway` (entry) → `trading-engine` → `hsm-bridge` → `cold-vault`.
**Solution password:** `ZEN1TH_C0LD_V@ULT` · **User password:** `trader_oa`
**Detection:** 80, +20 · **Timer:** 240s · **Attempts:** 4
**New mechanics:** hex bytes (`PUZZLE_HEX`), XOR cipher (`PUZZLE_XOR`), `combine` command.

Fragment chain:
- `frag1.hex` (trading-engine) — hex-to-ASCII → `ZEN1TH_`
- `frag2.xor` (hsm-bridge)     — XOR with key `ZENITH` → `C0LD_`
- `frag3.enc` (cold-vault)     — Caesar-13 → `V@ULT`

Walkthrough:
1. `cat staff_memo.txt` → user creds `trader_oa`
2. `login trader_oa` → USER tier
3. `scan` → 3 hosts; `connect 10.10.10.20` → trading-engine
4. `decrypt frag1.hex` → `ZEN1TH_`; `save ZEN1TH_`
5. `connect 10.10.10.30` → hsm-bridge; `decrypt frag2.xor` → `C0LD_`; `save C0LD_`
6. `connect 10.10.10.40` → cold-vault; `decrypt frag3.enc` → `V@ULT`; `save V@ULT`
7. `combine 1 2 3` → `ZEN1TH_C0LD_V@ULT` stored as new inventory slot
8. `login ZEN1TH_C0LD_V@ULT` → **L16 complete**

---

### Level 17 — Industrial SCADA Sabotage `MYTHIC`

**Target:** City water-grid pump-station PLC.
**Topology:** 5 nodes — `scada-master` (entry) → `rtu-1`, `rtu-2`, `historian`, `plc-core`.
**Solution password:** `SET_P01NT_OVERRIDE` · **User password:** `plc_op_3`
**Detection:** 70, +25 · **Timer:** 240s · **Attempts:** 4
**New mechanics:** Vigenère cipher (`PUZZLE_VIGENERE`), routing-order requirement on `plc-core` (must visit `historian` first).

Fragment chain:
- `setpoint.vig` (rtu-1) — Vigenère key `HYDRA` → `SET_P01NT_`
- `token.rev`    (rtu-2) — reverse text → `OVERRIDE`

Walkthrough:
1. `cat login_banner.txt` → cred `plc_op_3`; `login plc_op_3`
2. `scan`; `connect 172.16.0.20` → rtu-1; `decrypt setpoint.vig` → `SET_P01NT_`; `save`
3. `connect 172.16.0.21` → rtu-2; `decrypt token.rev` → `OVERRIDE`; `save`
4. `connect 172.16.0.30` → historian *(routing prerequisite)*
5. `connect 172.16.0.99` → plc-core (now accepted)
6. `combine 1 2` → `SET_P01NT_OVERRIDE`; `login SET_P01NT_OVERRIDE` → **L17 complete**

> Skipping the historian and trying to reach plc-core directly costs `detection_per_fail` and refuses the connection.

---

### Level 18 — Telecom Backbone Hijack `MYTHIC++`

**Target:** Tier-1 ISP via BGP route reflector.
**Topology:** 5 nodes — `edge-router` (entry) → `bgp-reflector` → `transit-core` (routed) + `peering-x`, `route-optimizer`.
**Solution password:** `BGP_HIJACK_PRIME` · **User password:** `net_eng_99`
**Detection:** 70, +20 · **Timer:** 200s · **Attempts:** 4 · `bruteforce` available.
**New mechanics:** base64 (`PUZZLE_BASE64`), routing constraint enforcing AS-path traversal.

Fragment chain:
- `frag1.b64` (bgp-reflector) — base64 → `BGP_`
- `frag2.hex` (transit-core)  — hex → `HIJACK_`
- `frag3.xor` (peering-x)     — XOR key `AS1337` → `PRIME`

Walkthrough:
1. `cat peering_banner.txt` → `net_eng_99`; `login net_eng_99`
2. `scan`; `connect 10.20.0.10` → bgp-reflector; `decrypt frag1.b64` → `BGP_`; `save`
3. `connect 10.20.0.20` → transit-core *(only succeeds because step 2 visited bgp-reflector)*; `decrypt frag2.hex` → `HIJACK_`; `save`
4. `connect 10.20.0.30` → peering-x; `decrypt frag3.xor` → `PRIME`; `save`
5. `combine 1 2 3` → `BGP_HIJACK_PRIME`; `login BGP_HIJACK_PRIME` → **L18 complete**

---

### Level 19 — Spy Satellite Imagery Vault `APEX`

**Target:** Recover the KEYHOLE recon archive.
**Topology:** 5 nodes — `ground-station` (entry) → `uplink-relay` → `decryption-rig` + `vault-A` (live), `vault-B` (decoy).
**Solution password:** `KEYHOLE_RECON_X9` · **User password:** `ground_op_7`
**Detection:** 60, +30 · **Timer:** 200s · **Attempts:** 3.

Fragment chain:
- `keyhole.vig` (uplink-relay)   — Vigenère key `ORBIT` → `KEYHOLE_`
- `recon.hex`   (decryption-rig) — hex → `RECON_`
- `tail.rev`    (vault-A)        — reverse → `X9`

> **vault-B is a decoy** — its `tail.rev` decodes to `Q7`. The README on each vault notes which one is "live" — read both before assembling.

Walkthrough:
1. `login ground_op_7`
2. `scan`; pull frag1 from uplink-relay, frag2 from decryption-rig.
3. `connect 10.50.0.30` → vault-A; `decrypt tail.rev` → `X9`; `save`
4. `combine 1 2 3` → `KEYHOLE_RECON_X9`; `login` → **L19 complete**

---

### Level 20 — Forensic Counter-Hack `APEX`

**Target:** Trace and burn the attacker's C2.
**Topology:** 5 nodes — `ir-bastion` (entry) + `relay-honey`, `attacker-relay`, `attacker-c2`, `identity-leak`.
**Solution password:** `BURN_THE_C2_NOW` · **User password:** `ir_analyst`
**Detection:** 70, +20 · **Timer:** 300s · **Attempts:** 4.
**New mechanic:** `grep <pattern> <file>` — filter log lines.

Fragment chain:
- `burn.enc` (attacker-relay) — Caesar-9 → `BURN_THE_`
- `c2.hex`   (attacker-c2)    — hex → `C2_NOW`

The Caesar shift is **derived from the auth log**: the seconds field of the line containing `KEY_MISMATCH` (`03:14:09` → shift 9).

Walkthrough:
1. `login ir_analyst`; `scan`
2. `connect 10.0.0.67` → relay-honey; `grep KEY_MISMATCH auth.log` → `[2026-04-15 03:14:09] AUTH_FAIL src=66.249.13.37 user=root reason=KEY_MISMATCH`
3. `connect 10.0.0.68` → attacker-relay; `decrypt burn.enc` → `BURN_THE_` *(shift 9)*
4. `connect 10.0.0.69` → attacker-c2; `decrypt c2.hex` → `C2_NOW`
5. `combine 1 2`; `login BURN_THE_C2_NOW` → **L20 complete**

---

### Level 21 — Darknet Auction `APEX+`

**Target:** Acquire a zero-day from a darknet auction. Two of the listings are honeypots.
**Topology:** 6 nodes — `auction-board` (entry), `broker`, `escrow` *(HONEYPOT)*, `buyer-mirror` *(HONEYPOT)*, `staging`, `payload-vault`.
**Solution password:** `Z3R0D@Y_W1NN3R` · **User password:** `dn_bidder`
**Detection:** 100, +20 · **Timer:** 240s · **Attempts:** 3 · `bruteforce` + `override` required.
**New mechanic:** Honeypot nodes — connecting fires `2 × detection_per_fail` extra detection. Read the topology before connecting.

Fragment chain:
- `stake.locked`  (staging)       — locked + XOR key `STAKE` → `Z3R0D@Y_`
- `.winner_frag`  (payload-vault) — hidden + locked + reverse → `W1NN3R`

Walkthrough:
1. `login dn_bidder`; `scan`
2. **Skip** `escrow` and `buyer-mirror` — both are honeypots.
3. `connect 127.42.0.30` → staging; `bruteforce` → unlocks `stake.locked`; `decrypt stake.locked` → `Z3R0D@Y_`; `save`
4. `connect 127.42.0.40` → payload-vault; `override` → `.winner_frag` unlocked; `ls -a`; `decrypt .winner_frag` → `W1NN3R`; `save`
5. `combine 1 2`; `login Z3R0D@Y_W1NN3R` → **L21 complete**

---

### Level 22 — Black Site Dossier `LEGENDARY+`

**Target:** Air-gapped intelligence vault with a 180-second skiff window.
**Topology:** 5 nodes — `skiff-bastion` (entry) + `vault-alpha`, `vault-bravo`, `vault-charlie`, `cipher-index`.
**Solution password:** `BLACK_SITE_BURN_03` · **User password:** `classified_a`
**Detection:** 80, +25 · **Timer:** 180s · **Attempts:** 3.

Fragment chain:
- `alpha.vig`   (vault-alpha)   — Vigenère key `REDACT` → `BLACK_`
- `bravo.bin`   (vault-bravo)   — binary → `SITE_`
- `charlie.enc` (vault-charlie) — Caesar-23 → `BURN_03`

`cipher-index` documents both keys (`REDACT` and `shift23`) — visit it early to confirm.

Walkthrough:
1. `login classified_a`; `scan`; `connect 10.99.0.40` → cipher-index; `cat keys.txt`
2. Pull alpha, bravo, charlie fragments in any order.
3. `combine 1 2 3`; `login BLACK_SITE_BURN_03` → **L22 complete**

---

### Level 23 — Pacemaker Killswitch `LEGENDARY+`

**Target:** Stop a worm spreading through hospital implants.
**Topology:** 7 nodes — `hospital-bastion` (entry) → strict route `ER → ICU → imaging → pharmacy → mdm → pacemaker-net`.
**Solution password:** `K1LLSWITCH_ARMED` · **User password:** `med_admin_x`
**Detection:** 90, +30 · **Timer:** 240s · **Attempts:** 3.
**Mechanic:** Five-step routing chain — every node beyond ER demands the previous hop have been visited this level.

Fragment chain:
- `kill.hex`  (ER)        — hex → `K1LLSWITCH_`
- `armed.vig` (pharmacy) — Vigenère key `HIPAA` → `ARMED`

Walkthrough:
1. `login med_admin_x`; `scan`
2. `connect ER` → `decrypt kill.hex` → `K1LLSWITCH_`; `save`
3. `connect ICU` → `connect imaging` → `connect pharmacy`
4. `decrypt armed.vig` → `ARMED`; `save`
5. `connect mdm` → `connect pacemaker-net`; `combine 1 2`; `login K1LLSWITCH_ARMED` → **L23 complete**

> Trying to jump straight to `pharmacy` from `ER` is rejected with a routing message and a small detection cost.

---

### Level 24 — Cobalt Mirage Showdown `LEGENDARY++`

**Target:** Take down nation-state APT 'Cobalt Mirage'. Three compartmented enclaves.
**Topology:** 5 nodes — `soc-bastion` (entry) + `enclave-a`, `enclave-b`, `enclave-c`, `phantom-c2`.
**Solution password:** `COBALT_M1RAGE_END` · **User password:** `agent_apt`
**Detection:** 100, +30 · **Timer:** 180s · **Attempts:** 3 · `bruteforce` + `override`.

Fragment chain:
- `frag_a.b64`    (enclave-a)  — base64 → `COBALT_`
- `frag_b.locked` (enclave-b)  — locked + hex → `M1RAGE_` (bruteforce on this node)
- `.frag_c`       (phantom-c2) — hidden + locked + XOR key `PHANTOM` → `END` (override on this node)

Walkthrough:
1. `login agent_apt`; `scan`
2. `connect enclave-a` → `decrypt frag_a.b64` → `COBALT_`
3. `connect enclave-b` → `bruteforce` → `decrypt frag_b.locked` → `M1RAGE_`
4. `connect phantom-c2` → `override` → `ls -a` → `decrypt .frag_c` → `END`
5. `combine 1 2 3`; `login COBALT_M1RAGE_END` → **L24 complete**

---

### Level 25 — The Architect `TRANSCENDENT`

**Target:** A rogue AGI you helped build. Final boss.
**Topology:** 6 nodes — `ghost-shell` (entry) + `shard-aleph`, `shard-beth`, `shard-gimel`, `shard-daleth` *(HONEYPOT)*, `architect-core`.
**Solution password:** `ARCH1TECT_DECOMM_INF` · **User password:** `architect_mirror`
**Detection:** 260, +40 · **Timer:** 120s · **Attempts:** 2 · `bruteforce` + `override` · **adaptive detection on**.
**Mechanic:** Adaptive detection — repeating the same command name 3+ times in a row charges escalating extra detection. Vary your moves.

Fragment chain:
- `aleph.b64`     (shard-aleph)   — base64 → `ARCH`
- `beth.hex`      (shard-beth)    — hex → `1TECT_`
- `mirror.locked` (shard-gimel)   — locked + Vigenère key `GHOST` → `DECOMM` (bruteforce here)
- `.final_frag`   (architect-core)— hidden + locked + reverse → `_INF` (override here)

Walkthrough:
1. `login architect_mirror`; `scan`
2. `connect shard-aleph` → `decrypt aleph.b64` → `ARCH`; `save`
3. `connect shard-beth` → `decrypt beth.hex` → `1TECT_`; `save`
4. **Avoid** `shard-daleth` (honeypot).
5. `connect shard-gimel` → `bruteforce` → `decrypt mirror.locked` → `DECOMM`; `save`
6. `connect architect-core` → `override` → `ls -a` → `decrypt .final_frag` → `_INF`; `save`
7. `combine 1 2 3 4`; `login ARCH1TECT_DECOMM_INF` → **Act III complete**, but something is still talking.

---

## Act IV — The Lazarus Protocol (Levels 26–35)

> Full command-by-command solutions (timed around every sentinel sweep) are in [WALKTHROUGH.md](WALKTHROUGH.md#act-iv--the-lazarus-protocol).

> The Architect is dead. On decommission, its dead-man seed **LAZARUS** fired
> and began rebuilding it across the network. Every level adds one more
> mechanic, and the last one puts them all together.

| Level | Name | Difficulty | New pressure |
|-------|------|-----------|--------------|
| 26 | Lazarus Seed | OMEGA | Atbash, rail fence, `wipe`, `drop`, hints cost detection |
| 27 | Onion Relay | OMEGA | Onion payloads (one layer per `decrypt`), port knocking, honeypot |
| 28 | Sentinel Grid | OMEGA+ | Sentinel sweeps every 6 commands, keypad with escalating penalty |
| 29 | Silent Alarm | OMEGA+ | Tripwire: 60s reverse trace from first touch of the vault |
| 30 | Mirror Maze | SINGULARITY | 3 *unlabelled* honeypots out of 6 mirrors (deduce from DNS TTLs) |
| 31 | Deadman's Vault | SINGULARITY | Sweeps + PIN rotation + bruteforce + override |
| 32 | Hydra Botnet | SINGULARITY+ | Adaptive detection returns + sweeps + 4-fragment routing chain |
| 33 | Quantum Ghost | EVENT HORIZON | Firewalled + alarmed core, Fibonacci keypad riddle, 3-shell onions |
| 34 | Lazarus Core | EVENT HORIZON+ | Everything at once, 8 nodes, 2 attempts |
| 35 | Zero Point | ZERO POINT | Final level: sweeps every 5, 90s trace, 4-shell onion, the twist |

### Level 26 — Lazarus Seed `OMEGA`

**Solution:** `LAZ4RUS_S33D_PURGE` · **User:** `lazarus_hunter` · **Detection:** 100, +25 · **Timer:** 240s · **Hint cost:** 10

1. `login lazarus_hunter`; `scan`
2. `connect seed-mirror-a` → `decrypt seed.atb` → `LAZ4RUS_`; `save LAZ4RUS_`
3. `connect seed-mirror-b` → `decrypt seed.rail` (3 rails) → `S33D_`; `save S33D_`
4. `connect audit-sink` (`wipe` here if you have taken detection), then `connect purge-console` (routing requires audit-sink first)
5. `decrypt purge.hex` → `PURGE`; `save PURGE`; `combine 1 2 3`; `login LAZ4RUS_S33D_PURGE`

### Level 27 — Onion Relay `OMEGA`

**Solution:** `0N10N_TR4P_D00R` · **User:** `tor_exit_9` · **Detection:** 100, +25 · **Timer:** 240s · **Honeypot:** `directory-auth`

1. `login tor_exit_9`; `scan`
2. `connect middle-relay` → `decrypt frag1.oni` ×3 (base64 → reversed hex → hex) → `0N10N_`; `save`
3. `connect hidden-service` → `decrypt knock.rail` → `knock exit-relay: 9001 9030 9050`
4. `knock exit-relay 9001`, `knock exit-relay 9030`, `knock exit-relay 9050` → `connect exit-relay`
5. `decrypt frag2.oni` ×2 → `TR4P_D00R`; `save`; `combine 1 2`; `login 0N10N_TR4P_D00R`

### Level 28 — Sentinel Grid `OMEGA+`

**Solution:** `S3NT1NEL_BL1ND_SP0T` · **User:** `grid_ghost` · **Detection:** 100, +20 · **Timer:** 270s · **Sweep:** every 6 · **Watched:** `watchtower`, `patrol-hub`

1. `login grid_ghost`; `scan`
2. `connect camera-loop` → `grep PIN cam.log` → digits reorder to **4471**
3. `connect vault-door` → `decrypt blind.vig` → `BL1ND_`; `unlock spot.pin 4471` → `decrypt spot.pin` → `SP0T`
4. Check `status`. Right after a sweep: `connect watchtower` → `decrypt watch.rail` → leave before the next sweep. → `S3NT1NEL_`
5. Save in order and `combine`; `login S3NT1NEL_BL1ND_SP0T`. `patrol-hub` has nothing you need.

### Level 29 — Silent Alarm `OMEGA+`

**Solution:** `QU13T_H4NDS_0NLY` · **User:** `night_shift` · **Detection:** 100, +25 · **Timer:** 300s · **Tripwire:** `vault-core` 60s

1. `login night_shift`; `scan`
2. `connect security-office` → `grep keypad guard.log` → "straight down the middle column" = **2580**
3. `connect locker-room` → `decrypt quiet.oni` ×2 → `QU13T_`; `connect server-closet` → `decrypt hands.rail` → `H4NDS_`
4. `connect antechamber` → `bruteforce` → `cat door.locked`
5. **Have everything saved first.** `connect vault-core` (60s trace starts) → `unlock only.pin 2580` → `decrypt only.pin` → `0NLY` → `save`, `combine`, `login QU13T_H4NDS_0NLY`

### Level 30 — Mirror Maze `SINGULARITY`

**Solution:** `M1RR0R_M4Z3_3X1T` · **User:** `maze_runner` · **Detection:** 110, +25 · **Timer:** 270s · **Honeypots:** `mirror-b`, `mirror-d`, `mirror-e` (not labelled)

1. `login maze_runner`; `grep TTL=1 dns.log` → the 1-second-TTL mirrors are spoofed
2. `scan`; `connect mirror-a` → `decrypt m1.oni` ×2 → `M1RR0R_`
3. `connect mirror-c` → `decrypt maze.atb` → `M4Z3_`; `decrypt knock.oni` ×2 → `knock mirror-exit 4815 1623 4200`
4. Knock all three → `connect mirror-exit` → `decrypt exit.rail` → `3X1T`
5. `combine`; `login M1RR0R_M4Z3_3X1T`

### Level 31 — Deadman's Vault `SINGULARITY`

**Solution:** `D3ADM4N_SW1TCH_0FF` · **User:** `vault_warden` · **Detection:** 150, +25 · **Timer:** 270s · **Sweep:** every 7 · **Watched:** `heartbeat-mon` · **Honeypot:** `dead-drop`

1. `login vault_warden`; `scan`; `connect warden-log` → `grep ACTIVE warden.log` → PIN **7719**
2. `connect switch-room` → `bruteforce` → `decrypt switch.locked` ×2 → `SW1TCH_`; `unlock keyring.pin 7719` (intel)
3. Time a quick visit to `heartbeat-mon` → `decrypt pulse.vig` → `D3ADM4N_`
4. `connect vault-heart` (via switch-room) → `override` → `decrypt .heart_frag` → `0FF`
5. Use `wipe` on warden-log *after* the bruteforce spike. Then `combine` in order and `login D3ADM4N_SW1TCH_0FF`

### Level 32 — Hydra Botnet `SINGULARITY+`

**Solution:** `HYDR4_H3ADS_SEVERED` · **User:** `hydra_slayer` · **Detection:** 120, +30 · **Timer:** 270s · **Sweep:** every 8 · **Adaptive** · **Honeypot:** `head-3`

1. `login hydra_slayer`; `scan`
2. `connect head-1` → `h1.hex` → `HYDR4_`; `connect head-2` (watched) → `h2.rail` → `H3ADS_`; `connect head-4` → `venom.oni` ×2 → `SEV`
3. `connect c2-ledger` → `grep knock ledger.log` → `8080 4444 1337`; `wipe`
4. Knock all three → `connect hydra-heart` → `override` → `decrypt .heart` → `ERED`
5. `combine 1 2 3 4`; `login HYDR4_H3ADS_SEVERED`. Mix up your commands so you don't trigger the pattern penalty.

### Level 33 — Quantum Ghost `EVENT HORIZON`

**Solution:** `QU4NTUM_GH0ST_C0LL4PSE` · **User:** `observer_zero` · **Detection:** 120, +30 · **Timer:** 300s · **Sweep:** every 7 · **Tripwire:** `superposition` 75s · **Honeypot:** `schrodinger-box`

1. `connect entangle-a` → `qa.oni` ×3 → `QU4NTUM_`
2. `connect decoherence-log` → `grep knock q.log` (6626 1054 2998), `grep collapse q.log` (Fibonacci after 8 → 13, 21 → **1321**)
3. Visit watched `entangle-b` between sweeps → `qb.oni` ×2 → `GH0ST_`
4. Knock superposition, `connect superposition` (75s trace) → `unlock collapse.pin 1321` → `decrypt` ×2 → `C0LL4PSE`
5. `combine`; `login QU4NTUM_GH0ST_C0LL4PSE`

### Level 34 — Lazarus Core `EVENT HORIZON+`

**Solution:** `L4ZARUS_N3VER_R1SES` · **User:** `final_witness` · **Detection:** 180, +30 · **Timer:** 300s · **Sweep:** every 6 · **Adaptive** · **Tripwire:** `lazarus-core` 60s · **Attempts:** 2

1. `connect ossuary` → `grep DECOY lazarus.log` (crypt-mirror, ghost-choir), `grep gate lazarus.log` (knock + PIN riddle: the Architect fell on L25, so **2525**)
2. `reliquary` (watched) → `relic.oni` ×3 → `L4ZARUS_`
3. `resurrection-lab` (via reliquary) → `bruteforce` → `decrypt rebirth.locked` → `N3VER_`
4. Knock `soul-gate` 1666 6661 6616 → `unlock gate.pin 2525` → `decrypt` → `R1`
5. Wait for a sweep to pass, then `lazarus-core` (watched + alarmed) → `override` → `decrypt .core_frag` → `SES` → leave → `combine 1 2 3 4` → `login`

### Level 35 — Zero Point `ZERO POINT` (final)

**Solution:** `GH0ST_1S_TH3_ARCH1TECT` · **User:** `GHOST` (run `whoami`) · **Detection:** 200, +35 · **Timer:** 360s · **Sweep:** every 5 · **Adaptive** · **Tripwire:** `origin` 90s · **Attempts:** 2 · **Honeypots:** `memory-3`, `recursion`

1. `login GHOST`; `connect memory-1` → `grep echo origin.log` (decoys), `grep gate origin.log` (knock 1010 0101 1111; PIN = 34 systems breached so far, typed twice = **3434**)
2. `memory-2` is watched and the onion has **4 shells**. You can't do connect + 4 peels in 5 commands, so peel 3, leave, and come back for the 4th (peel progress is kept) → `GH0ST_`
3. `memory-4` → `bruteforce` → `self.locked` → `1S_`; return to `memory-1` and `wipe`
4. Knock origin-gate → `unlock core.pin 3434` → `decrypt` → `TH3_`
5. `origin` (watched + 90s trace) → `override` → `decrypt .origin_frag` → leave → come back → `decrypt` again → `ARCH1TECT`
6. `combine` in order → `login GH0ST_1S_TH3_ARCH1TECT` → **GAME COMPLETE**

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
| 16    | Crypto Exchange Heist    | 80  | 20       | —               | —             | 240s  |
| 17    | Industrial SCADA Sabotage| 70  | 25       | —               | —             | 240s  |
| 18    | Telecom Backbone Hijack  | 70  | 20       | 40              | —             | 200s  |
| 19    | Spy Satellite Imagery    | 60  | 30       | —               | —             | 200s  |
| 20    | Forensic Counter-Hack    | 70  | 20       | —               | —             | 300s  |
| 21    | Darknet Auction          | 130 | 20       | 40              | 60            | 240s  |
| 22    | Black Site Dossier       | 80  | 25       | —               | —             | 180s  |
| 23    | Pacemaker Killswitch     | 90  | 30       | —               | —             | 240s  |
| 24    | Cobalt Mirage Showdown   | 200 | 30       | 60              | 90            | 180s  |
| 25    | The Architect            | 260 | 40       | 80              | 120           | 120s  |
| 26    | Lazarus Seed             | 100 | 25       | —               | —             | 240s  |
| 27    | Onion Relay              | 100 | 25       | —               | —             | 240s  |
| 28    | Sentinel Grid            | 100 | 20       | —               | —             | 270s  |
| 29    | Silent Alarm             | 100 | 25       | 50              | —             | 300s (+60s trip) |
| 30    | Mirror Maze              | 110 | 25       | —               | —             | 270s  |
| 31    | Deadman's Vault          | 150 | 25       | 50              | 75            | 270s  |
| 32    | Hydra Botnet             | 120 | 30       | —               | 90            | 270s  |
| 33    | Quantum Ghost            | 120 | 30       | —               | —             | 300s (+75s trip) |
| 34    | Lazarus Core             | 180 | 30       | 60              | 90            | 300s (+60s trip) |
| 35    | Zero Point               | 200 | 35       | 70              | 105           | 360s (+90s trip) |

*Honeypots (connect cost = 2× per-fail) appear on L21, L25, L27, L30–L35. Routing order is enforced on L17, L18, L23, L26, L29–L32, L34 and L35. Each sentinel sweep that catches you costs 1× per-fail, and `wipe` refunds 1× per-fail once per log host. For v4.0 every ceiling was re-checked so the mandatory bruteforce + override cost leaves room for at least one mistake (L21, L24 and L25 used to be unwinnable).*

---

## Adding New Levels

1. **Bump the level count** in `levels.h`:
   ```c
   #define TOTAL_LEVELS 36
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

   Act IV macros: `FAT` (Atbash), `FRL(name, ct, rails)` (rail fence), `FON(name, ct, "b64>hex>atb")` (onion, with layers listed outermost first; tokens are `b64 hex rev bin atb rail:N caesar:N xor:KEY vig:KEY`), `FPIN(name, ct, type, shift, key, "1234")` (keypad), and `FLOCK` / `FHLOCK` (bruteforce/override-locked). Node markers that go after `add_node`: `mark_honeypot`, `route_after(l, "host")`, `mark_watched`, `mark_logs`, `set_trip(l, secs)`, `set_knock(l, "p1 p2 p3")`. Level fields: `sweep_interval`, `hint_cost`, `adaptive_detection`, plus `bf_node`/`bf_file` and `ov_node`/`ov_file` for bruteforce/override targets (commands.c no longer needs per-level code).

   **Budget rule:** on levels that require both bruteforce and override, keep `detection_max` above `5 × detection_per_fail`.

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

## Technical Notes

- Written in **C11**, compiled with GCC. No external libraries — only `stdio.h`, `string.h`, `stdlib.h`, `time.h`, `unistd.h`.
- All ANSI colour codes are inline escape sequences — works on any standard terminal.
- Level data is stored in a static array of `Level` structs initialized at startup. Level structs are **immutable** during play — file decryption state is tracked in `GameState` bitmask arrays, not in the Level struct itself. This allows clean level resets without re-initializing level data.
- The detection system uses integer arithmetic — no floats anywhere in the game.
- `slow_print()` uses `nanosleep()` for character-by-character output with configurable delay.
- Save file (`terminal_breach.sav`) is plain text key=value format — human readable and editable. The v3 format adds per-level scores.
- **Practice / testing:** `TB_START_LEVEL=26 ./terminal_breach` jumps straight to a level, and `TB_FAST=1` turns off the typewriter delays. Every sequence in WALKTHROUGH.md is run this way, and the whole 35-level game has been completed in a single session (35/35, 0 fails, GHOST LEGEND).

---

## Changelog v4.0

New: levels 26–35, seven new mechanics, four new commands, a live timer/trace countdown in the prompt, `MAX_NODES` raised from 6 to 8, and inventory raised from 20 to 30 slots.

Bug fixes:
- **`loadgame` skipped a level.** It resumed at *saved level + 1*. It now restarts the saved level.
- **`loadgame` duplicated the inventory** every time it ran, and trusted out-of-range `LEVEL=` values (array overrun). Both are fixed, and per-level scores are now saved so the win-screen breakdown survives a reload.
- **Routing state leaked between levels.** `nodes_connected` was never reset, so on later levels a route requirement could be skipped if node indices happened to line up. The adaptive-detection streak is now reset too.
- **Bruteforce soft-lock.** Running `bruteforce` on the wrong host used up its single use, which left L5/L13/L14/L15/L21/L24/L25 unwinnable. It's now refused without being used up.
- **Unwinnable detection budgets** on L21 (bruteforce + override hit the 100 cap exactly), L24 (150 vs 100) and L25 (200 vs 120).
- **L23 pacemaker-net** was named in the briefing, hint and topology but didn't exist. It's now the last hop of the routing chain.
- **A routing rejection printed "CONNECTION ESTABLISHED"** before refusing. The checks now run first.
- The adaptive-detection hash relied on signed overflow (undefined behaviour). It's now unsigned.
- The 20-slot inventory filled up for good around L20 with no way to clear it. The inventory is now cleared at each level transition, raised to 30 slots, and `drop` removes single slots.
- The level-transition banner never announced `grep`, `combine`, `hint` or `logout` unlocks.
- Outdated text: L8 was named "[FINAL]", the boot screen said "Seven targets", the banner said v2.0, and the win screen said "All 25 systems".

---

*Terminal Breach v4.0 — Levels 26–35 and every bruteforce/override level tested end-to-end with scripted playthroughs. Zero compiler warnings.*
