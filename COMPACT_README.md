# Terminal Breach v5.0 — Compact Reference

45 levels · 5 acts · pure C11 · zero warnings. Full guide: [README.md](README.md) · Solutions: [WALKTHROUGH.md](WALKTHROUGH.md)

## Build & Run
```bash
cd src && make && ./terminal_breach
TB_START_LEVEL=26 TB_FAST=1 ./terminal_breach   # jump to a level, no typing delay
```

## Source Map
| File | Role |
|---|---|
| `main.c` | game loop, level transitions (inventory purge), win/loss screens, score |
| `commands.c/h` | every command handler, sentinel sweep tick, trace check, dispatcher |
| `levels.c/h` | 45 level definitions, all structs, file/node macros |
| `network.c/h` | node lookup, file unlock/decrypt bitmasks |
| `puzzles.c/h` | Caesar, reverse, binary, hex, XOR, Vigenère, Base64, Atbash, rail fence, onion |
| `utils.c/h` | detection bar, prompt with `[T-n]`/`[TRACE n]`, briefings, `slow_print` |
| `save.c/h` | `terminal_breach.sav` (key=value, v3 format) |

## Access Tiers
`GUEST` (start) → `USER` (`login <user_password>`) → `ADMIN` (`login <solution>`, completes the level)

## Commands
| Command | From | Notes |
|---|---|---|
| `help` `ls [-a]` `cat` `clear` `whoami` `status` `hint` `login` `exit` `savegame` `loadgame` | L1 | `hint` costs detection from L26 |
| `logout` `decrypt` `save` `inventory` | L2 | |
| `scan` `connect <ip\|host>` | L3 | |
| `bruteforce` | L5 | 2× per-fail; refused (not consumed) on the wrong host |
| `override` | L7 | 3× per-fail; must be on the level's override host (first needed L8) |
| `combine [slots]` `drop <n\|all>` | L16 | inventory clears on every level transition |
| `grep <pat> <file>` | L20 | |
| `wipe` | L26 | once per log host: −1× per-fail |
| `knock <host> <port>` | L27 | wrong port resets sequence, ½ per-fail |
| `unlock <file> <code>` | L28 | wrong codes escalate: ½, 1, 1½ … × per-fail |
| `decrypt <file> <key>` | L36 | `[KEY]` files; wrong key = garbage + ¼ |
| `su <password>` | L36 | root on THIS host only (prompt `#`), opens `[ROOT]` files; fail ½ |

## Detection Costs
| Event | Cost |
|---|---|
| wrong login | 1× per-fail |
| unknown / locked command | ¼ |
| bad connect target, insufficient tier, filtered host, wrong knock, NO ROUTE, re-sealed window, failed su | ½ |
| wrong manual key | ¼ |
| routing rejected | 1× |
| honeypot connect | 2× |
| sentinel sweep catches you on a watched host | 1× |
| bruteforce / override | 2× / 3× |
| adaptive repeat (L25, L32, L34, L35, L43–L45) | +1, +2, +3 … from the 4th identical command in a row |

## Cipher Families
| Type | First | Decode |
|---|---|---|
| Reverse, Caesar | L2, L3 | reverse string / subtract shift |
| Binary | L5 | 8-bit tokens → ASCII |
| Hex, XOR | L16 | hex bytes → ASCII / ⊕ repeating key |
| Vigenère | L17 | subtract repeating keyword |
| Base64 | L18 | standard |
| Atbash, Rail fence | L26 | A↔Z mirror / zig-zag over N rails |
| Onion | L27 | stacked layers, **one per `decrypt`**, `ls` shows `[ONI k/n]` |

## Act IV Mechanics (L26–L35)
- **Sentinel sweeps:** every N commands (all commands count). Being on a WATCHED host when it fires costs 1× per-fail. `status` shows the countdown, and you get a warning one command before.
- **Tripwire:** first connect to an ALARMED host starts a reverse trace (`[TRACE n]` in prompt) that never stops.
- **Port knocking:** FILTERED hosts need `knock` in exact order before `connect`.
- **Keypads:** `[PIN]` files. Codes come from `grep` on logs and riddles.
- **Onion progress persists:** split a long peel across two visits to dodge a sweep.

## Act V Mechanics (L36–L45)
- **Manual keys:** `[KEY]` files keep no key on disk. Find it, then `decrypt <file> <key>`.
- **Per-host root:** `su <pw>` works on the current host only. Root passwords hide on *other* hosts.
- **Links:** hosts with a link list only accept connections from those neighbours. Read the link map first.
- **Rotating sentry:** each sweep watches the next host in a fixed order. `status` shows now and next.
- **Knock windows:** an opened firewall re-seals after N commands, and `status` counts down.

## Level Table
| # | Level | Diff | Max/Fail | Timer | Special |
|---|---|---|---|---|---|
| 1 | Tutorial System | EASY | 100/10 | — | ls -a |
| 2 | Employee PC | EASY | 80/15 | — | reverse |
| 3 | Office Server | MEDIUM | 70/20 | — | scan, Caesar-13 |
| 4 | Bank Network | MEDIUM | 60/25 | — | key file |
| 5 | Secure Vault | HARD | 50/12 | 300 | bruteforce, binary |
| 6 | Darknet Node | HARD | 40/35 | — | one-shot budget |
| 7 | Prometheus Military Grid | HARD | 60/20 | — | connect side-effect |
| 8 | AI Core System | EXTREME | 100/30 | 180 | override |
| 9 | Corporate Espionage | HARD | 55/18 | — | key on other node |
| 10 | Power Grid Control | HARD | 50/15 | 240 | 2 fragments |
| 11 | Intelligence Agency | VERY HARD | 45/22 | — | decode chain |
| 12 | Satellite Network | VERY HARD | 40/20 | 200 | 5 nodes |
| 13 | Underground Market | EXTREME | 35/12 | — | 3 frags, bruteforce |
| 14 | Quantum Research Lab | EXTREME | 50/8 | 200 | bruteforce + override |
| 15 | GHOST Protocol | LEGENDARY | 80/15 | 120 | 4 frags, both |
| 16 | Crypto Exchange Heist | MYTHIC | 80/20 | 240 | hex, XOR, combine |
| 17 | Industrial SCADA Sabotage | MYTHIC | 70/25 | 240 | Vigenère, routing |
| 18 | Telecom Backbone Hijack | MYTHIC++ | 70/20 | 200 | Base64, routing |
| 19 | Spy Satellite Imagery Vault | APEX | 60/30 | 200 | decoy vault |
| 20 | Forensic Counter-Hack | APEX | 70/20 | 300 | grep |
| 21 | Darknet Auction | APEX+ | 130/20 | 240 | 2 honeypots, both |
| 22 | Black Site Dossier | LEGENDARY+ | 80/25 | 180 | 3 ciphers |
| 23 | Pacemaker Killswitch | LEGENDARY+ | 90/30 | 240 | 6-hop route |
| 24 | Cobalt Mirage Showdown | LEGENDARY++ | 200/30 | 180 | both |
| 25 | The Architect | TRANSCENDENT | 260/40 | 120 | adaptive, both |
| 26 | Lazarus Seed | OMEGA | 100/25 | 240 | Atbash, rail, wipe |
| 27 | Onion Relay | OMEGA | 100/25 | 240 | onion, knock |
| 28 | Sentinel Grid | OMEGA+ | 100/20 | 270 | sweeps /6, keypad |
| 29 | Silent Alarm | OMEGA+ | 100/25 | 300 | tripwire 60s |
| 30 | Mirror Maze | SINGULARITY | 110/25 | 270 | 3 hidden honeypots |
| 31 | Deadman's Vault | SINGULARITY | 150/25 | 270 | sweeps /7, both |
| 32 | Hydra Botnet | SINGULARITY+ | 120/30 | 270 | adaptive, sweeps /8 |
| 33 | Quantum Ghost | EVENT HORIZON | 120/30 | 300 | trip 75s, riddle PIN |
| 34 | Lazarus Core | EVENT HORIZON+ | 180/30 | 300 | everything, 2 attempts |
| 35 | Zero Point | ZERO POINT | 200/35 | 360 | sweeps /5, trip 90s |
| 36 | Cold Storage | ABYSS | 120/25 | 420 | 4 manual keys |
| 37 | Root of Trust | ABYSS | 130/25 | 450 | su chain |
| 38 | Pivot Point | ABYSS+ | 130/25 | 480 | links, watched jumpbox |
| 39 | Carousel | ABYSS+ | 140/25 | 480 | rotating sentry x4 |
| 40 | Knock Window | ABYSS++ | 140/25 | 480 | re-sealing knocks, trip 60s |
| 41 | Interpol Mesh | OBLIVION | 160/25 | 540 | links, 2 su, bruteforce |
| 42 | Five Eyes | OBLIVION | 170/30 | 540 | rotation x5, override, trip 90s |
| 43 | Black Ledger | OBLIVION+ | 200/30 | 600 | everything, adaptive |
| 44 | Mirror Protocol | NULL | 220/35 | 600 | everything, 2 attempts |
| 45 | Null Pointer | NULL POINTER | 230/35 | 720 | everything, finale |

## Score & Rank
`level score = level# × 1000 − fails × 100 − detection × 5` (min 0). Max 1,035,000; verified clean run 1,026,085.
Rank by total failed logins: 0 GHOST LEGEND · 1–4 PHANTOM · 5–10 SPECTRE · 11–20 AGENT · 21+ ROOKIE.

## Design Rules for New Levels
- Keep `detection_max > 5 × detection_per_fail` when bruteforce **and** override are mandatory.
- Use `bf_node/bf_file`, `ov_node/ov_file` on the Level, not code in commands.c.
- Encode with the same algorithm `puzzles.c` decodes. The onion spec lists layers outermost first.
- Add a scripted solution and run it with `TB_FAST=1 TB_START_LEVEL=N` before shipping.
- The Makefile rebuilds everything on any header change. Never ship a build made from stale objects.
