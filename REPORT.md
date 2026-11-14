# Terminal Breach v4.0 — Technical Project Report

## Executive Summary

Terminal Breach is a terminal-based hacking puzzle game written entirely in C11. The player is GHOST, an elite black-hat operator, working through 35 escalating network-intrusion scenarios in four acts. Each level is a self-contained puzzle that introduces at most one or two new mechanics while building on everything before it: navigating multi-node networks, decoding files with ten encoding schemes, managing a tightening detection budget, racing countdown timers, and assembling passwords from fragments scattered across machines.

Version 4.0 adds Act IV, *The Lazarus Protocol* (levels 26–35). It brings seven new mechanics: Atbash and rail-fence ciphers, multi-layer "onion" payloads, port knocking, keypad locks, log wiping, sentinel sweeps, and silent-alarm tripwires. It also includes a correctness pass that fixed ten defects, three of which made original levels impossible to win.

The game has no external dependencies. It compiles to a single binary using only the C standard library and POSIX `nanosleep`, and runs in any ANSI terminal. The codebase is about 6,000 lines across seven modules. Every level has a scripted solution that is run against the real binary, and the full 35-level game has been completed in a single session with zero failures.

---

## Architecture and Module Design

The project is split into seven modules, each with a `.c` implementation and a `.h` interface. All modules depend on `levels.h` for the shared data structures, and no implementation module reaches into another except through those types.

```
main.c          game loop, level transitions, win/loss screens
  ├── commands.c    command handlers, dispatcher, sweep + trace ticks
  ├── utils.c       rendering: prompt, detection bar, briefings
  └── (uses everything below through commands.c)

commands.c
  ├── network.c     node/file lookup and bitmask state helpers
  ├── puzzles.c     all ten decoders + the onion layer engine
  └── save.c        save/load to disk

levels.c        all 35 level definitions (data only)
levels.h        every shared data structure and constant
```

`main.c` knows nothing about how commands work: it calls `process_command` and reacts to the `level_complete`, `game_over` and `load_pending` flags. `commands.c` contains no level-specific branches for the new content. Every Act IV mechanic is driven by data fields on the level, node or file. `levels.c` never touches `GameState`.

| Module | Lines |
|---|---|
| levels.c / levels.h | 3,458 / 214 |
| commands.c / commands.h | 1,143 / 45 |
| puzzles.c / puzzles.h | 328 / 59 |
| main.c | 246 |
| utils.c / utils.h | 209 / 49 |
| save.c / save.h | 88 / 25 |
| network.c / network.h | 75 / 40 |

---

## Data Structures

All core structures live in `levels.h`. They nest naturally (`GameFile` inside `NetworkNode` inside `Level`), with `GameState` as the single mutable companion to the immutable level array.

### GameFile

```c
typedef struct {
    char       name[64];
    char       content[1024];
    Permission min_perm;
    int        hidden;
    int        encrypted;
    int        cipher_shift;     /* Caesar shift, or rail count     */
    int        puzzle_type;      /* PUZZLE_* constant               */
    int        locked;
    char       cipher_key[64];   /* XOR/Vigenère key or onion spec  */
    char       unlock_code[16];  /* keypad PIN (v4.0)               */
} GameFile;
```

`content` always holds the raw (possibly encoded) text and is never changed during play. Decoders write into a caller-supplied buffer. `cipher_key` was widened from 32 to 64 bytes in v4.0 because it now also holds onion layer specifications such as `b64>rev>hex>atb`. A non-empty `unlock_code` turns a locked file into a keypad file: it is listed as `[PIN]` in `ls` and opened with `unlock`.

### NetworkNode

```c
typedef struct {
    char      ip[20], hostname[32], description[256];
    GameFile  files[12];
    int       file_count;
    Permission min_perm;
    int       is_entry, discovered;
    int       is_honeypot;          /* v3.0 */
    char      route_prev[32];       /* v3.0 */
    int       is_watched;           /* v4.0: sentinel target       */
    int       has_logs;             /* v4.0: 'wipe' allowed        */
    int       trip_seconds;         /* v4.0: silent-alarm trace    */
    char      knock_seq[48];        /* v4.0: port-knock sequence   */
} NetworkNode;
```

`discovered` is the only node field written during play (by `scan`, and reset by `reset_level`). Every other behaviour flag is static data, so a node's whole personality can be read from its initialiser.

### Level

```c
typedef struct {
    int  id;
    char name[80], objective[512], difficulty[16], warnings[256];
    NetworkNode nodes[8];
    int  node_count;
    char solution_password[64], user_password[64], hint[512];
    int  max_attempts, detection_max, detection_per_fail;
    int  has_timer, timer_seconds;
    unsigned int available_cmds;
    int  adaptive_detection;        /* v3.0 */
    int  sweep_interval;            /* v4.0 */
    int  hint_cost;                 /* v4.0 */
    char bf_node[32], bf_file[64];  /* v4.0: bruteforce target */
    char ov_node[32], ov_file[64];  /* v4.0: override target   */
} Level;
```

`MAX_NODES` was raised from 6 to 8 for the larger Act IV topologies. The `bf_*` and `ov_*` fields replace about 120 lines of hard-coded `if (current_level == N)` branches in `commands.c`. Legacy levels are wired through a single table in `wire_legacy_targets()`.

### GameState

```c
typedef struct {
    int        current_level, current_node;
    Permission permission;
    int        detection;
    int        node_files_unlocked[8], node_files_decrypted[8];
    char       inventory[30][256];
    int        inv_count, attempts, scanned;
    int        bruteforce_used, override_used, level_complete, game_over;
    int        nodes_connected, last_node, last_cmd_hash, repeat_streak;
    /* v4.0 */
    int        level_cmds;                 /* drives sentinel sweeps   */
    int        knock_progress[8], knock_open, wiped, keypad_fails;
    time_t     trace_deadline;             /* 0 = no alarm tripped     */
    unsigned char file_layers[8][12];      /* onion layers peeled      */
    int        load_pending;
    int        total_fails, total_commands;
    time_t     level_start, game_start;
    int        score, level_scores[35];
} GameState;
```

`GameState` is the only mutable object. Per-level fields are reset explicitly in `reset_level()`. That function also fixes a v3 defect: `nodes_connected`, `last_node` and the adaptive-detection streak were never reset, so routing state leaked from one level into the next.

---

## Permission System

Three ordered tiers exist: `PERM_GUEST` (0), `PERM_USER` (1) and `PERM_ADMIN` (2). Checks use `>` comparisons, so a higher tier always satisfies a lower requirement. GUEST is the default at every level start. USER comes from the level's `user_password`, or on level 8 from `bruteforce`. ADMIN comes only from the solution password and completes the level. A failed `connect` for lack of tier costs half a per-fail.

---

## Command Progression System

Each level's `available_cmds` is an `unsigned int` bitmask. Twenty-five bits are in use. The dispatcher runs a known command only if its bit is set. A recognised but locked command, or an unknown one, prints a message and costs a quarter of a per-fail. Level transitions diff the previous and next masks and announce every newly unlocked command. In v3 this announcement silently skipped `grep`, `combine`, `hint` and `logout`.

| Command | Unlocked | Purpose |
|---|---|---|
| `help`, `ls [-a]`, `cat`, `clear`, `whoami`, `status`, `hint`, `login`, `exit`, `savegame`, `loadgame` | L1 | basics |
| `logout`, `decrypt`, `save`, `inventory` | L2 | decoding and notes |
| `scan`, `connect` | L3 | multi-node navigation |
| `bruteforce` | L5 | force a lock (2× per-fail) |
| `override` | L7 | neural override (3× per-fail) |
| `combine`, `drop` | L16 | fragment assembly, slot removal |
| `grep` | L20 | log forensics |
| `wipe` | L26 | scrub logs once per host (−1× per-fail) |
| `knock <host> <port>` | L27 | port knocking |
| `unlock <file> <code>` | L28 | keypads |

---

## Detection System

Every level has a `detection_max` ceiling and a `detection_per_fail` unit cost. Reaching the ceiling ends the run. All increases go through `detection_add()`, which clamps, redraws the bar and sets `game_over`.

| Event | Cost (× per-fail) |
|---|---|
| Wrong login | 1 |
| Unknown or locked command | ¼ |
| Bad connect target / insufficient tier / FILTERED host / wrong knock | ½ |
| Routing rejected | 1 |
| Honeypot connect | 2 |
| Sentinel sweep while on a watched host | 1 |
| `bruteforce` | 2 |
| `override` | 3 |
| Wrong keypad code (n-th this level) | ½ × n |
| `hint` (L26+) | fixed `hint_cost` |
| Adaptive repeat (4th+ identical command in a row) | +1, +2, +3 … |
| `wipe` | −1 (once per log host) |

**Budget invariant.** A level that requires both `bruteforce` and `override` spends 5× per-fail on them alone, so `detection_max` must exceed that figure, with room for at least one mistake. The v4.0 audit found that the original levels 21, 24 and 25 broke this rule: their mandatory cost was 100 of 100, 150 of 100 and 200 of 120 respectively, which made them mathematically unwinnable. Their ceilings were raised to 130, 200 and 260. The rule was then applied to every new level. Act IV levels add `wipe` as a planned way to win back budget.

---

## Puzzle Algorithms

`puzzles.c` implements ten decoders. Each takes a source string, writes into a bounded buffer and returns the number of characters written. `decode_content()` dispatches on `puzzle_type`.

| Type | Since | Algorithm |
|---|---|---|
| Reverse | L2 | reverse the string |
| Caesar | L3 | `((c - base - shift % 26 + 26) % 26) + base` on letters only |
| Binary | L5 | 8-digit tokens → byte, stops at newline or `[` |
| Hex | L16 | whitespace-separated hex pairs → bytes |
| XOR | L16 | hex decode, then ⊕ a repeating ASCII key |
| Vigenère | L17 | subtract a repeating keyword; the key index advances on letters only |
| Base64 | L18 | standard alphabet, padding and whitespace ignored |
| Atbash | L26 | letter → mirror letter (`'Z' - (c - 'A')`), self-inverse |
| Rail fence | L26 | zig-zag transposition over N rails |
| Onion | L27 | an ordered stack of any of the above |

### Rail Fence

To decode, the zig-zag is replayed to find which rail each position falls on. The ciphertext is sliced into per-rail runs of those lengths, and the zig-zag is walked again taking the next character from each rail in turn. This runs in O(n) with two passes and no allocation. Degenerate inputs (fewer than two rails, or at least as many rails as characters) fall back to identity.

### Onion Payloads

An onion file's `cipher_key` holds a `>`-separated list of layers, outermost first, for example `b64>rev>hex>atb`. Tokens can take arguments (`rail:3`, `caesar:9`, `xor:KEY`, `vig:KEY`). `onion_peel(content, spec, k)` applies the first *k* layers through a pair of ping-pong buffers. `GameState.file_layers[node][file]` records how many layers the player has removed, so:

- each `decrypt` peels exactly one layer, names the shell it removed, and shows the intermediate text;
- `cat` shows the current partially-peeled state, and `ls` shows `[ONI k/n]`;
- progress survives leaving the node. Level 35 relies on this: its four-shell onion sits on a host swept every five commands, so it can't be peeled in a single visit.

All 84 encrypted files in the game were checked by decoding them through the C decoders. Every Act IV fragment was produced by an independent Python encoder, so the encoder and the decoder check each other.

---

## Network Navigation Model

The player always occupies one node. `scan` reveals every non-entry node. `connect` then runs a fixed sequence of gates, and the order matters: v3 printed "CONNECTION ESTABLISHED" before checking routing and then refused the connection.

1. target exists (else ½ per-fail) and is not the current node
2. target discovered and permission tier sufficient
3. **knock gate**: if `knock_seq` is set and the sequence has not been completed, the host is FILTERED (½)
4. **routing**: if `route_prev` is set, that host must already appear in `nodes_connected` (1×)
5. connection established; a honeypot adds 2×
6. post-connect: watched-host warning; a **tripwire** starts `trace_deadline` on first touch; and the three legacy connect side-effects (L7 firebase, L12 orion-core, L15 fragment-delta) fire.

### Port Knocking

`knock <host> <port>` advances `knock_progress[node]` when the port matches the next expected value. A wrong port resets the progress and costs half a per-fail. When the sequence is complete, the node's bit in `knock_open` is set. Progress is kept between unrelated commands, so knocks don't have to be consecutive.

### Sentinel Sweeps

`process_command()` now separates parsing and pre-checks from a `dispatch()` call, followed by a `sentinel_tick()`. On levels with `sweep_interval > 0`, every command (including typos, `status` and `help`) increments `level_cmds`. When it reaches a multiple of the interval, a sweep runs: if the player is on an `is_watched` node, they pay one per-fail. One command before a sweep, a player standing on a watched node gets a warning. `status` always shows the countdown. This turns command order into a resource: players align the sweep phase with cheap filler commands, and interleave different ones so they don't trigger adaptive detection.

### Silent Alarm (Tripwire)

The first connection to a node with `trip_seconds > 0` sets `trace_deadline = now + trip_seconds`. The deadline is checked at the top of every command, just like the level timer, and shows in the prompt as `[TRACE n]`. Unlike the level timer, it starts only when the player chooses to touch the alarmed host, so the design challenge becomes "prepare everything first, then commit."

---

## Timer System

Timed levels check `time(NULL) - level_start` against `timer_seconds` at the top of `process_command`. In v4.0 the prompt itself renders live countdowns (`[T-212]` and, once tripped, `[TRACE 41]`), so players no longer need `status` to watch the clock. Act IV timers run from 240 to 360 seconds. Intensity there comes from stacked mechanics rather than ever-shorter clocks, since the animated output (`slow_print`) puts a practical floor on how fast commands can be issued.

---

## Scoring System

```
level_score = level × 1000 − failed_logins × 100 − detection × 5   (minimum 0)
```

The theoretical maximum over 35 levels is 630,000. Mandatory bruteforce and override costs make a perfect score impossible on some levels. The verified clean playthrough scores 624,135. Rank is decided by total failed logins: 0 GHOST LEGEND, 1–4 PHANTOM, 5–10 SPECTRE, 11–20 AGENT, 21+ ROOKIE (thresholds were rescaled from the 16-level game).

---

## Inventory System

The inventory holds 30 strings of up to 256 bytes. `save` appends, `inventory` lists, `combine [slots]` concatenates into a new slot, and `drop <n|all>` removes entries. In v3 the 20-slot inventory filled permanently around level 20, because nothing could ever remove an item. v4.0 clears the inventory at each level transition (fragments never carry between targets). This also makes the slot numbers in every walkthrough deterministic.

---

## Save and Load System

Progress is saved to `terminal_breach.sav` as plain `KEY=value` lines. The v3 format writes `VERSION`, `LEVEL`, `SCORE`, `TOTAL_FAILS`, `TOTAL_CMDS`, one `LSCORE_i` per completed level, and the inventory. Unknown keys are ignored, so older saves still load.

Three load defects were fixed in v4.0:

- **Skipped level.** Loading set `level_complete`, which the main loop treats as "advance to `current_level + 1`". A load therefore resumed one level *past* the save. Load now sets `load_pending`, and the loop restarts the saved level itself.
- **Duplicated inventory.** Items were appended without clearing, so every load doubled the inventory.
- **Unchecked level index.** An edited or corrupt `LEVEL=` value indexed past the level array. It is now clamped.

---

## Level Design Philosophy

**Act I (L1–8): Breaking In.** One mechanic per level: files, `decrypt`, multi-node navigation, the user tier, timers and `bruteforce`, connect side-effects, and finally `override` with a three-fragment password.

**Act II (L9–15): Going Deeper.** Information management under constraint: keys on different nodes than their ciphertext, two-step decode chains, five- and six-node maps, and the first levels that need both special commands.

**Act III (L16–25): The Architect.** Four new cipher families, `combine`, routing chains, honeypots, `grep` forensics and adaptive detection on the boss level.

**Act IV (L26–35): The Lazarus Protocol.** Each level adds exactly one new pressure, and then the last levels combine them:

| Level | Adds |
|---|---|
| 26 Lazarus Seed | Atbash, rail fence, `wipe`, `drop`, hint cost |
| 27 Onion Relay | onion payloads, port knocking |
| 28 Sentinel Grid | sentinel sweeps, keypads |
| 29 Silent Alarm | tripwire trace |
| 30 Mirror Maze | *unlabelled* honeypots, identified only through `grep` on DNS TTLs |
| 31 Deadman's Vault | sweeps + PIN rotation + bruteforce + override |
| 32 Hydra Botnet | adaptive detection returns alongside sweeps |
| 33 Quantum Ghost | knock + tripwire + keypad riddle (Fibonacci) |
| 34 Lazarus Core | everything, eight nodes, two attempts |
| 35 Zero Point | everything at tighter parameters, plus the narrative twist |

The story ends with a reveal: the final user credential is `GHOST`, the player's own identity from `whoami`, and the final password is `GH0ST_1S_TH3_ARCH1TECT`.

---

## Level Reference

| # | Name | Difficulty | Nodes | Max | Per-fail | Attempts | Timer | Key mechanic |
|---|---|---|---|---|---|---|---|---|
| 1 | Tutorial System | EASY | 1 | 100 | 10 | 6 | — | navigation |
| 2 | Employee PC | EASY | 1 | 80 | 15 | 5 | — | reverse |
| 3 | Office Server | MEDIUM | 2 | 70 | 20 | 6 | — | scan, Caesar |
| 4 | Bank Network | MEDIUM | 2 | 60 | 25 | 5 | — | key file |
| 5 | Secure Vault | HARD | 1 | 50 | 12 | 4 | 300 | bruteforce, binary |
| 6 | Darknet Node | HARD | 1 | 40 | 35 | 4 | — | one-shot budget |
| 7 | Prometheus Military Grid | HARD | 3 | 60 | 20 | 3 | — | side-effect |
| 8 | AI Core System | EXTREME | 2 | 100 | 30 | 3 | 180 | override |
| 9 | Corporate Espionage | HARD | 3 | 55 | 18 | 5 | — | remote key |
| 10 | Power Grid Control | HARD | 4 | 50 | 15 | 5 | 240 | two fragments |
| 11 | Intelligence Agency | VERY HARD | 4 | 45 | 22 | 4 | — | decode chain |
| 12 | Satellite Network | VERY HARD | 5 | 40 | 20 | 4 | 200 | five nodes |
| 13 | Underground Market | EXTREME | 4 | 35 | 12 | 3 | — | bruteforce |
| 14 | Quantum Research Lab | EXTREME | 5 | 50 | 8 | 3 | 200 | both specials |
| 15 | GHOST Protocol | LEGENDARY | 6 | 80 | 15 | 3 | 120 | four fragments |
| 16 | Crypto Exchange Heist | MYTHIC | 4 | 80 | 20 | 4 | 240 | hex, XOR |
| 17 | Industrial SCADA Sabotage | MYTHIC | 5 | 70 | 25 | 4 | 240 | Vigenère, routing |
| 18 | Telecom Backbone Hijack | MYTHIC++ | 5 | 70 | 20 | 4 | 200 | Base64 |
| 19 | Spy Satellite Imagery Vault | APEX | 5 | 60 | 30 | 3 | 200 | decoy vault |
| 20 | Forensic Counter-Hack | APEX | 5 | 70 | 20 | 4 | 300 | grep |
| 21 | Darknet Auction | APEX+ | 6 | 130 | 20 | 3 | 240 | honeypots |
| 22 | Black Site Dossier | LEGENDARY+ | 5 | 80 | 25 | 3 | 180 | three ciphers |
| 23 | Pacemaker Killswitch | LEGENDARY+ | 7 | 90 | 30 | 3 | 240 | six-hop route |
| 24 | Cobalt Mirage Showdown | LEGENDARY++ | 5 | 200 | 30 | 3 | 180 | both specials |
| 25 | The Architect | TRANSCENDENT | 6 | 260 | 40 | 2 | 120 | adaptive |
| 26 | Lazarus Seed | OMEGA | 5 | 100 | 25 | 3 | 240 | Atbash, rail, wipe |
| 27 | Onion Relay | OMEGA | 5 | 100 | 25 | 3 | 240 | onion, knock |
| 28 | Sentinel Grid | OMEGA+ | 5 | 100 | 20 | 3 | 270 | sweeps, keypad |
| 29 | Silent Alarm | OMEGA+ | 6 | 100 | 25 | 3 | 300 | tripwire |
| 30 | Mirror Maze | SINGULARITY | 7 | 110 | 25 | 3 | 270 | hidden honeypots |
| 31 | Deadman's Vault | SINGULARITY | 6 | 150 | 25 | 3 | 270 | sweeps + both |
| 32 | Hydra Botnet | SINGULARITY+ | 7 | 120 | 30 | 3 | 270 | adaptive + sweeps |
| 33 | Quantum Ghost | EVENT HORIZON | 6 | 120 | 30 | 3 | 300 | trip + riddle |
| 34 | Lazarus Core | EVENT HORIZON+ | 8 | 180 | 30 | 2 | 300 | everything |
| 35 | Zero Point | ZERO POINT | 8 | 200 | 35 | 2 | 360 | everything, tighter |

---

## Verification

Every level has a scripted solution (the same scripts behind `WALKTHROUGH.md`). Each script runs against the release binary with `TB_FAST=1 TB_START_LEVEL=n` and must meet all of the following:

- the level is breached;
- no sentinel sweep catches the player;
- no honeypot is tripped;
- no error message of any kind appears (missing file, routing rejection, filtered host, wrong knock or code, denied login, locked command).

All 35 pass. The scripts are also concatenated and played as one continuous game, which exercises every level transition, the inventory purge and the win screen. That run finishes 35/35 with zero failed logins, rank GHOST LEGEND and 624,135 points.

Targeted negative tests covered: wrong knocks (reset + penalty), knocking a host with no sequence, connecting to a filtered host, escalating keypad penalties, bruteforce on the wrong host (refused, not consumed), routing rejection before connection, honeypot spikes, trace expiry after a real 60-second wait, and save → load → load (same level, no duplicated inventory). The build is warning-free under `-Wall -Wextra -std=c11`.

---

## Defects Fixed in v4.0

| Defect | Effect | Fix |
|---|---|---|
| L21/L24/L25 budgets | mandatory bruteforce + override ≥ ceiling, so unwinnable | ceilings raised to 130 / 200 / 260 |
| Bruteforce on wrong host consumed its single use | soft-lock on L5, L13–15, L21, L24, L25 | target host is data-driven; a wrong host is refused without consuming the use |
| `loadgame` advanced one level | saved level skipped | `load_pending` restarts the saved level |
| `loadgame` appended inventory | duplicates on every load | inventory reset before reading |
| Unchecked `LEVEL=` in save | array overrun | clamped to range |
| `nodes_connected` never reset | routing could be bypassed on later levels | reset per level; entry node pre-marked |
| Routing checked after "CONNECTION ESTABLISHED" | misleading output | all gates run before any connect message |
| L23 `pacemaker-net` referenced but missing | briefing and hint could not be followed | node added as the final routing hop |
| Signed overflow in adaptive hash | undefined behaviour | unsigned arithmetic |
| Inventory could never shrink | full at ~L20 | `drop`, 30 slots, purge on transition |

---

## Technical Design Decisions

**Immutable level data.** Level structs are written once at startup. Every per-play fact (unlocks, decrypts, onion peel depth, knock progress, wipes, trace deadline) lives in `GameState`, so resetting a level means resetting fields, never re-initialising data.

**Data-driven mechanics.** v3 attached special behaviour through `if (current_level == N)` branches. v4.0 moved bruteforce and override targets into level fields and added every new mechanic as a flag on a node or level. Adding Act IV needed no level-specific code in `commands.c`, and a level designer can see a node's entire behaviour in its initialiser:

```c
add_node(l, "13.13.0.99", "lazarus-core", "LAZARUS core.", USR, 0);
route_after(l, "soul-gate");
set_trip(l, 60);
mark_watched(l);
FHLOCK(".core_frag", "HVH", PUZZLE_ATBASH, 0, NULL);
```

**Composable ciphers.** Onion payloads reuse the existing decoders as layers instead of adding new algorithms. One spec string can express any stack, and peeling one layer at a time turns decoding from a single command into a decision that interacts with sweeps and timers.

**No dynamic memory.** There is no `malloc` anywhere. Every buffer is fixed-size and bounded with `strncpy` or `snprintf`. Raising `MAX_NODES` to 8 grew the static level array to about 4.0 MB, which is acceptable for a desktop binary.

**Testability hooks.** `TB_FAST` turns off `slow_print` delays and `TB_START_LEVEL` starts at any level. Together they make the full 35-level regression run in seconds, and they double as a practice mode for players.

**No terminal library.** Rendering is plain ANSI escape codes with `printf`. Colour, the detection bar, the live prompt clocks and `slow_print` give the atmosphere without ncurses.

---

## Known Constraints and Limitations

**Fixed capacity.** Files per node (12), nodes per level (8), inventory (30) and levels (35) are compile-time constants. The file-state bitmasks are `int`, which limits a node to 32 files.

**Sweep timing is command-based, not time-based.** Typos count toward the next sweep. This is deliberate, but it can surprise players. The prompt shows timers, but not the sweep countdown, which is only in `status`.

**Legacy side-effects remain hard-coded.** The three connect side-effects from levels 7, 12 and 15 still use hostname checks in `cmd_connect`. They are candidates for the same data-driven treatment.

**Byte-level strings.** Passwords are compared case-sensitively with `strcmp`. ASCII art uses UTF-8 box characters, which need a UTF-8 terminal.

**Single save slot.** Saves go to `terminal_breach.sav` in the working directory.

---

*Terminal Breach v4.0: 35 levels, verified end-to-end, zero compiler warnings, no external dependencies.*
