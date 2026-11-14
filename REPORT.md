# Terminal Breach v5.0 — Technical Project Report

## Executive Summary

Terminal Breach is a terminal-based hacking puzzle game written entirely in C11. The player is GHOST, an elite black-hat operator, working through 45 escalating network-intrusion scenarios in five acts. Each level is a self-contained puzzle that introduces at most one or two new mechanics while building on everything before it: navigating multi-node networks, decoding files with ten encoding schemes, managing a tightening detection budget, racing countdown timers, and assembling passwords from fragments scattered across machines.

Version 4.0 adds Act IV, *The Lazarus Protocol* (levels 26–35). It brings seven new mechanics: Atbash and rail-fence ciphers, multi-layer "onion" payloads, port knocking, keypad locks, log wiping, sentinel sweeps, and silent-alarm tripwires. It also includes a correctness pass that fixed ten defects, three of which made original levels impossible to win.

Version 5.0 adds Act V, *Erasure* (levels 36–45), the longest levels in the game at 7–11 hosts and 25–40 commands each. It brings five more mechanics: manual keys the player must find and type, per-host root via `su`, link-only topologies, a rotating sentry, and knock windows that re-seal. It also fixes a build defect: the Makefile had no header dependencies, so changing a shared struct could silently corrupt every level.

The game has no external dependencies. It compiles to a single binary using only the C standard library and POSIX `nanosleep`, and runs in any ANSI terminal. The codebase is about 7,600 lines across seven modules. Every level has a scripted solution that is run against the real binary, and the full 45-level game has been completed in a single session with zero failures.

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

levels.c        all 45 level definitions (data only)
levels.h        every shared data structure and constant
```

`main.c` knows nothing about how commands work: it calls `process_command` and reacts to the `level_complete`, `game_over` and `load_pending` flags. `commands.c` contains no level-specific branches for the new content. Every Act IV mechanic is driven by data fields on the level, node or file. `levels.c` never touches `GameState`.

| Module | Lines |
|---|---|
| levels.c / levels.h | 4,892 / 224 |
| commands.c / commands.h | 1,309 / 46 |
| puzzles.c / puzzles.h | 328 / 59 |
| main.c | 256 |
| utils.c / utils.h | 212 / 49 |
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
    int        manual_key;       /* v5.0: key must be typed          */
    int        needs_root;       /* v5.0: requires su on this host   */
} GameFile;
```

`content` always holds the raw (possibly encoded) text and is never changed during play. Decoders write into a caller-supplied buffer. `cipher_key` was widened from 32 to 64 bytes in v4.0 because it now also holds onion layer specifications such as `b64>rev>hex>atb`. A non-empty `unlock_code` turns a locked file into a keypad file: it is listed as `[PIN]` in `ls` and opened with `unlock`. In v5.0, `manual_key` means the key is still stored (so the game can check it) but never applied automatically: the player has to type it. `needs_root` hides the file behind `su` on its host.

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
    char      su_pass[32];          /* v5.0: root password         */
    char      link_from[96];        /* v5.0: allowed source hosts  */
    int       watch_slot;           /* v5.0: rotating-sentry slot  */
    int       knock_window;         /* v5.0: commands before reseal */
} NetworkNode;
```

`discovered` is the only node field written during play (by `scan`, and reset by `reset_level`). Every other behaviour flag is static data, so a node's whole personality can be read from its initialiser.

### Level

```c
typedef struct {
    int  id;
    char name[80], objective[512], difficulty[16], warnings[256];
    NetworkNode nodes[12];
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
    int  watch_cycle;               /* v5.0: rotating-sentry length */
} Level;
```

`MAX_NODES` was raised from 6 to 8 for Act IV, and to 12 for Act V. The `bf_*` and `ov_*` fields replace about 120 lines of hard-coded `if (current_level == N)` branches in `commands.c`. Legacy levels are wired through a single table in `wire_legacy_targets()`.

### GameState

```c
typedef struct {
    int        current_level, current_node;
    Permission permission;
    int        detection;
    int        node_files_unlocked[12], node_files_decrypted[12];
    char       inventory[30][256];
    int        inv_count, attempts, scanned;
    int        bruteforce_used, override_used, level_complete, game_over;
    int        nodes_connected, last_node, last_cmd_hash, repeat_streak;
    /* v4.0 */
    int        level_cmds;                 /* drives sentinel sweeps   */
    int        knock_progress[12], knock_open, wiped, keypad_fails;
    time_t     trace_deadline;             /* 0 = no alarm tripped     */
    unsigned char file_layers[12][12];     /* onion layers peeled      */
    int        load_pending;
    int        su_mask;                    /* v5.0: root per host      */
    int        knock_open_at[12];          /* v5.0: window start       */
    int        total_fails, total_commands;
    time_t     level_start, game_start;
    int        score, level_scores[45];
} GameState;
```

`GameState` is the only mutable object. Per-level fields are reset explicitly in `reset_level()`. That function also fixes a v3 defect: `nodes_connected`, `last_node` and the adaptive-detection streak were never reset, so routing state leaked from one level into the next.

---

## Permission System

Three ordered tiers exist: `PERM_GUEST` (0), `PERM_USER` (1) and `PERM_ADMIN` (2). Checks use `>` comparisons, so a higher tier always satisfies a lower requirement. GUEST is the default at every level start. USER comes from the level's `user_password`, or on level 8 from `bruteforce`. ADMIN comes only from the solution password and completes the level. A failed `connect` for lack of tier costs half a per-fail.

---

## Command Progression System

Each level's `available_cmds` is an `unsigned int` bitmask. Twenty-six bits are in use. The dispatcher runs a known command only if its bit is set. A recognised but locked command, or an unknown one, prints a message and costs a quarter of a per-fail. Level transitions diff the previous and next masks and announce every newly unlocked command. In v3 this announcement silently skipped `grep`, `combine`, `hint` and `logout`.

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
| `decrypt <file> <key>` | L36 | manual-key files |
| `su <password>` | L36 | root on the current host |

---

## Detection System

Every level has a `detection_max` ceiling and a `detection_per_fail` unit cost. Reaching the ceiling ends the run. All increases go through `detection_add()`, which clamps, redraws the bar and sets `game_over`.

| Event | Cost (× per-fail) |
|---|---|
| Wrong login | 1 |
| Unknown or locked command | ¼ |
| Bad connect target / insufficient tier / FILTERED host / wrong knock | ½ |
| NO ROUTE (link) / knock window re-sealed / failed `su` | ½ |
| Wrong manual key | ¼ |
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

From L36, any Caesar, rail-fence, Vigenère or XOR file can be marked *manual*. Its key is stored for checking but never applied automatically.

### Rail Fence

To decode, the zig-zag is replayed to find which rail each position falls on. The ciphertext is sliced into per-rail runs of those lengths, and the zig-zag is walked again taking the next character from each rail in turn. This runs in O(n) with two passes and no allocation. Degenerate inputs (fewer than two rails, or at least as many rails as characters) fall back to identity.

### Onion Payloads

An onion file's `cipher_key` holds a `>`-separated list of layers, outermost first, for example `b64>rev>hex>atb`. Tokens can take arguments (`rail:3`, `caesar:9`, `xor:KEY`, `vig:KEY`). `onion_peel(content, spec, k)` applies the first *k* layers through a pair of ping-pong buffers. `GameState.file_layers[node][file]` records how many layers the player has removed, so:

- each `decrypt` peels exactly one layer, names the shell it removed, and shows the intermediate text;
- `cat` shows the current partially-peeled state, and `ls` shows `[ONI k/n]`;
- progress survives leaving the node. Level 35 relies on this: its four-shell onion sits on a host swept every five commands, so it can't be peeled in a single visit.

### Manual Keys

`decrypt <file> <key>` compares the typed key to the stored one: case-insensitively for words, and as a decimal string for Caesar shifts and rail counts. On a mismatch, the game still decodes with the wrong key and prints the result, with non-printable bytes masked, so a wrong key produces believable garbage rather than an obvious error message. It also costs a quarter of a per-fail. This turns every key clue (a log line, a riddle, a hint on another host) into a real gate, where before the key was applied automatically.

All 128 encrypted files in the game are checked by decoding them through the C decoders. Every Act IV and Act V fragment was produced by an independent Python encoder, so the encoder and the decoder check each other. Act V levels are generated as C from a spec, so no ciphertext is ever copied by hand.

---

## Network Navigation Model

The player always occupies one node. `scan` reveals every non-entry node. `connect` then runs a fixed sequence of gates, and the order matters: v3 printed "CONNECTION ESTABLISHED" before checking routing and then refused the connection.

1. target exists (else ½ per-fail) and is not the current node
2. target discovered and permission tier sufficient
3. **link** (v5.0): if `link_from` is set, the current host must be in that list (else NO ROUTE, ½)
4. **knock window** (v5.0): an opened knock older than `knock_window` commands re-seals (½)
5. **knock gate**: if `knock_seq` is set and the sequence has not been completed, the host is FILTERED (½)
6. **routing**: if `route_prev` is set, that host must already appear in `nodes_connected` (1×)
7. connection established; a honeypot adds 2×
8. post-connect: watched-host or live-sentry warning; a **tripwire** starts `trace_deadline` on first touch; and the three legacy connect side-effects (L7 firebase, L12 orion-core, L15 fragment-delta) fire.

### Port Knocking

`knock <host> <port>` advances `knock_progress[node]` when the port matches the next expected value. A wrong port resets the progress and costs half a per-fail. When the sequence is complete, the node's bit in `knock_open` is set. Progress is kept between unrelated commands, so knocks don't have to be consecutive.

### Sentinel Sweeps

`process_command()` now separates parsing and pre-checks from a `dispatch()` call, followed by a `sentinel_tick()`. On levels with `sweep_interval > 0`, every command (including typos, `status` and `help`) increments `level_cmds`. When it reaches a multiple of the interval, a sweep runs: if the player is on an `is_watched` node, they pay one per-fail. One command before a sweep, a player standing on a watched node gets a warning. `status` always shows the countdown. This turns command order into a resource: players align the sweep phase with cheap filler commands, and interleave different ones so they don't trigger adaptive detection.

### Rotating Sentry (v5.0)

A level with `watch_cycle = k` gives hosts `watch_slot` values 1..k. Commands are grouped into windows of `sweep_interval`, and the window that contains command *c* belongs to slot `((c − 1) / interval) mod k + 1`. A host is watched at a sweep if it is always watched, or if its slot owns that window. `status` shows the live host and the next one. Players therefore plan a route that visits each rotating host while the sentry is looking somewhere else.

### Per-Host Root and Links (v5.0)

`su <password>` sets a bit in `su_mask` for the current node only. `[ROOT]` files on that node then become readable. Root passwords are always stored on *other* hosts, so `su` turns the map into a dependency chain. `link_from` turns the flat network into a graph: a host accepts connections only from its listed neighbours, so a fragment's location also fixes the path the player must take, often through watched hosts.

### Knock Windows (v5.0)

Completing a knock sequence records the command number in `knock_open_at`. A connection attempted more than `knock_window` commands later finds the firewall re-sealed: the progress resets, half a per-fail is charged, and the sequence must be knocked again. `status` counts the window down. A per-level command counter, `level_cmds`, now increments on every level, because both sweeps and windows depend on it.

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

The theoretical maximum over 45 levels is 1,035,000. Mandatory bruteforce and override costs make a perfect score impossible on some levels. The verified clean playthrough scores 1,026,085. Rank is decided by total failed logins: 0 GHOST LEGEND, 1–4 PHANTOM, 5–10 SPECTRE, 11–20 AGENT, 21+ ROOKIE (thresholds were rescaled from the 16-level game).

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

**Act V (L36–45): Erasure.** Five agencies hunt GHOST. Again, each of the first five levels adds one mechanic, and the last five combine them:

| Level | Adds |
|---|---|
| 36 Cold Storage | manual keys |
| 37 Root of Trust | per-host root (`su`) chains |
| 38 Pivot Point | link-only topology through a watched jumpbox |
| 39 Carousel | rotating sentry |
| 40 Knock Window | re-sealing knocks |
| 41 Interpol Mesh | links + su + manual keys + hidden honeypots + bruteforce |
| 42 Five Eyes | five-station rotation + window + alarm + override |
| 43 Black Ledger | adaptive + rotation + watched corridor + keypad + bruteforce + override |
| 44 Mirror Protocol | everything, two attempts |
| 45 Null Pointer | everything at the tightest settings, five fragments |

Act IV ends with a reveal: the final user credential is `GHOST`, the player's own identity from `whoami`, and the final password is `GH0ST_1S_TH3_ARCH1TECT`. In Act V, the last level's credential is `architect`, the name GHOST had before it became GHOST, and the final password frees the last pointer to it: `FR33_GH0ST_SET_T0_NULL`.

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
| 36 | Cold Storage | ABYSS | 7 | 120 | 25 | 3 | 420 | manual keys |
| 37 | Root of Trust | ABYSS | 8 | 130 | 25 | 3 | 450 | su chain |
| 38 | Pivot Point | ABYSS+ | 9 | 130 | 25 | 3 | 480 | links |
| 39 | Carousel | ABYSS+ | 8 | 140 | 25 | 3 | 480 | rotating sentry |
| 40 | Knock Window | ABYSS++ | 8 | 140 | 25 | 3 | 480 | knock windows |
| 41 | Interpol Mesh | OBLIVION | 9 | 160 | 25 | 3 | 540 | combination |
| 42 | Five Eyes | OBLIVION | 8 | 170 | 30 | 3 | 540 | rotation x5 |
| 43 | Black Ledger | OBLIVION+ | 10 | 200 | 30 | 3 | 600 | everything |
| 44 | Mirror Protocol | NULL | 10 | 220 | 35 | 2 | 600 | everything |
| 45 | Null Pointer | NULL POINTER | 11 | 230 | 35 | 2 | 720 | finale |

---

## Verification

Every level has a scripted solution (the same scripts behind `WALKTHROUGH.md`). Each script runs against the release binary with `TB_FAST=1 TB_START_LEVEL=n` and must meet all of the following:

- the level is breached;
- no sentinel sweep catches the player;
- no honeypot is tripped;
- no error message of any kind appears (missing file, routing rejection, filtered host, wrong knock or code, denied login, locked command).

All 45 pass. The scripts are also concatenated and played as one continuous game, which exercises every level transition, the inventory purge and the win screen. That run finishes 45/45 with zero failed logins, zero sweep catches, zero honeypots and zero repeat penalties, rank GHOST LEGEND and 1,026,085 points.

Targeted negative tests covered: wrong knocks (reset + penalty), knocking a host with no sequence, connecting to a filtered host, escalating keypad penalties, bruteforce on the wrong host (refused, not consumed), routing rejection before connection, honeypot spikes, trace expiry after a real 60-second wait, and save → load → load (same level, no duplicated inventory). The v5.0 tests add: missing and wrong manual keys, failed `su` and root-only access, NO ROUTE across a link, a knock window expiring, and being caught by the rotating sentry. The build is warning-free under `-Wall -Wextra -std=c11`.

---

## Defects Fixed in v4.0 and v5.0

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
| Makefile without header dependencies (v5.0) | stale objects read old struct offsets after a header change, breaking every level | every object depends on every header |
| Win-screen box misaligned (v5.0) | ragged right border | rows normalised to one width |

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

**No dynamic memory.** There is no `malloc` anywhere. Every buffer is fixed-size and bounded with `strncpy` or `snprintf`. Raising `MAX_NODES` to 12 grew the static level array to about 7.8 MB, which is acceptable for a desktop binary.

**Testability hooks.** `TB_FAST` turns off `slow_print` delays and `TB_START_LEVEL` starts at any level. Together they make the full 35-level regression run in seconds, and they double as a practice mode for players.

**No terminal library.** Rendering is plain ANSI escape codes with `printf`. Colour, the detection bar, the live prompt clocks and `slow_print` give the atmosphere without ncurses.

---

## Known Constraints and Limitations

**Fixed capacity.** Files per node (12), nodes per level (12), inventory (30) and levels (45) are compile-time constants. The file-state bitmasks are `int`, which limits a node to 32 files.

**Sweep timing is command-based, not time-based.** Typos count toward the next sweep. This is deliberate, but it can surprise players. The prompt shows timers, but not the sweep countdown, which is only in `status`.

**Legacy side-effects remain hard-coded.** The three connect side-effects from levels 7, 12 and 15 still use hostname checks in `cmd_connect`. They are candidates for the same data-driven treatment.

**Byte-level strings.** Passwords are compared case-sensitively with `strcmp`. ASCII art uses UTF-8 box characters, which need a UTF-8 terminal.

**Single save slot.** Saves go to `terminal_breach.sav` in the working directory.

---

*Terminal Breach v5.0: 45 levels, verified end-to-end, zero compiler warnings, no external dependencies.*
