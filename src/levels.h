/*
 * levels.h — Core data structures and constants for Terminal Breach.
 *
 * This header defines everything the game operates on: the file, node, level,
 * and game-state structures, along with the permission model, puzzle type
 * identifiers, and the command availability bitmask. Every other module
 * includes this header as its primary dependency.
 */

#ifndef LEVELS_H
#define LEVELS_H

#include <time.h>

/* Maximum array sizes used throughout the game. Keeping these as named
   constants makes it easy to tune capacity without hunting magic numbers. */
#define MAX_FILES       12
#define MAX_FILENAME    64
#define MAX_CONTENT     1024
#define MAX_NODES       12
#define MAX_NODE_IP     20
#define MAX_NODE_NAME   32
#define MAX_LEVEL_NAME  80
#define MAX_HINT        512
#define TOTAL_LEVELS    45
#define MAX_INV_ITEMS   30
#define MAX_INV_LEN    256

/* Access tiers that control which files and nodes a player can interact with.
   GUEST is the default on every level start. USER is granted by logging in with
   the intermediate user_password. ADMIN is granted only by solving the level. */
typedef enum { PERM_GUEST = 0, PERM_USER = 1, PERM_ADMIN = 2 } Permission;

/* Puzzle type identifiers stored per-file. PUZZLE_NONE means the file is
   plain text and does not need decryption. The other three map directly to
   the decode functions in puzzles.c. */
#define PUZZLE_NONE     0
#define PUZZLE_CAESAR   1
#define PUZZLE_REVERSE  2
#define PUZZLE_BINARY   3
#define PUZZLE_XOR      4   /* hex bytes XOR'd with cipher_key string         */
#define PUZZLE_VIGENERE 5   /* letters shifted by repeating cipher_key        */
#define PUZZLE_HEX      6   /* hex bytes -> ASCII, no key                     */
#define PUZZLE_BASE64   7   /* base64 -> ASCII, no key                        */
#define PUZZLE_ATBASH   8   /* A<->Z mirror substitution, no key              */
#define PUZZLE_RAIL     9   /* rail-fence transposition, rails = cipher_shift */
#define PUZZLE_ONION   10   /* multi-layer: cipher_key = "b64>hex>atb..."     */

/* Command availability bitmask — one bit per command. Each Level stores an
   unsigned int with these bits set for every command the player may use.
   The dispatcher in commands.c checks the active level's bitmask before
   executing any command, and charges a small detection penalty for attempts
   to run a command that has not yet been unlocked. */
#define CMD_HELP        (1u <<  0)
#define CMD_LS          (1u <<  1)
#define CMD_CAT         (1u <<  2)
#define CMD_CLEAR       (1u <<  3)
#define CMD_WHOAMI      (1u <<  4)
#define CMD_STATUS      (1u <<  5)
#define CMD_EXIT        (1u <<  6)
#define CMD_HINT        (1u <<  7)
#define CMD_LOGIN       (1u <<  8)
#define CMD_LOGOUT      (1u <<  9)
#define CMD_DECRYPT     (1u << 10)
#define CMD_SAVE        (1u << 11)
#define CMD_INVENTORY   (1u << 12)
#define CMD_SCAN        (1u << 13)
#define CMD_CONNECT     (1u << 14)
#define CMD_BRUTEFORCE  (1u << 15)
#define CMD_OVERRIDE    (1u << 16)
#define CMD_SAVEGAME    (1u << 17)
#define CMD_LOADGAME    (1u << 18)
#define CMD_GREP        (1u << 19)
#define CMD_COMBINE     (1u << 20)
#define CMD_DROP        (1u << 21)
#define CMD_KNOCK       (1u << 22)
#define CMD_UNLOCK      (1u << 23)
#define CMD_WIPE        (1u << 24)
#define CMD_SU          (1u << 25)

/* Convenience bundle for the commands every level provides from the start. */
#define CMD_BASIC (CMD_HELP|CMD_LS|CMD_CAT|CMD_CLEAR|CMD_WHOAMI|CMD_STATUS|CMD_EXIT)

/* A single file inside a network node. The content field holds the raw
   (possibly encoded) text. For encrypted files the decode functions in
   puzzles.c read from content and write the decoded result to a temporary
   buffer — the struct itself is never mutated during play. */
typedef struct {
    char       name[MAX_FILENAME];
    char       content[MAX_CONTENT];
    Permission min_perm;     /* minimum access tier required to read this file */
    int        hidden;       /* if 1, only visible with 'ls -a'                */
    int        encrypted;    /* if 1, 'cat' shows ciphertext until decrypted   */
    int        cipher_shift; /* shift value for Caesar decryption              */
    int        puzzle_type;  /* one of the PUZZLE_* constants above            */
    int        locked;       /* if 1, inaccessible until a condition is met    */
    char       cipher_key[64];/* key for XOR / Vigenère, or ONION layer spec    */
    char       unlock_code[16];/* if set, 'unlock <file> <code>' opens the lock */
    int        manual_key;    /* v5: key not on disk -- 'decrypt <file> <key>'  */
    int        needs_root;    /* v5: readable only after 'su' on this host       */
} GameFile;

/* A network node — a machine within a level's topology. The entry node is
   the player's starting position each level. Non-entry nodes are discovered
   via 'scan' and reached with 'connect'. */
typedef struct {
    char      ip[MAX_NODE_IP];
    char      hostname[MAX_NODE_NAME];
    char      description[256];
    GameFile  files[MAX_FILES];
    int       file_count;
    Permission min_perm;   /* permission tier required to connect              */
    int       is_entry;    /* 1 if this is the level's starting node           */
    int       discovered;  /* 1 once 'scan' has revealed this node             */
    int       is_honeypot; /* if 1, connecting fires a heavy detection spike   */
    char      route_prev[MAX_NODE_NAME]; /* if set, requires prior connect to this hostname */
    int       is_watched;  /* sentinel sweeps catch players parked here        */
    int       has_logs;    /* 'wipe' can scrub this node's logs once           */
    int       trip_seconds;/* connecting starts a trace countdown (silent alarm)*/
    char      knock_seq[48]; /* space-separated ports; must 'knock' before connect */
    char      su_pass[32];   /* v5: 'su <pass>' grants root on this host          */
    char      link_from[96]; /* v5: comma list -- only reachable from these hosts */
    int       watch_slot;    /* v5: 1..watch_cycle -- watched on that rotation   */
    int       knock_window;  /* v5: knock stays open this many commands          */
} NetworkNode;

/* All data that defines one level — its narrative context, network topology,
   authentication requirements, detection budget, and available commands.
   Level structs are initialised once at startup and treated as read-only
   during play; mutable state lives entirely in GameState. */
typedef struct {
    int  id;
    char name[MAX_LEVEL_NAME];

    char objective[512];   /* mission briefing text shown at level start  */
    char difficulty[16];   /* display string: EASY / MEDIUM / HARD / etc. */
    char warnings[256];    /* additional alert text shown in the briefing  */

    NetworkNode nodes[MAX_NODES];
    int         node_count;

    char solution_password[64]; /* correct password — completes the level  */
    char user_password[64];     /* intermediate password — grants USER tier */
    char hint[MAX_HINT];
    int  max_attempts;

    int  detection_max;      /* detection ceiling; reaching it ends the run */
    int  detection_per_fail; /* cost added per wrong login                  */

    int  has_timer;
    int  timer_seconds;

    unsigned int available_cmds; /* bitmask of commands usable this level   */
    int  adaptive_detection;     /* if 1, repeated commands cost more       */
    int  sweep_interval;         /* sentinel sweep every N commands (0=off) */
    int  hint_cost;              /* detection charged for using 'hint'      */
    int  watch_cycle;            /* v5: rotating sentry, nodes use watch_slot */

    /* Data-driven targets for bruteforce/override. When bf_node is set the
       player must be on that host or the attempt is refused (not consumed). */
    char bf_node[MAX_NODE_NAME];
    char bf_file[MAX_FILENAME];
    char ov_node[MAX_NODE_NAME];
    char ov_file[MAX_FILENAME];
} Level;

/* All mutable runtime state for an active play session. This struct is the
   single source of truth for everything that changes during a level: the
   player's position, access tier, detection level, inventory, and progress
   flags. It is also what gets serialised to disk by the save system. */
typedef struct {
    int        current_level;
    int        current_node;
    Permission permission;
    int        detection;

    /* Per-node file state stored as bitmasks so that level data can remain
       immutable. Bit i in node_files_unlocked[n] means file i on node n has
       had its lock condition satisfied. Bit i in node_files_decrypted[n]
       means the player has already decoded that file this session. */
    int  node_files_unlocked[MAX_NODES];
    int  node_files_decrypted[MAX_NODES];

    char inventory[MAX_INV_ITEMS][MAX_INV_LEN];
    int  inv_count;

    int  attempts;
    int  scanned;
    int  bruteforce_used;
    int  override_used;
    int  level_complete;
    int  game_over;

    int    nodes_connected;  /* bitmask of nodes visited this level   */
    int    last_node;        /* node index visited just before current */
    int    last_cmd_hash;    /* hash of last command (adaptive detection) */
    int    repeat_streak;    /* consecutive same-command count          */

    /* Mechanics introduced in levels 26-35. */
    int    level_cmds;                      /* commands issued this level (sweeps) */
    int    knock_progress[MAX_NODES];       /* ports knocked so far, per node      */
    int    knock_open;                      /* bitmask: knock sequence completed   */
    int    wiped;                           /* bitmask: logs wiped on node         */
    int    keypad_fails;                    /* wrong keypad codes this level       */
    time_t trace_deadline;                  /* 0 = no silent-alarm trace running   */
    unsigned char file_layers[MAX_NODES][MAX_FILES]; /* onion layers peeled    */
    int    load_pending;                    /* loadgame: restart at current_level  */
    int    su_mask;                         /* v5: hosts the player has root on    */
    int    knock_open_at[MAX_NODES];        /* v5: command number a knock completed */

    int    total_fails;
    int    total_commands;
    time_t level_start;
    time_t game_start;

    int  score;
    int  level_scores[TOTAL_LEVELS];
} GameState;

/* Public API for the level subsystem. */
void   init_levels(void);
Level *get_level(int id);

#endif
