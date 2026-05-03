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
#define MAX_NODES        6
#define MAX_NODE_IP     20
#define MAX_NODE_NAME   32
#define MAX_LEVEL_NAME  80
#define MAX_HINT        512
#define TOTAL_LEVELS    16
#define MAX_INV_ITEMS   20
#define MAX_INV_LEN    256

/* Access tiers that control which files and nodes a player can interact with.
   GUEST is the default on every level start. USER is granted by logging in with
   the intermediate user_password. ADMIN is granted only by solving the level. */
typedef enum { PERM_GUEST = 0, PERM_USER = 1, PERM_ADMIN = 2 } Permission;

/* Puzzle type identifiers stored per-file. PUZZLE_NONE means the file is
   plain text and does not need decryption. The other three map directly to
   the decode functions in puzzles.c. */
#define PUZZLE_NONE    0
#define PUZZLE_CAESAR  1
#define PUZZLE_REVERSE 2
#define PUZZLE_BINARY  3

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
