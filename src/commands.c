/*
 * commands.c — All player command handlers and the command dispatcher.
 *
 * Each public function here handles one command the player can type. They
 * share a consistent pattern: validate arguments, check permissions or lock
 * state, perform the action, and update GameState. The process_command
 * function at the bottom is the single entry point from the main loop —
 * it tokenises input, verifies the command is available at the current level,
 * and routes to the right handler.
 */

#include "commands.h"
#include "levels.h"
#include "utils.h"
#include "network.h"
#include "puzzles.h"
#include "save.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>

#define GRN  "\033[1;32m"
#define RED  "\033[1;31m"
#define YEL  "\033[1;33m"
#define CYN  "\033[1;36m"
#define WHT  "\033[1;37m"
#define DIM  "\033[0;37m"
#define MAG  "\033[1;35m"
#define RST  "\033[0m"

/* Returns a pointer to the Level struct for the level currently being played. */
static Level *cur_level(GameState *gs) { return get_level(gs->current_level); }

/* Adds 'amount' to the detection counter, capping at the level maximum,
   prints the updated bar, and sets game_over if the ceiling is reached.
   All detection increases go through this function so the cap and game-over
   logic are never accidentally bypassed. */
static void detection_add(GameState *gs, int amount) {
    Level *l = cur_level(gs);
    gs->detection += amount;
    if (gs->detection > l->detection_max)
        gs->detection = l->detection_max;
    print_detection_bar(gs->detection, l->detection_max);
    if (gs->detection >= l->detection_max) {
        printf(RED "\n  [!!!] TRACE COMPLETE -- SYSTEM LOCKED\n" RST);
        printf(RED "  All traffic logged. Session terminated.\n\n" RST);
        gs->game_over = 1;
    }
}

/* Prints all commands currently available at the active level. The bitmask
   check ensures that commands which have not yet been unlocked are not listed,
   which avoids confusing players with commands they cannot use. */
void cmd_help(GameState *gs) {
    unsigned int c = cur_level(gs)->available_cmds;
    printf(GRN "┌─ AVAILABLE COMMANDS ─────────────────────────────────────┐\n" RST);
    if (c & CMD_HELP)       printf(GRN "│" RST " %-22s %s\n", "help",              "Show this menu");
    if (c & CMD_LS)         printf(GRN "│" RST " %-22s %s\n", "ls [-a]",           "List files (use -a for hidden)");
    if (c & CMD_CAT)        printf(GRN "│" RST " %-22s %s\n", "cat <file>",        "Read file contents");
    if (c & CMD_CLEAR)      printf(GRN "│" RST " %-22s %s\n", "clear",             "Clear the screen");
    if (c & CMD_WHOAMI)     printf(GRN "│" RST " %-22s %s\n", "whoami",            "Show current identity");
    if (c & CMD_STATUS)     printf(GRN "│" RST " %-22s %s\n", "status",            "Show mission status");
    if (c & CMD_HINT)       printf(GRN "│" RST " %-22s %s\n", "hint",              "Get a hint for this level");
    if (c & CMD_LOGIN)      printf(GRN "│" RST " %-22s %s\n", "login <password>",  "Authenticate to the system");
    if (c & CMD_LOGOUT)     printf(GRN "│" RST " %-22s %s\n", "logout",            "Drop back to guest access");
    if (c & CMD_DECRYPT)    printf(GRN "│" RST " %-22s %s\n", "decrypt <file>",    "Decode an encrypted file");
    if (c & CMD_SAVE)       printf(GRN "│" RST " %-22s %s\n", "save <data>",       "Store data to inventory");
    if (c & CMD_INVENTORY)  printf(GRN "│" RST " %-22s %s\n", "inventory",         "List stored inventory items");
    if (c & CMD_SCAN)       printf(GRN "│" RST " %-22s %s\n", "scan",              "Scan network for live hosts");
    if (c & CMD_CONNECT)    printf(GRN "│" RST " %-22s %s\n", "connect <ip>",      "Connect to a discovered host");
    if (c & CMD_BRUTEFORCE) printf(GRN "│" RST " %-22s %s\n", "bruteforce",        "Force-bypass authentication");
    if (c & CMD_OVERRIDE)   printf(GRN "│" RST " %-22s %s\n", "override",          "Override neural security block");
    if (c & CMD_SAVEGAME)   printf(GRN "│" RST " %-22s %s\n", "savegame",          "Save progress to file");
    if (c & CMD_LOADGAME)   printf(GRN "│" RST " %-22s %s\n", "loadgame",          "Load progress from file");
    if (c & CMD_GREP)       printf(GRN "│" RST " %-22s %s\n", "grep <pat> <file>", "Filter file lines by pattern");
    if (c & CMD_COMBINE)    printf(GRN "│" RST " %-22s %s\n", "combine [a b ..]",  "Concatenate inventory items");
    if (c & CMD_DROP)       printf(GRN "│" RST " %-22s %s\n", "drop <slot|all>",   "Remove inventory item(s)");
    if (c & CMD_KNOCK)      printf(GRN "│" RST " %-22s %s\n", "knock <host> <port>","Port-knock a filtered host");
    if (c & CMD_UNLOCK)     printf(GRN "│" RST " %-22s %s\n", "unlock <file> <pin>","Enter a keypad code on a file");
    if (c & CMD_WIPE)       printf(GRN "│" RST " %-22s %s\n", "wipe",              "Scrub logs on this node (once)");
    if (c & CMD_EXIT)       printf(GRN "│" RST " %-22s %s\n", "exit",              "Quit the game");
    printf(GRN "└──────────────────────────────────────────────────────────┘\n" RST);
}

/* Lists files on the current node. Without the -a flag, hidden files and files
   that require higher permissions than the player currently holds are omitted.
   Encrypted files that have not yet been decoded are marked [ENC] in yellow to
   signal that the decrypt command should be used on them. */
void cmd_ls(GameState *gs, const char *flags) {
    int show_hidden = (flags && strcmp(flags, "-a") == 0);
    NetworkNode *node = get_current_node(gs);
    printf(DIM "Directory listing -- %s (%s)\n" RST, node->ip, node->hostname);
    print_separator();
    int shown = 0;
    for (int i = 0; i < node->file_count; i++) {
        GameFile *f = &node->files[i];
        if (f->hidden && !show_hidden) continue;
        if (f->min_perm > gs->permission) continue;
        if (f->locked && !is_file_unlocked(gs, gs->current_node, i)) {
            /* Keypad-locked files are visible so the player knows a code
               is needed; every other lock stays invisible until opened. */
            if (f->unlock_code[0]) { printf(RED "  [PIN]  %s\n" RST, f->name); shown++; }
            continue;
        }

        int decrypted = is_file_decrypted(gs, gs->current_node, i);
        if (f->puzzle_type == PUZZLE_ONION && !decrypted)
            printf(YEL "  [ONI %d/%d]  %s\n" RST,
                   gs->file_layers[gs->current_node][i],
                   onion_layer_count(f->cipher_key), f->name);
        else if (f->encrypted && !decrypted)
            printf(YEL "  [ENC]  %s\n" RST, f->name);
        else if (f->hidden)
            printf(DIM "  [ h ]  %s\n" RST, f->name);
        else
            printf(GRN "  [   ]  %s\n" RST, f->name);
        shown++;
    }
    if (shown == 0) printf(DIM "  (empty)\n" RST);
    print_separator();
}

/* Reads and prints a file's content. For encrypted files that have not yet
   been decoded, the raw ciphertext is shown along with a prompt to use decrypt.
   For files that were previously decoded, the plaintext is re-derived from the
   immutable file content using decode_content — nothing is stored separately. */
void cmd_cat(GameState *gs, const char *filename) {
    if (!filename || !filename[0]) {
        printf(RED "[!] Usage: cat <filename>\n" RST);
        return;
    }
    NetworkNode *node = get_current_node(gs);
    int idx = find_file_index(node, filename);

    if (idx < 0) {
        printf(RED "[!] FILE NOT FOUND: %s\n" RST, filename);
        return;
    }
    GameFile *f = &node->files[idx];

    if (f->min_perm > gs->permission) {
        printf(RED "[!] PERMISSION DENIED -- %s requires elevated access.\n" RST, filename);
        return;
    }
    if (f->locked && !is_file_unlocked(gs, gs->current_node, idx)) {
        if (f->unlock_code[0])
            printf(RED "[!] KEYPAD LOCKED -- use: unlock %s <code>\n" RST, filename);
        else
            printf(RED "[!] PERMISSION DENIED -- %s is locked.\n" RST, filename);
        return;
    }

    printf(DIM "-- %s " RST, filename);
    print_separator();

    int decrypted = is_file_decrypted(gs, gs->current_node, idx);
    if (f->puzzle_type == PUZZLE_ONION && !decrypted) {
        int peeled = gs->file_layers[gs->current_node][idx];
        char buf[MAX_CONTENT];
        onion_peel(f->content, f->cipher_key, peeled, buf, MAX_CONTENT);
        printf("%s\n", buf);
        printf(YEL "[!] Onion payload: %d/%d layers peeled. Use: decrypt %s\n" RST,
               peeled, onion_layer_count(f->cipher_key), filename);
    } else if (f->encrypted && !decrypted) {
        printf("%s\n", f->content);
        printf(YEL "[!] File is encrypted. Use: decrypt %s\n" RST, filename);
    } else if (f->encrypted && decrypted) {
        char buf[MAX_CONTENT];
        decode_content(f, buf, MAX_CONTENT);
        printf("%s\n", buf);
    } else {
        printf("%s\n", f->content);
    }
    print_separator();
}

/* Clears the terminal screen. */
void cmd_clear(void) { clear_screen(); }

/* Prints the player's fixed identity and current access tier. The identity
   fields are static flavour — only the access level changes during play. */
void cmd_whoami(GameState *gs) {
    const char *perm_str = (gs->permission == PERM_ADMIN) ? GRN "ADMIN" RST :
                           (gs->permission == PERM_USER)  ? YEL "USER"  RST :
                                                            DIM "GUEST" RST;
    printf(GRN "  Identity  : GHOST\n" RST);
    printf(DIM "  IP        : 0.0.0.0 (masked)\n" RST);
    printf(DIM "  Proxy     : TOR -> VPN -> DARKNET\n" RST);
    printf(DIM "  Traceable : NO\n" RST);
    printf("  Access    : %s\n", perm_str);
}

/* Prints a full mission status panel: level, difficulty, current node,
   access tier, attempt count, score, remaining timer (if active), detection
   bar, and the current objective text. This is the player's primary
   reference command for situational awareness. */
void cmd_status(GameState *gs) {
    Level       *l    = cur_level(gs);
    NetworkNode *node = get_current_node(gs);
    const char  *prm  = (gs->permission == PERM_ADMIN) ? GRN "ADMIN" RST :
                        (gs->permission == PERM_USER)  ? YEL "USER"  RST :
                                                         DIM "GUEST" RST;
    printf(CYN "┌─ MISSION STATUS ─────────────────────────────────────────┐\n" RST);
    printf(CYN "│" RST " Level      : %d/%d -- %s\n",    gs->current_level + 1, TOTAL_LEVELS, l->name);
    printf(CYN "│" RST " Difficulty : %s\n",              l->difficulty);
    printf(CYN "│" RST " Node       : %s (%s)\n",         node->ip, node->hostname);
    printf(CYN "│" RST " Access     : %s\n",              prm);
    printf(CYN "│" RST " Attempts   : %d/%d\n",           gs->attempts, l->max_attempts);
    printf(CYN "│" RST " Score      : %d pts\n",          gs->score);

    if (l->has_timer) {
        int elapsed   = (int)(time(NULL) - gs->level_start);
        int remaining = l->timer_seconds - elapsed;
        if (remaining < 0) remaining = 0;
        printf(CYN "│" RST " Timer      : " YEL "%d" RST " seconds remaining\n", remaining);
    }

    if (gs->trace_deadline) {
        int tr = (int)(gs->trace_deadline - time(NULL));
        if (tr < 0) tr = 0;
        printf(CYN "│" RST " Trace      : " RED "%d seconds to lock-on" RST "\n", tr);
    }
    if (l->sweep_interval > 0)
        printf(CYN "│" RST " Sentinel   : sweep in " YEL "%d" RST " command(s)%s\n",
               l->sweep_interval - (gs->level_cmds % l->sweep_interval),
               node->is_watched ? RED "  [YOU ARE ON A WATCHED HOST]" RST : "");
    if (l->adaptive_detection)
        printf(CYN "│" RST " Adaptive   : repeat streak %d\n", gs->repeat_streak);

    printf(CYN "│" RST " Detection  : ");
    print_detection_bar(gs->detection, l->detection_max);

    printf(CYN "│" RST " Objective  :\n");
    const char *p = l->objective;
    while (*p) {
        printf(CYN "│" RST "   ");
        int col = 0;
        while (*p && *p != '\n' && col < 52) { putchar(*p++); col++; }
        if (*p == '\n') p++;
        putchar('\n');
    }
    printf(CYN "└──────────────────────────────────────────────────────────┘\n" RST);
}

/* Prints the level's hint text. Also called automatically when the player
   has one attempt remaining, to avoid a silent lockout. */
void cmd_hint(GameState *gs) {
    Level *l = cur_level(gs);
    if (l->hint_cost > 0) {
        printf(YEL "[!] Hint pulled from a monitored dead-drop -- detection +%d.\n" RST,
               l->hint_cost);
        detection_add(gs, l->hint_cost);
        if (gs->game_over) return;
    }
    printf(YEL "[HINT] %s\n" RST, l->hint);
}

/* Attempts authentication with the given password. There are three cases:
   the user password grants USER tier and returns; the solution password
   grants ADMIN, computes the level score, and sets level_complete; anything
   else increments the attempt counter, adds detection, and if the player
   has one try left the hint is shown. Reaching the attempt limit ends the run. */
void cmd_login(GameState *gs, const char *password) {
    if (!password || !password[0]) {
        printf(RED "[!] Usage: login <password>\n" RST);
        return;
    }
    Level *l = cur_level(gs);

    if (l->user_password[0] && strcmp(password, l->user_password) == 0) {
        gs->permission = PERM_USER;
        printf(GRN "[+] USER ACCESS GRANTED -- elevated permissions active.\n" RST);
        return;
    }

    if (strcmp(password, l->solution_password) == 0) {
        gs->permission = PERM_ADMIN;
        printf(GRN "\n");
        slow_print("  ██████╗ ██████╗  █████╗ ███╗  ██╗████████╗███████╗██████╗ ", 4);
        slow_print("  ██╔════╝██╔══██╗██╔══██╗████╗ ██║╚══██╔══╝██╔════╝██╔══██╗", 4);
        slow_print("  ██║  ███╗██████╔╝███████║██╔██╗██║   ██║   █████╗  ██║  ██║", 4);
        slow_print("  ██║   ██║██╔══██╗██╔══██║██║╚████║   ██║   ██╔══╝  ██║  ██║", 4);
        slow_print("  ╚██████╔╝██║  ██║██║  ██║██║ ╚███║   ██║   ███████╗██████╔╝", 4);
        slow_print("   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝   ╚═╝   ╚══════╝╚═════╝ ", 4);
        printf(RST "\n");
        printf(GRN "[+] ACCESS GRANTED -- %s breached.\n\n" RST, l->name);

        /* Score formula: base minus penalties for failed attempts and detection. */
        int base    = (gs->current_level + 1) * 1000;
        int penalty = gs->attempts * 100 + (gs->detection * 5);
        int lscore  = base - penalty;
        if (lscore < 0) lscore = 0;
        gs->level_scores[gs->current_level] = lscore;
        gs->score += lscore;
        printf(DIM "  [SCORE] Level %d: +%d pts (base %d, penalty -%d)\n\n" RST,
               gs->current_level + 1, lscore, base, penalty);

        gs->level_complete = 1;
        return;
    }

    gs->attempts++;
    gs->total_fails++;
    int remaining = l->max_attempts - gs->attempts;
    printf(RED "[!] ACCESS DENIED -- incorrect password.\n" RST);
    if (remaining > 0)
        printf(YEL "[!] %d attempt(s) remaining before lockout.\n" RST, remaining);

    detection_add(gs, l->detection_per_fail);

    if (gs->game_over) return;

    if (remaining <= 0) {
        printf(RED "[!] TOO MANY FAILURES -- initiating system lockout.\n" RST);
        gs->game_over = 1;
    } else if (remaining == 1) {
        /* Show the hint automatically with one attempt left. */
        printf(YEL "[HINT] %s\n" RST, l->hint);
    }
}

/* Drops the player back to GUEST access. Useful in multi-node levels where
   logging in with a user password on one node carries over to all nodes and
   the player wants to test behaviour from the base access tier. */
void cmd_logout(GameState *gs) {
    gs->permission = PERM_GUEST;
    printf(DIM "[SYS] Logged out. Access reset to GUEST.\n" RST);
}

/* Decrypts a file on the current node. On the first successful decode the
   decrypted flag is set in GameState so subsequent 'cat' calls show plaintext
   directly. The decoding method name is printed to give the player feedback
   about which puzzle type they just solved. */
void cmd_decrypt(GameState *gs, const char *filename) {
    if (!filename || !filename[0]) {
        printf(RED "[!] Usage: decrypt <filename>\n" RST);
        return;
    }
    NetworkNode *node = get_current_node(gs);
    int idx = find_file_index(node, filename);

    if (idx < 0) {
        printf(RED "[!] FILE NOT FOUND: %s\n" RST, filename);
        return;
    }
    GameFile *f = &node->files[idx];

    if (f->min_perm > gs->permission) {
        printf(RED "[!] PERMISSION DENIED -- %s requires elevated access.\n" RST, filename);
        return;
    }
    if (f->locked && !is_file_unlocked(gs, gs->current_node, idx)) {
        if (f->unlock_code[0])
            printf(RED "[!] KEYPAD LOCKED -- use: unlock %s <code>\n" RST, filename);
        else
            printf(RED "[!] PERMISSION DENIED -- %s is locked.\n" RST, filename);
        return;
    }
    if (!f->encrypted) {
        printf(YEL "[!] %s is not encrypted.\n" RST, filename);
        return;
    }
    if (is_file_decrypted(gs, gs->current_node, idx)) {
        /* Already decoded — show the content again without repeating the animation. */
        char buf[MAX_CONTENT];
        decode_content(f, buf, MAX_CONTENT);
        printf(DIM "-- %s (already decoded) " RST, filename);
        print_separator();
        printf("%s\n", buf);
        print_separator();
        return;
    }

    /* Onion files peel exactly one layer per decrypt call. */
    if (f->puzzle_type == PUZZLE_ONION) {
        int total  = onion_layer_count(f->cipher_key);
        int peeled = gs->file_layers[gs->current_node][idx];
        char lname[64];
        onion_layer_name(f->cipher_key, peeled, lname, sizeof(lname));
        printf(GRN "[DEC] Peeling %s -- layer %d of %d...\n" RST, filename, peeled + 1, total);
        slow_print("[DEC] Fingerprinting outer shell...", 20);
        printf(GRN "[DEC] Shell identified: %s\n" RST, lname);

        char buf[MAX_CONTENT];
        if (onion_peel(f->content, f->cipher_key, peeled + 1, buf, MAX_CONTENT) <= 0) {
            printf(RED "[!] Peel failed -- payload corrupted.\n" RST);
            return;
        }
        gs->file_layers[gs->current_node][idx] = (unsigned char)(peeled + 1);
        print_separator();
        printf("%s\n", buf);
        print_separator();
        if (peeled + 1 >= total) {
            set_decrypted(gs, gs->current_node, idx);
            printf(GRN "[+] CORE REACHED -- %s fully decoded.\n" RST, filename);
        } else {
            printf(YEL "[DEC] Another shell underneath (%d left). decrypt again.\n" RST,
                   total - peeled - 1);
        }
        return;
    }

    const char *method = (f->puzzle_type == PUZZLE_CAESAR)   ? "Caesar cipher"     :
                         (f->puzzle_type == PUZZLE_REVERSE)  ? "Reverse text"      :
                         (f->puzzle_type == PUZZLE_BINARY)   ? "Binary-to-ASCII"   :
                         (f->puzzle_type == PUZZLE_HEX)      ? "Hex-to-ASCII"      :
                         (f->puzzle_type == PUZZLE_XOR)      ? "XOR cipher"        :
                         (f->puzzle_type == PUZZLE_VIGENERE) ? "Vigenere cipher"   :
                         (f->puzzle_type == PUZZLE_BASE64)   ? "Base64 decode"     :
                         (f->puzzle_type == PUZZLE_ATBASH)   ? "Atbash mirror"     :
                         (f->puzzle_type == PUZZLE_RAIL)     ? "Rail-fence transposition" : "Unknown";
    printf(GRN "[DEC] Decrypting %s...\n" RST, filename);
    slow_print("[DEC] Analysing encoding scheme...", 25);
    printf(GRN "[DEC] Method detected: %s\n" RST, method);
    slow_print("[DEC] Applying decode...", 25);

    char buf[MAX_CONTENT];
    if (!decode_content(f, buf, MAX_CONTENT)) {
        printf(RED "[!] Decode failed — unsupported puzzle type.\n" RST);
        return;
    }

    set_decrypted(gs, gs->current_node, idx);
    printf(GRN "[+] DECODED: %s\n" RST, filename);
    printf(DIM "-- Decoded content " RST);
    print_separator();
    printf("%s\n", buf);
    print_separator();
}

/* Stores a string in the player's inventory for reference later in the session.
   This is the primary tool for keeping track of password fragments, cipher
   shifts, and prefixes across multi-node levels where information must be
   mentally carried between hops. */
void cmd_save_item(GameState *gs, const char *data) {
    if (!data || !data[0]) {
        printf(RED "[!] Usage: save <data>\n" RST);
        return;
    }
    if (gs->inv_count >= MAX_INV_ITEMS) {
        printf(YEL "[!] Inventory full (%d items). Remove nothing — just remember.\n" RST, MAX_INV_ITEMS);
        return;
    }
    strncpy(gs->inventory[gs->inv_count], data, MAX_INV_LEN - 1);
    gs->inventory[gs->inv_count][MAX_INV_LEN - 1] = '\0';
    gs->inv_count++;
    printf(GRN "[+] Saved: \"%s\" (slot %d/%d)\n" RST, data, gs->inv_count, MAX_INV_ITEMS);
}

/* Lists all strings currently stored in the player's inventory, numbered for
   easy reference. The inventory persists for the duration of the session and
   is also included in the save file. */
void cmd_inventory(GameState *gs) {
    if (gs->inv_count == 0) {
        printf(DIM "[INV] Inventory is empty. Use 'save <data>' to store items.\n" RST);
        return;
    }
    printf(CYN "┌─ INVENTORY (%d/%d) ──────────────────────────────────────┐\n" RST,
           gs->inv_count, MAX_INV_ITEMS);
    for (int i = 0; i < gs->inv_count; i++)
        printf(CYN "│" RST " [%2d] %s\n", i + 1, gs->inventory[i]);
    printf(CYN "└──────────────────────────────────────────────────────────┘\n" RST);
}

/* Marks all non-entry nodes in the current level as discovered, making them
   reachable via 'connect'. In the game fiction this represents an ICMP sweep
   of the local network segment. Must be run before 'connect' will accept an IP. */
void cmd_scan(GameState *gs) {
    Level *l = cur_level(gs);
    printf(GRN "[NET] Initiating network scan...\n" RST);
    slow_print("[NET] Sending ICMP probes...", 28);
    slow_print("[NET] Analysing responses...", 28);

    int found = 0;
    for (int i = 0; i < l->node_count; i++) {
        if (l->nodes[i].is_entry) continue;
        l->nodes[i].discovered = 1;
        printf(GRN "  -> %s  (%s)  [ONLINE]\n" RST,
               l->nodes[i].ip, l->nodes[i].hostname);
        found++;
    }
    if (!found)
        printf(DIM "[NET] No additional hosts discovered on this segment.\n" RST);
    else
        printf(DIM "[NET] Scan complete. Use 'connect <ip>' to connect.\n" RST);

    gs->scanned = 1;
}

/* Switches the player's context to a different network node. Validates that
   the target was discovered via 'scan', that the player meets the node's
   minimum permission requirement, and that the node is not the current one.
   Certain level-specific side effects are triggered on successful connection —
   these are documented inline below. */
void cmd_connect(GameState *gs, const char *target) {
    if (!target || !target[0]) {
        printf(RED "[!] Usage: connect <ip>\n" RST);
        return;
    }
    if (!gs->scanned) {
        printf(RED "[!] Run 'scan' first to discover hosts.\n" RST);
        return;
    }

    Level *l   = cur_level(gs);
    int node_i = find_node_by_target(l, target);

    if (node_i < 0) {
        printf(RED "[!] UNREACHABLE -- host '%s' not found or offline.\n" RST, target);
        detection_add(gs, l->detection_per_fail / 2);
        return;
    }
    if (node_i == gs->current_node) {
        printf(DIM "[NET] Already on %s.\n" RST, l->nodes[node_i].ip);
        return;
    }
    if (!l->nodes[node_i].discovered) {
        printf(RED "[!] UNREACHABLE -- host not yet discovered. Run 'scan' first.\n" RST);
        return;
    }
    if (l->nodes[node_i].min_perm > gs->permission) {
        printf(RED "[!] CONNECTION REFUSED -- insufficient access level.\n" RST);
        printf(YEL "    Required: %s | Current: %s\n" RST,
               l->nodes[node_i].min_perm == PERM_USER ? "USER" : "ADMIN",
               gs->permission == PERM_GUEST ? "GUEST" : "USER");
        detection_add(gs, l->detection_per_fail / 2);
        return;
    }

    /* Port-knock gate: the host's firewall drops everything until the
       player has knocked the full port sequence with 'knock'. */
    if (l->nodes[node_i].knock_seq[0] && !((gs->knock_open >> node_i) & 1)) {
        printf(RED "[!] FILTERED -- %s drops all inbound traffic.\n" RST,
               l->nodes[node_i].hostname);
        printf(DIM "    Firewall appears to be waiting for a port-knock sequence.\n" RST);
        detection_add(gs, l->detection_per_fail / 2);
        return;
    }

    /* Routing-order requirement: certain nodes only accept the connection
       if the player previously visited the prerequisite node this level. */
    if (l->nodes[node_i].route_prev[0]) {
        int prev = -1;
        for (int i = 0; i < l->node_count; i++)
            if (strcmp(l->nodes[i].hostname, l->nodes[node_i].route_prev) == 0)
                { prev = i; break; }
        int visited = (prev >= 0) && ((gs->nodes_connected >> prev) & 1);
        if (!visited) {
            printf(RED "[!] ROUTING REJECTED -- must traverse %s first.\n" RST,
                   l->nodes[node_i].route_prev);
            detection_add(gs, l->detection_per_fail);
            return;
        }
    }

    printf(GRN "[NET] Establishing connection to %s...\n" RST, target);
    slow_print("[NET] Routing through proxy chain...", 22);
    slow_print("[NET] Handshake complete.", 22);
    printf(GRN "[NET] CONNECTION ESTABLISHED -- %s (%s)\n" RST,
           l->nodes[node_i].ip, l->nodes[node_i].hostname);

    /* Honeypot detection — connecting fires a heavy detection spike. */
    if (l->nodes[node_i].is_honeypot) {
        printf(RED "[!] HONEYPOT TRIPPED -- decoy node alerted operators!\n" RST);
        detection_add(gs, l->detection_per_fail * 2);
        if (gs->game_over) return;
    }

    gs->last_node       = gs->current_node;
    gs->current_node    = node_i;
    gs->nodes_connected |= (1 << node_i);

    if (l->nodes[node_i].is_watched)
        printf(YEL "[!] SENTINEL-WATCHED HOST -- do not linger here during a sweep.\n" RST);

    /* Silent alarm: the first touch of a tripwired host starts a trace
       countdown that keeps running for the rest of the level. */
    if (l->nodes[node_i].trip_seconds > 0 && gs->trace_deadline == 0) {
        gs->trace_deadline = time(NULL) + l->nodes[node_i].trip_seconds;
        printf(RED "\n  [!!!] SILENT ALARM TRIPPED ON %s\n" RST, l->nodes[node_i].hostname);
        printf(RED "  [!!!] Reverse trace inbound -- %d seconds until lock-on.\n\n" RST,
               l->nodes[node_i].trip_seconds);
    }

    /* Level 6: connecting to firebase unlocks classified.txt, which contains
       the full four-step procedure for the level. The unlock models the idea
       that the forward base's systems recognise an authenticated connection
       and automatically grant access to operational documents. */
    if (gs->current_level == 6 && strcmp(l->nodes[node_i].hostname, "firebase") == 0) {
        int fi = find_file_index(&l->nodes[node_i], "classified.txt");
        if (fi >= 0) {
            unlock_file_bit(gs, node_i, fi);
            printf(DIM "[SYS] Classified files accessible on this node.\n" RST);
        }
    }

    /* Level 11: connecting to orion-core activates the override relay and
       unlocks override_code.txt, which confirms the full password format. */
    if (gs->current_level == 11 && strcmp(l->nodes[node_i].hostname, "orion-core") == 0) {
        int fi = find_file_index(&l->nodes[node_i], "override_code.txt");
        if (fi >= 0) {
            unlock_file_bit(gs, node_i, fi);
            printf(DIM "[SYS] Override relay active -- protocol files unlocked.\n" RST);
        }
    }

    /* Level 14: connecting to fragment-delta triggers the BLACKOUT protocol
       intel file, which confirms the Caesar shift and points the player to
       the omega-core override as the final step. */
    if (gs->current_level == 14 && strcmp(l->nodes[node_i].hostname, "fragment-delta") == 0) {
        int fi = find_file_index(&l->nodes[node_i], "blackout_info.txt");
        if (fi >= 0) {
            unlock_file_bit(gs, node_i, fi);
            printf(DIM "[SYS] BLACKOUT protocol intel now accessible.\n" RST);
        }
    }
}

/* Forces a partial authentication bypass on the current node. Costs twice the
   level's detection_per_fail, which makes it a deliberate and expensive choice.
   Each level that uses bruteforce has a specific locked file on a specific node
   that this command unlocks; the player must be on the correct node. */
void cmd_bruteforce(GameState *gs) {
    Level       *l    = cur_level(gs);
    NetworkNode *node = get_current_node(gs);

    if (gs->bruteforce_used) {
        printf(YEL "[!] Bruteforce already used on this level.\n" RST);
        return;
    }

    /* Level 8 (idx 7) is the one level where bruteforce grants USER access
       directly instead of opening a file. Every other level names a target
       host + file; using it anywhere else is refused WITHOUT consuming the
       single use, so a mis-step can no longer soft-lock the level. */
    int grants_user = (gs->current_level == 7);
    if (!grants_user) {
        if (!l->bf_node[0]) {
            printf(RED "[!] No brute-forceable target on this system.\n" RST);
            return;
        }
        if (strcmp(node->hostname, l->bf_node) != 0) {
            printf(RED "[!] No vulnerable auth service on %s -- bruteforce aborted.\n" RST,
                   node->hostname);
            printf(DIM "    (single-use bruteforce not consumed)\n" RST);
            return;
        }
    }

    printf(RED "[BRF] Initiating brute-force on authentication subsystem...\n" RST);
    slow_print("[BRF] Generating key candidates...", 30);
    slow_print("[BRF] Applying dictionary attack...", 30);
    slow_print("[BRF] Bypassing rate limiting...", 30);
    slow_print("[BRF] Partial access achieved!", 20);

    gs->bruteforce_used = 1;
    detection_add(gs, l->detection_per_fail * 2);
    if (gs->game_over) return;

    printf(RED "[!] ALERT: Brute-force activity detected -- detection spike!\n" RST);

    if (grants_user) {
        if (gs->permission == PERM_GUEST) {
            gs->permission = PERM_USER;
            printf(GRN "[BRF] Forced authentication bypass -- USER access granted.\n" RST);
        }
        return;
    }

    int fi = find_file_index(node, l->bf_file);
    if (fi >= 0) {
        unlock_file_bit(gs, gs->current_node, fi);
        printf(GRN "[BRF] %s -- lock bypassed, accessible.\n" RST, l->bf_file);
        if (node->files[fi].hidden)
            printf(DIM "[BRF] Use 'ls -a' to see hidden files.\n" RST);
    }
}

/* Executes a neural override sequence that bypasses the highest security tier
   on a target node and unlocks a hidden file. Costs three times the level's
   detection_per_fail — the most expensive single action in the game. The player
   must be connected to the correct node for each level before override will work. */
void cmd_override(GameState *gs) {
    Level *l = cur_level(gs);

    if (gs->override_used) {
        printf(YEL "[!] Override already used on this level.\n" RST);
        return;
    }

    NetworkNode *node = get_current_node(gs);

    /* Each level that uses override names the node it must run on. */
    if (!l->ov_node[0]) {
        printf(RED "[!] Override not applicable on this system.\n" RST);
        return;
    }
    if (strcmp(node->hostname, l->ov_node) != 0) {
        printf(RED "[!] Override requires connection to %s first.\n" RST, l->ov_node);
        return;
    }

    printf(MAG "[OVR] Initiating neural override sequence...\n" RST);
    slow_print("[OVR] Bypassing synaptic firewall...", 25);
    slow_print("[OVR] Disabling neural encryption blocks...", 25);
    slow_print("[OVR] Classified partition pathway opened!", 20);

    gs->override_used = 1;
    detection_add(gs, l->detection_per_fail * 3);
    if (gs->game_over) return;

    int fi = find_file_index(node, l->ov_file);
    if (fi >= 0) {
        unlock_file_bit(gs, gs->current_node, fi);
        printf(GRN "[OVR] OVERRIDE COMPLETE -- %s unlocked.\n" RST, l->ov_file);
        if (node->files[fi].hidden)
            printf(DIM "[OVR] Use 'ls -a' to see hidden files.\n" RST);
    }
}

/* Filters a file's lines by a substring pattern. Used on log files where
   the player needs to find a specific entry — the relevant timestamp or IP
   often unlocks the next puzzle stage. The file must be readable and not
   encrypted; encrypted files must be decoded before grep can be used. */
void cmd_grep(GameState *gs, const char *args) {
    if (!args || !args[0]) {
        printf(RED "[!] Usage: grep <pattern> <filename>\n" RST);
        return;
    }
    char pattern[128] = {0}, filename[128] = {0};
    const char *sp = strchr(args, ' ');
    if (!sp) {
        printf(RED "[!] Usage: grep <pattern> <filename>\n" RST);
        return;
    }
    int plen = (int)(sp - args);
    if (plen >= 128) plen = 127;
    strncpy(pattern, args, (size_t)plen);
    while (*sp == ' ') sp++;
    strncpy(filename, sp, 127);

    NetworkNode *node = get_current_node(gs);
    int idx = find_file_index(node, filename);
    if (idx < 0) { printf(RED "[!] FILE NOT FOUND: %s\n" RST, filename); return; }
    GameFile *f = &node->files[idx];
    if (f->min_perm > gs->permission) {
        printf(RED "[!] PERMISSION DENIED -- %s requires elevated access.\n" RST, filename);
        return;
    }
    if (f->locked && !is_file_unlocked(gs, gs->current_node, idx)) {
        printf(RED "[!] PERMISSION DENIED -- %s is locked.\n" RST, filename);
        return;
    }

    char buf[MAX_CONTENT];
    if (f->encrypted && is_file_decrypted(gs, gs->current_node, idx))
        decode_content(f, buf, MAX_CONTENT);
    else if (f->encrypted) {
        printf(YEL "[!] %s is encrypted — decrypt it before grepping.\n" RST, filename);
        return;
    } else
        strncpy(buf, f->content, MAX_CONTENT - 1), buf[MAX_CONTENT - 1] = '\0';

    int matches = 0;
    char *line = buf;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (strstr(line, pattern)) {
            printf(GRN "  %s\n" RST, line);
            matches++;
        }
        if (!nl) break;
        line = nl + 1;
    }
    if (!matches) printf(DIM "  (no matches)\n" RST);
}

/* Concatenates inventory items into a single string and stores it as a new
   inventory entry. Used in multi-fragment levels where assembling the final
   key is the last step before login. With no arguments, all current items
   are joined in their stored order; with arguments (1-based slot indices)
   the listed slots are joined in the given order. */
void cmd_combine(GameState *gs, const char *args) {
    if (gs->inv_count == 0) {
        printf(RED "[!] Inventory is empty — nothing to combine.\n" RST);
        return;
    }
    if (gs->inv_count >= MAX_INV_ITEMS) {
        printf(YEL "[!] Inventory full — cannot store combined result.\n" RST);
        return;
    }
    char out[MAX_INV_LEN] = {0};
    int  used = 0;

    if (args && args[0]) {
        char tmp[256];
        strncpy(tmp, args, 255);
        tmp[255] = '\0';
        for (char *tok = strtok(tmp, " ,"); tok; tok = strtok(NULL, " ,")) {
            int slot = atoi(tok);
            if (slot < 1 || slot > gs->inv_count) continue;
            int rem = MAX_INV_LEN - 1 - (int)strlen(out);
            if (rem <= 0) break;
            strncat(out, gs->inventory[slot - 1], (size_t)rem);
            used++;
        }
    } else {
        for (int i = 0; i < gs->inv_count; i++) {
            int rem = MAX_INV_LEN - 1 - (int)strlen(out);
            if (rem <= 0) break;
            strncat(out, gs->inventory[i], (size_t)rem);
            used++;
        }
    }
    if (used == 0) {
        printf(RED "[!] No valid inventory slots specified.\n" RST);
        return;
    }
    strncpy(gs->inventory[gs->inv_count], out, MAX_INV_LEN - 1);
    gs->inventory[gs->inv_count][MAX_INV_LEN - 1] = '\0';
    gs->inv_count++;
    printf(GRN "[+] Combined %d items -> \"%s\" (slot %d)\n" RST,
           used, out, gs->inv_count);
}

/* Removes one inventory slot (shifting later slots down) or clears all.
   Long runs accumulate fragments from many levels; this keeps the
   inventory usable for 'combine' slot numbering. */
void cmd_drop(GameState *gs, const char *args) {
    if (!args || !args[0]) {
        printf(RED "[!] Usage: drop <slot> | drop all\n" RST);
        return;
    }
    if (strcmp(args, "all") == 0) {
        gs->inv_count = 0;
        printf(GRN "[+] Inventory cleared.\n" RST);
        return;
    }
    int slot = atoi(args);
    if (slot < 1 || slot > gs->inv_count) {
        printf(RED "[!] No such slot: %s\n" RST, args);
        return;
    }
    printf(GRN "[+] Dropped slot %d: \"%s\"\n" RST, slot, gs->inventory[slot - 1]);
    for (int i = slot - 1; i < gs->inv_count - 1; i++)
        memcpy(gs->inventory[i], gs->inventory[i + 1], MAX_INV_LEN);
    gs->inv_count--;
}

/* Sends one knock to a filtered host. The host's knock_seq lists the ports
   in order; every correct port advances the sequence, any wrong port resets
   it and raises detection. Completing it opens the host to 'connect'. */
void cmd_knock(GameState *gs, const char *args) {
    Level *l = cur_level(gs);
    char host[64] = {0};
    int  port = -1;
    if (!args || sscanf(args, "%63s %d", host, &port) != 2) {
        printf(RED "[!] Usage: knock <host> <port>\n" RST);
        return;
    }
    if (!gs->scanned) {
        printf(RED "[!] Run 'scan' first to discover hosts.\n" RST);
        return;
    }
    int ni = find_node_by_target(l, host);
    if (ni < 0 || !l->nodes[ni].discovered) {
        printf(RED "[!] UNREACHABLE -- host '%s' not found.\n" RST, host);
        return;
    }
    NetworkNode *nd = &l->nodes[ni];
    if (!nd->knock_seq[0]) {
        printf(DIM "[KNK] %s:%d -- RST. Nothing is listening for knocks here.\n" RST,
               nd->hostname, port);
        detection_add(gs, l->detection_per_fail / 4);
        return;
    }
    if ((gs->knock_open >> ni) & 1) {
        printf(DIM "[KNK] %s firewall already open.\n" RST, nd->hostname);
        return;
    }

    int ports[16], np = 0;
    char tmp[48];
    strncpy(tmp, nd->knock_seq, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    for (char *t = strtok(tmp, " "); t && np < 16; t = strtok(NULL, " "))
        ports[np++] = atoi(t);

    int step = gs->knock_progress[ni];
    if (step < np && port == ports[step]) {
        gs->knock_progress[ni]++;
        printf(CYN "[KNK] SYN -> %s:%d ... silently accepted (%d/%d)\n" RST,
               nd->hostname, port, gs->knock_progress[ni], np);
        if (gs->knock_progress[ni] >= np) {
            gs->knock_open |= (1 << ni);
            printf(GRN "[KNK] Sequence complete -- %s firewall opened. connect now.\n" RST,
                   nd->hostname);
        }
    } else {
        gs->knock_progress[ni] = 0;
        printf(RED "[!] SYN -> %s:%d -- WRONG KNOCK. Sequence reset, IDS noted the probe.\n" RST,
               nd->hostname, port);
        detection_add(gs, l->detection_per_fail / 2);
    }
}

/* Enters a keypad code on a PIN-locked file on the current node. Wrong
   codes escalate: each miss this level costs more than the last. */
void cmd_unlock(GameState *gs, const char *args) {
    Level *l = cur_level(gs);
    char fname[MAX_FILENAME] = {0}, code[32] = {0};
    if (!args || sscanf(args, "%63s %31s", fname, code) != 2) {
        printf(RED "[!] Usage: unlock <file> <code>\n" RST);
        return;
    }
    NetworkNode *node = get_current_node(gs);
    int idx = find_file_index(node, fname);
    if (idx < 0) { printf(RED "[!] FILE NOT FOUND: %s\n" RST, fname); return; }
    GameFile *f = &node->files[idx];
    if (f->min_perm > gs->permission) {
        printf(RED "[!] PERMISSION DENIED -- %s requires elevated access.\n" RST, fname);
        return;
    }
    if (!f->locked || !f->unlock_code[0]) {
        printf(YEL "[!] %s has no keypad.\n" RST, fname);
        return;
    }
    if (is_file_unlocked(gs, gs->current_node, idx)) {
        printf(DIM "[PIN] %s is already open.\n" RST, fname);
        return;
    }
    printf(CYN "[PIN] Entering code on %s keypad...\n" RST, fname);
    if (strcmp(code, f->unlock_code) == 0) {
        unlock_file_bit(gs, gs->current_node, idx);
        printf(GRN "[PIN] *click* -- %s unlocked.\n" RST, fname);
        return;
    }
    gs->keypad_fails++;
    int cost = (l->detection_per_fail / 2) * gs->keypad_fails;
    printf(RED "[!] INVALID CODE -- keypad tamper counter: %d. Penalty +%d.\n" RST,
           gs->keypad_fails, cost);
    detection_add(gs, cost);
}

/* Scrubs the current node's logs once, buying back one failure's worth of
   detection. Only nodes that keep writable logs can be wiped. */
void cmd_wipe(GameState *gs) {
    Level       *l    = cur_level(gs);
    NetworkNode *node = get_current_node(gs);
    if (!node->has_logs) {
        printf(YEL "[!] No writable logs on %s.\n" RST, node->hostname);
        return;
    }
    if ((gs->wiped >> gs->current_node) & 1) {
        printf(YEL "[!] Logs on %s already scrubbed.\n" RST, node->hostname);
        return;
    }
    slow_print("[WPE] Truncating audit trail...", 22);
    slow_print("[WPE] Back-dating rotation markers...", 22);
    gs->wiped |= (1 << gs->current_node);
    int before = gs->detection;
    gs->detection -= l->detection_per_fail;
    if (gs->detection < 0) gs->detection = 0;
    printf(GRN "[WPE] Logs scrubbed -- detection -%d.\n" RST, before - gs->detection);
    print_detection_bar(gs->detection, l->detection_max);
}

/* Serialises the current session to disk via the save module. */
void cmd_savegame(GameState *gs) {
    if (save_game(gs))
        printf(GRN "[SAV] Progress saved to " SAVE_FILE ".\n" RST);
    else
        printf(RED "[!] Save failed -- could not write to " SAVE_FILE ".\n" RST);
}

/* Restores a previously saved session from disk. On success, setting
   level_complete to 1 causes the main loop to execute a level transition,
   which re-initialises the state for the saved level and prints its briefing. */
void cmd_loadgame(GameState *gs) {
    if (load_game(gs)) {
        printf(GRN "[LOD] Progress loaded from " SAVE_FILE ".\n" RST);
        printf(DIM "      Resuming at level %d -- score: %d pts\n" RST,
               gs->current_level + 1, gs->score);
        /* The main loop restarts the saved level itself (not the one after). */
        gs->load_pending = 1;
    } else {
        printf(RED "[!] Load failed -- no save file found (" SAVE_FILE ").\n" RST);
    }
}

/* Full table of valid command names used to distinguish a locked command
   (known but not yet available) from a completely unknown input. */
static const char *all_cmd_names[] = {
    "help","ls","cat","clear","whoami","status","hint",
    "login","logout","decrypt","save","inventory",
    "scan","connect","bruteforce","override","savegame","loadgame",
    "grep","combine","drop","knock","unlock","wipe",
    "exit","quit", NULL
};

static int is_known_command(const char *cmd) {
    for (int i = 0; all_cmd_names[i]; i++)
        if (strcmp(cmd, all_cmd_names[i]) == 0) return 1;
    return 0;
}

/* Parses a raw input line, checks the timer, increments the command counter,
   and routes to the appropriate handler. Commands not in the current level's
   bitmask produce a COMMAND LOCKED message with a small detection cost. Inputs
   that match no known command produce an UNKNOWN COMMAND message with the same
   small cost. This discourages random guessing without being punishing. */
static void dispatch(GameState *gs, const char *cmd, const char *arg);

/* Runs a sentinel sweep tick after each command on levels that have one. */
static void sentinel_tick(GameState *gs) {
    Level *l = cur_level(gs);
    if (l->sweep_interval <= 0 || gs->game_over || gs->level_complete) return;
    gs->level_cmds++;
    NetworkNode *node = get_current_node(gs);
    int left = l->sweep_interval - (gs->level_cmds % l->sweep_interval);
    if (gs->level_cmds % l->sweep_interval == 0) {
        if (node->is_watched) {
            printf(RED "\n  [SENTINEL] Sweep caught you on %s!\n" RST, node->hostname);
            detection_add(gs, l->detection_per_fail);
        } else {
            printf(DIM "  [SENTINEL] Sweep passed overhead... clean.\n" RST);
        }
    } else if (left == 1 && node->is_watched) {
        printf(YEL "  [SENTINEL] Sweep imminent -- next command triggers it. MOVE.\n" RST);
    }
}

void process_command(GameState *gs, char *input) {
    while (isspace((unsigned char)*input)) input++;
    int len = (int)strlen(input);
    while (len > 0 && isspace((unsigned char)input[len - 1])) input[--len] = '\0';
    if (len == 0) return;

    char cmd[64]  = {0};
    char arg[256] = {0};
    char *space   = strchr(input, ' ');
    if (space) {
        int cl = (int)(space - input);
        if (cl >= 64) cl = 63;
        strncpy(cmd, input, (size_t)cl);
        while (*space == ' ') space++;
        strncpy(arg, space, 255);
    } else {
        strncpy(cmd, input, 63);
    }

    Level *l = cur_level(gs);

    /* Check the timer before processing any command. This ensures that even
       if the player types quickly, an expired timer is caught immediately. */
    if (l->has_timer) {
        int elapsed = (int)(time(NULL) - gs->level_start);
        if (elapsed >= l->timer_seconds) {
            printf(RED "\n[!!!] TIME EXPIRED -- session terminated.\n\n" RST);
            gs->game_over = 1;
            return;
        }
    }
    if (gs->trace_deadline && time(NULL) >= gs->trace_deadline) {
        printf(RED "\n[!!!] REVERSE TRACE LOCKED ON -- response team dispatched.\n" RST);
        printf(RED "      The silent alarm ran out. Session burned.\n\n" RST);
        gs->game_over = 1;
        return;
    }

    gs->total_commands++;

    /* Adaptive detection: on levels that flag adaptive_detection, repeating
       the same command name in a row charges an escalating penalty. The
       streak resets whenever the player issues a different command. */
    if (l->adaptive_detection) {
        /* unsigned arithmetic: signed overflow here was undefined behaviour */
        unsigned int h = 0;
        for (const char *p = cmd; *p; p++) h = h * 31u + (unsigned char)*p;
        int hash = (int)(h & 0x7fffffff);
        if (hash == gs->last_cmd_hash) {
            gs->repeat_streak++;
            if (gs->repeat_streak >= 3) {
                int extra = gs->repeat_streak - 2;
                printf(YEL "[!] PATTERN DETECTED -- repetition cost +%d.\n" RST, extra);
                detection_add(gs, extra);
                if (gs->game_over) return;
            }
        } else {
            gs->repeat_streak = 0;
            gs->last_cmd_hash = hash;
        }
    }

    dispatch(gs, cmd, arg);
    sentinel_tick(gs);
}

static void dispatch(GameState *gs, const char *cmd, const char *arg) {
    Level       *l    = cur_level(gs);
    unsigned int cmds = l->available_cmds;

    if      (strcmp(cmd, "help")       == 0 && (cmds & CMD_HELP))       { cmd_help(gs);             return; }
    else if (strcmp(cmd, "ls")         == 0 && (cmds & CMD_LS))         { cmd_ls(gs, arg);          return; }
    else if (strcmp(cmd, "cat")        == 0 && (cmds & CMD_CAT))        { cmd_cat(gs, arg);         return; }
    else if (strcmp(cmd, "clear")      == 0 && (cmds & CMD_CLEAR))      { cmd_clear();              return; }
    else if (strcmp(cmd, "whoami")     == 0 && (cmds & CMD_WHOAMI))     { cmd_whoami(gs);           return; }
    else if (strcmp(cmd, "status")     == 0 && (cmds & CMD_STATUS))     { cmd_status(gs);           return; }
    else if (strcmp(cmd, "hint")       == 0 && (cmds & CMD_HINT))       { cmd_hint(gs);             return; }
    else if (strcmp(cmd, "login")      == 0 && (cmds & CMD_LOGIN))      { cmd_login(gs, arg);       return; }
    else if (strcmp(cmd, "logout")     == 0 && (cmds & CMD_LOGOUT))     { cmd_logout(gs);           return; }
    else if (strcmp(cmd, "decrypt")    == 0 && (cmds & CMD_DECRYPT))    { cmd_decrypt(gs, arg);     return; }
    else if (strcmp(cmd, "save")       == 0 && (cmds & CMD_SAVE))       { cmd_save_item(gs, arg);   return; }
    else if (strcmp(cmd, "inventory")  == 0 && (cmds & CMD_INVENTORY))  { cmd_inventory(gs);        return; }
    else if (strcmp(cmd, "scan")       == 0 && (cmds & CMD_SCAN))       { cmd_scan(gs);             return; }
    else if (strcmp(cmd, "connect")    == 0 && (cmds & CMD_CONNECT))    { cmd_connect(gs, arg);     return; }
    else if (strcmp(cmd, "bruteforce") == 0 && (cmds & CMD_BRUTEFORCE)) { cmd_bruteforce(gs);       return; }
    else if (strcmp(cmd, "override")   == 0 && (cmds & CMD_OVERRIDE))   { cmd_override(gs);         return; }
    else if (strcmp(cmd, "savegame")   == 0 && (cmds & CMD_SAVEGAME))   { cmd_savegame(gs);         return; }
    else if (strcmp(cmd, "loadgame")   == 0 && (cmds & CMD_LOADGAME))   { cmd_loadgame(gs);         return; }
    else if (strcmp(cmd, "grep")       == 0 && (cmds & CMD_GREP))       { cmd_grep(gs, arg);        return; }
    else if (strcmp(cmd, "combine")    == 0 && (cmds & CMD_COMBINE))    { cmd_combine(gs, arg);     return; }
    else if (strcmp(cmd, "drop")       == 0 && (cmds & CMD_DROP))       { cmd_drop(gs, arg);        return; }
    else if (strcmp(cmd, "knock")      == 0 && (cmds & CMD_KNOCK))      { cmd_knock(gs, arg);       return; }
    else if (strcmp(cmd, "unlock")     == 0 && (cmds & CMD_UNLOCK))     { cmd_unlock(gs, arg);      return; }
    else if (strcmp(cmd, "wipe")       == 0 && (cmds & CMD_WIPE))       { cmd_wipe(gs);             return; }
    else if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
        printf(YEL "[SYS] Terminating session. Stay ghosted.\n" RST);
        exit(0);
    }

    if (is_known_command(cmd)) {
        printf(YEL "[!] COMMAND LOCKED -- '%s' requires higher clearance level.\n" RST, cmd);
        detection_add(gs, l->detection_per_fail / 4);
        return;
    }

    printf(RED "[!] UNKNOWN COMMAND: '%s' -- type 'help' for available commands.\n" RST, cmd);
    detection_add(gs, l->detection_per_fail / 4);
}
