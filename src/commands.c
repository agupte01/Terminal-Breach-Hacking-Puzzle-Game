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
        if (f->locked && !is_file_unlocked(gs, gs->current_node, i)) continue;
        if (f->min_perm > gs->permission) continue;

        int decrypted = is_file_decrypted(gs, gs->current_node, i);
        if (f->encrypted && !decrypted)
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
        printf(RED "[!] PERMISSION DENIED -- %s is locked.\n" RST, filename);
        return;
    }

    printf(DIM "-- %s " RST, filename);
    print_separator();

    int decrypted = is_file_decrypted(gs, gs->current_node, idx);
    if (f->encrypted && !decrypted) {
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

    const char *method = (f->puzzle_type == PUZZLE_CAESAR)  ? "Caesar cipher"   :
                         (f->puzzle_type == PUZZLE_REVERSE) ? "Reverse text"    :
                         (f->puzzle_type == PUZZLE_BINARY)  ? "Binary-to-ASCII" : "Unknown";
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
    if (l->nodes[node_i].is_entry && node_i == gs->current_node) {
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

    printf(GRN "[NET] Establishing connection to %s...\n" RST, target);
    slow_print("[NET] Routing through proxy chain...", 22);
    slow_print("[NET] Handshake complete.", 22);
    printf(GRN "[NET] CONNECTION ESTABLISHED -- %s (%s)\n" RST,
           l->nodes[node_i].ip, l->nodes[node_i].hostname);

    gs->current_node = node_i;

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
    Level *l = cur_level(gs);

    if (gs->bruteforce_used) {
        printf(YEL "[!] Bruteforce already used on this level.\n" RST);
        return;
    }
    printf(RED "[BRF] Initiating brute-force on authentication subsystem...\n" RST);
    slow_print("[BRF] Generating key candidates...", 30);
    slow_print("[BRF] Applying dictionary attack...", 30);
    slow_print("[BRF] Bypassing rate limiting...", 30);
    slow_print("[BRF] Partial access achieved!", 20);

    gs->bruteforce_used = 1;
    detection_add(gs, l->detection_per_fail * 2);
    if (gs->game_over) return;

    printf(RED "[!] ALERT: Brute-force activity detected — detection spike!\n" RST);

    /* Level 4: unlocks vault_access.txt which reveals the password prefix. */
    if (gs->current_level == 4) {
        NetworkNode *node = get_current_node(gs);
        int fi = find_file_index(node, "vault_access.txt");
        if (fi >= 0) {
            unlock_file_bit(gs, gs->current_node, fi);
            printf(GRN "[BRF] vault_access.txt -- unlocked and accessible.\n" RST);
        }
    }

    /* Level 7: grants USER access directly if the player is still at GUEST tier,
       bypassing the normal credential requirement on the AI Core entry node. */
    if (gs->current_level == 7 && gs->permission == PERM_GUEST) {
        gs->permission = PERM_USER;
        printf(GRN "[BRF] Forced authentication bypass -- USER access granted.\n" RST);
    }

    /* Level 12: unlocks locked_comms.enc on vendor-hub, which holds fragment 2
       of the SHADOWMARKET master key. Must be on vendor-hub when used. */
    if (gs->current_level == 12) {
        NetworkNode *node = get_current_node(gs);
        int fi = find_file_index(node, "locked_comms.enc");
        if (fi >= 0) {
            unlock_file_bit(gs, gs->current_node, fi);
            printf(GRN "[BRF] locked_comms.enc -- authentication bypassed, accessible.\n" RST);
        }
    }

    /* Level 13: unlocks locked_manifest.txt on quantum-relay, which directs
       the player to use override on quantum-core as the next required step. */
    if (gs->current_level == 13) {
        NetworkNode *node = get_current_node(gs);
        int fi = find_file_index(node, "locked_manifest.txt");
        if (fi >= 0) {
            unlock_file_bit(gs, gs->current_node, fi);
            printf(GRN "[BRF] locked_manifest.txt -- security partition bypassed.\n" RST);
        }
    }

    /* Level 14: unlocks day.enc on fragment-beta, which holds fragment 2
       of the ZERO_DAY_BLACKOUT deactivation key. Must be on fragment-beta. */
    if (gs->current_level == 14) {
        NetworkNode *node = get_current_node(gs);
        int fi = find_file_index(node, "day.enc");
        if (fi >= 0) {
            unlock_file_bit(gs, gs->current_node, fi);
            printf(GRN "[BRF] day.enc -- comms archive unlocked.\n" RST);
        }
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

    /* Each level that uses override requires the player to be on a specific node.
       These checks enforce that requirement and give an informative error if the
       player tries to use override from the wrong location. */
    if (gs->current_level == 7) {
        if (strcmp(node->hostname, "neural-net") != 0) {
            printf(RED "[!] Override requires connection to neural-net node first.\n" RST);
            return;
        }
    } else if (gs->current_level == 13) {
        if (strcmp(node->hostname, "quantum-core") != 0) {
            printf(RED "[!] Override requires connection to quantum-core first.\n" RST);
            return;
        }
    } else if (gs->current_level == 14) {
        if (strcmp(node->hostname, "omega-core") != 0) {
            printf(RED "[!] Override requires connection to omega-core first.\n" RST);
            return;
        }
    } else {
        printf(RED "[!] Override not applicable on this system.\n" RST);
        return;
    }

    printf(MAG "[OVR] Initiating neural override sequence...\n" RST);
    slow_print("[OVR] Bypassing synaptic firewall...", 25);
    slow_print("[OVR] Disabling neural encryption blocks...", 25);
    slow_print("[OVR] Classified partition pathway opened!", 20);

    gs->override_used = 1;
    detection_add(gs, l->detection_per_fail * 3);
    if (gs->game_over) return;

    /* Level 7: unlocks .genesis_key on neural-net, which contains the final
       fragment (digit 7) needed to complete NEURAL_0VERRIDE_7. */
    if (gs->current_level == 7) {
        int fi = find_file_index(node, ".genesis_key");
        if (fi >= 0) {
            unlock_file_bit(gs, gs->current_node, fi);
            printf(GRN "[OVR] OVERRIDE COMPLETE -- .genesis_key unlocked.\n" RST);
            printf(DIM "[OVR] Use 'ls -a' to see hidden files.\n" RST);
        }
    }
    /* Level 13: unlocks .classified_key on quantum-core, which holds the full
       assembled QUANTUM_BREACH_9 password as a confirmation. */
    else if (gs->current_level == 13) {
        int fi = find_file_index(node, ".classified_key");
        if (fi >= 0) {
            unlock_file_bit(gs, gs->current_node, fi);
            printf(GRN "[OVR] OVERRIDE COMPLETE -- .classified_key unlocked.\n" RST);
            printf(DIM "[OVR] Use 'ls -a' to see hidden files.\n" RST);
        }
    }
    /* Level 14: unlocks .deactivation_key on omega-core, which contains
       fragment 4 (OUT) and the full ZERO_DAY_BLACKOUT key. */
    else if (gs->current_level == 14) {
        int fi = find_file_index(node, ".deactivation_key");
        if (fi >= 0) {
            unlock_file_bit(gs, gs->current_node, fi);
            printf(GRN "[OVR] OVERRIDE COMPLETE -- .deactivation_key unlocked.\n" RST);
            printf(DIM "[OVR] Use 'ls -a' to see hidden files.\n" RST);
        }
    }
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
    int old_level = gs->current_level;
    if (load_game(gs)) {
        printf(GRN "[LOD] Progress loaded from " SAVE_FILE ".\n" RST);
        printf(DIM "      Resuming at level %d — score: %d pts\n" RST,
               gs->current_level + 1, gs->score);
        if (gs->current_level != old_level)
            gs->level_complete = 1;
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

    Level       *l    = cur_level(gs);
    unsigned int cmds = l->available_cmds;

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

    gs->total_commands++;

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
