/*
 * main.c — Game loop, level transitions, and end-game screens.
 *
 * This is the entry point and top-level controller for Terminal Breach.
 * It initialises all level data, runs the main read-eval loop, handles
 * level-to-level transitions, and renders the win and game-over screens.
 * All actual command logic lives in commands.c; this file only manages
 * the lifecycle around those calls.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "utils.h"
#include "levels.h"
#include "commands.h"

#define INPUT_BUF 512

#define GRN  "\033[1;32m"
#define RED  "\033[1;31m"
#define YEL  "\033[1;33m"
#define CYN  "\033[1;36m"
#define DIM  "\033[0;37m"
#define MAG  "\033[1;35m"
#define RST  "\033[0m"

/* Resets all per-level fields in GameState for a fresh start on level_id.
   This is called both when starting the game and when advancing to the next
   level. Level data itself is never modified — only the mutable GameState
   fields that track the current session are zeroed or reseeded. */
static void reset_level(GameState *gs, int level_id) {
    gs->current_level   = level_id;
    gs->current_node    = 0;
    gs->permission      = PERM_GUEST;
    gs->detection       = 0;
    gs->attempts        = 0;
    gs->scanned         = 0;
    gs->bruteforce_used = 0;
    gs->override_used   = 0;
    gs->level_complete  = 0;
    gs->game_over       = 0;
    gs->level_start     = time(NULL);

    /* Per-level navigation and mechanic state. These used to leak across
       levels: a stale nodes_connected bitmask let players skip routing
       requirements on later levels whose node indices happened to match. */
    gs->nodes_connected = 1;      /* entry node (index 0) counts as visited */
    gs->last_node       = 0;
    gs->last_cmd_hash   = 0;
    gs->repeat_streak   = 0;
    gs->level_cmds      = 0;
    gs->knock_open      = 0;
    gs->wiped           = 0;
    gs->keypad_fails    = 0;
    gs->trace_deadline  = 0;
    gs->load_pending    = 0;
    gs->su_mask         = 0;

    for (int i = 0; i < MAX_NODES; i++) {
        gs->node_files_unlocked[i]  = 0;
        gs->node_files_decrypted[i] = 0;
        gs->knock_progress[i]       = 0;
        gs->knock_open_at[i]        = 0;
        for (int j = 0; j < MAX_FILES; j++) gs->file_layers[i][j] = 0;
    }

    /* Mark only the entry node as discovered so the player starts with a
       clean network view and must run 'scan' to find the other nodes. */
    Level *l = get_level(level_id);
    for (int i = 0; i < l->node_count; i++)
        l->nodes[i].discovered = l->nodes[i].is_entry;
}

/* Handles the transition from a completed level to the next. Announces any
   newly unlocked commands, resets state for the new level, and prints its
   mission briefing. The slow-print lines give a brief narrative pause between
   levels that reinforces the sense of moving to a new target. */
static void level_transition(GameState *gs, int next, unsigned int prev_cmds,
                             int keep_inventory) {
    printf("\n");
    print_separator();
    if (next == 25) {
        printf(MAG);
        slow_print("[????] ...the Architect is dead. So why is the network still talking?", 22);
        slow_print("[????] A dead-man seed just fired. Codename: LAZARUS.", 22);
        printf(RST);
    }
    if (next == 35) {
        printf(MAG);
        slow_print("[ZERO] You logged in as yourself. The Architect was always GHOST.", 22);
        slow_print("[MIRROR] ...and now five agencies know it too. Operation MIRROR is live.", 22);
        slow_print("[SYS]  ACT V -- ERASURE. Burn every record of GHOST. Then GHOST.", 22);
        printf(RST);
    }
    slow_print("[SYS] Level complete. Pivoting to next target...", 28);
    slow_print("[NET] Routing to next system...",                   28);
    slow_print("[NET] Connection established.",                     28);
    printf(GRN "[SYS] Loading: %s\n" RST, get_level(next)->name);
    print_separator();
    printf("\n");

    show_new_commands(prev_cmds, get_level(next)->available_cmds);

    /* Fragments never carry between targets, so start each level with an
       empty inventory. This keeps 'combine 1 2 3' slot numbers matching the
       walkthroughs and stops the inventory filling up over a long run. A
       loadgame restart keeps the inventory it just restored. */
    if (!keep_inventory && gs->inv_count > 0) {
        gs->inv_count = 0;
        printf(DIM "[SYS] Inventory purged for the new target.\n" RST);
    }

    reset_level(gs, next);
    print_mission_briefing(get_level(next));
}

/* Renders the final win screen. Displays the total score, session statistics,
   per-level breakdown, and the player's rank based on total failed attempts.
   The ASCII art is printed with slow_print to maintain the animated aesthetic. */
static void show_win_screen(GameState *gs) {
    clear_screen();
    printf(GRN);
    slow_print("  ╔══════════════════════════════════════════════════════╗", 6);
    slow_print("  ║   ██╗   ██╗ ██████╗ ██╗   ██╗    ██╗    ██╗██╗███╗  ║", 6);
    slow_print("  ║   ╚██╗ ██╔╝██╔═══██╗██║   ██║    ██║    ██║██║████╗ ║", 6);
    slow_print("  ║    ╚████╔╝ ██║   ██║██║   ██║    ██║ █╗ ██║██║██╔██╗║", 6);
    slow_print("  ║     ╚██╔╝  ██║   ██║██║   ██║    ██║███╗██║██║██║╚██║", 6);
    slow_print("  ║      ██║   ╚██████╔╝╚██████╔╝    ╚███╔███╔╝██║██║ ╚█║", 6);
    slow_print("  ╚══════════════════════════════════════════════════════╝", 6);
    printf(RST "\n");

    printf(MAG);
    slow_print("  [NULL] free(ghost); ghost = NULL;", 18);
    slow_print("  [NULL] Every record is gone. Every mirror is dark. Nobody is looking", 18);
    slow_print("  [NULL] for you, because there is no one left to find.", 18);
    printf(RST "\n");

    int duration = (int)(time(NULL) - gs->game_start);
    int mins     = duration / 60;
    int secs     = duration % 60;

    printf(GRN "  ╔═════════════════════════════════════════════════════╗\n" RST);
    printf(GRN "  ║  TERMINAL BREACH -- COMPLETE                        ║\n" RST);
    printf(GRN "  ║  All %2d systems compromised. GHOST was never here.  ║\n" RST, TOTAL_LEVELS);
    printf(GRN "  ╠═════════════════════════════════════════════════════╣\n" RST);
    printf(GRN "  ║  FINAL SCORE    : %-7d pts                       ║\n" RST, gs->score);
    printf(GRN "  ║  Total fails    : %-4d                              ║\n" RST, gs->total_fails);
    printf(GRN "  ║  Commands used  : %-4d                              ║\n" RST, gs->total_commands);
    printf(GRN "  ║  Time taken     : %02d:%02d                             ║\n" RST, mins, secs);
    printf(GRN "  ╠═════════════════════════════════════════════════════╣\n" RST);
    printf(GRN "  ║  Level scores:                                      ║\n" RST);
    for (int i = 0; i < TOTAL_LEVELS; i++) {
        Level *lv = get_level(i);
        printf(GRN "  ║    L%-2d %-27.27s %6d pts       ║\n" RST,
               i + 1, lv->name, gs->level_scores[i]);
    }
    printf(GRN "  ╠═════════════════════════════════════════════════════╣\n" RST);

    /* Rank is determined by total login failures across the entire run. */
    const char *rank;
    if      (gs->total_fails == 0)  rank = "GHOST LEGEND -- Flawless run!";
    else if (gs->total_fails <= 4)  rank = "PHANTOM      -- Near perfect!";
    else if (gs->total_fails <= 10) rank = "SPECTRE      -- Well played.";
    else if (gs->total_fails <= 20) rank = "AGENT        -- Good effort.";
    else                            rank = "ROOKIE       -- Keep training.";

    printf(GRN "  ║  Rank: %-45s║\n" RST, rank);
    printf(GRN "  ╚═════════════════════════════════════════════════════╝\n" RST);
    printf("\n");
}

/* Renders the game-over screen shown when detection is maxed out or the
   attempt limit is exceeded. Tells the player which level they failed on
   and the score they accumulated before the run ended. */
static void show_game_over(GameState *gs) {
    printf("\n");
    printf(RED);
    slow_print("  ██████╗  █████╗ ███╗   ███╗███████╗     ██████╗ ██╗   ██╗███████╗██████╗", 6);
    slow_print("  ██╔════╝██╔══██╗████╗ ████║██╔════╝    ██╔═══██╗██║   ██║██╔════╝██╔══██╗", 6);
    slow_print("  ██║  ███╗███████║██╔████╔██║█████╗      ██║   ██║██║   ██║█████╗  ██████╔╝", 6);
    slow_print("  ██║   ██║██╔══██║██║╚██╔╝██║██╔══╝     ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗", 6);
    slow_print("  ╚██████╔╝██║  ██║██║ ╚═╝ ██║███████╗   ╚██████╔╝ ╚████╔╝ ███████╗██║  ██║", 6);
    slow_print("   ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝    ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝", 6);
    printf(RST "\n");
    printf(RED "  [!] System lockout. Trace initiated. Session terminated.\n" RST);
    printf(DIM "  Level %d/%d failed. Total fails: %d. Score: %d pts.\n\n" RST,
           gs->current_level + 1, TOTAL_LEVELS, gs->total_fails, gs->score);
    printf(DIM "  Run the game again to retry from level %d.\n\n" RST,
           gs->current_level + 1);
}

int main(void) {
    init_levels();

    GameState gs;
    memset(&gs, 0, sizeof(gs));
    gs.game_start = time(NULL);

    /* Developer/practice shortcut: TB_START_LEVEL=26 ./terminal_breach
       jumps straight to a level (1-based). Scores for skipped levels stay 0. */
    int start = 0;
    const char *sl = getenv("TB_START_LEVEL");
    if (sl) {
        int v = atoi(sl) - 1;
        if (v >= 0 && v < TOTAL_LEVELS) start = v;
    }
    reset_level(&gs, start);

    boot_sequence();
    print_mission_briefing(get_level(start));

    char input[INPUT_BUF];
    char prompt[256];

    while (1) {
        get_prompt(&gs, prompt, sizeof(prompt));
        printf("%s", prompt);
        fflush(stdout);

        /* EOF (Ctrl-D) exits cleanly. */
        if (!fgets(input, sizeof(input), stdin)) {
            printf("\n");
            break;
        }

        unsigned int cmds_before = get_level(gs.current_level)->available_cmds;
        process_command(&gs, input);

        /* loadgame: restart the saved level cleanly (previously this jumped
           to saved_level + 1, silently skipping a level). */
        if (gs.load_pending) {
            gs.load_pending = 0;
            level_transition(&gs, gs.current_level, cmds_before, 1);
            continue;
        }

        if (gs.game_over) {
            show_game_over(&gs);
            break;
        }

        if (gs.level_complete) {
            int next = gs.current_level + 1;
            if (next >= TOTAL_LEVELS) {
                show_win_screen(&gs);
                break;
            }
            level_transition(&gs, next, cmds_before, 0);
        }
    }

    return 0;
}
