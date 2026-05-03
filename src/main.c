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

    for (int i = 0; i < MAX_NODES; i++) {
        gs->node_files_unlocked[i]  = 0;
        gs->node_files_decrypted[i] = 0;
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
static void level_transition(GameState *gs, int next) {
    printf("\n");
    print_separator();
    slow_print("[SYS] Level complete. Pivoting to next target...", 28);
    slow_print("[NET] Routing to next system...",                   28);
    slow_print("[NET] Connection established.",                     28);
    printf(GRN "[SYS] Loading: %s\n" RST, get_level(next)->name);
    print_separator();
    printf("\n");

    unsigned int prev = get_level(gs->current_level)->available_cmds;
    unsigned int nxt  = get_level(next)->available_cmds;
    show_new_commands(prev, nxt);

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

    int duration = (int)(time(NULL) - gs->game_start);
    int mins     = duration / 60;
    int secs     = duration % 60;

    printf(GRN "  ╔══════════════════════════════════════════════════════╗\n" RST);
    printf(GRN "  ║  TERMINAL BREACH -- COMPLETE                        ║\n" RST);
    printf(GRN "  ║  All 16 systems compromised. You are unstoppable.   ║\n" RST);
    printf(GRN "  ╠══════════════════════════════════════════════════════╣\n" RST);
    printf(GRN "  ║  FINAL SCORE    : %-7d pts                       ║\n" RST, gs->score);
    printf(GRN "  ║  Total fails    : %-4d                             ║\n" RST, gs->total_fails);
    printf(GRN "  ║  Commands used  : %-4d                             ║\n" RST, gs->total_commands);
    printf(GRN "  ║  Time taken     : %02d:%02d                             ║\n" RST, mins, secs);
    printf(GRN "  ╠══════════════════════════════════════════════════════╣\n" RST);
    printf(GRN "  ║  Level scores:                                      ║\n" RST);
    for (int i = 0; i < TOTAL_LEVELS; i++) {
        Level *lv = get_level(i);
        printf(GRN "  ║    L%-2d %-21s %5d pts              ║\n" RST,
               i + 1, lv->name, gs->level_scores[i]);
    }
    printf(GRN "  ╠══════════════════════════════════════════════════════╣\n" RST);

    /* Rank is determined by total login failures across the entire run. */
    const char *rank;
    if      (gs->total_fails == 0)  rank = "GHOST LEGEND -- Flawless run!";
    else if (gs->total_fails <= 3)  rank = "PHANTOM      -- Near perfect!";
    else if (gs->total_fails <= 8)  rank = "SPECTRE      -- Well played.";
    else if (gs->total_fails <= 15) rank = "AGENT        -- Good effort.";
    else                            rank = "ROOKIE       -- Keep training.";

    printf(GRN "  ║  Rank: %-44s║\n" RST, rank);
    printf(GRN "  ╚══════════════════════════════════════════════════════╝\n" RST);
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
    reset_level(&gs, 0);

    boot_sequence();
    print_mission_briefing(get_level(0));

    char input[INPUT_BUF];
    char prompt[128];

    while (1) {
        get_prompt(&gs, prompt, sizeof(prompt));
        printf("%s", prompt);
        fflush(stdout);

        /* EOF (Ctrl-D) exits cleanly. */
        if (!fgets(input, sizeof(input), stdin)) {
            printf("\n");
            break;
        }

        process_command(&gs, input);

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
            level_transition(&gs, next);
        }
    }

    return 0;
}
