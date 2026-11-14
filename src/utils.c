/*
 * utils.c — Terminal rendering and UI presentation helpers.
 *
 * This module owns all output that is not a direct response to a player
 * command: the boot animation, mission briefings, the detection bar, prompt
 * building, and the slow-print effect. Centralising rendering here keeps the
 * command handlers in commands.c focused on game logic rather than formatting.
 */

#include "utils.h"
#include "levels.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>

#define GRN  "\033[1;32m"
#define YEL  "\033[1;33m"
#define CYN  "\033[1;36m"
#define RED  "\033[1;31m"
#define DIM  "\033[0;37m"
#define MAG  "\033[1;35m"
#define RST  "\033[0m"

/* Prints text one character at a time with a nanosleep between each character.
   delay_ms is the per-character pause in milliseconds. This gives the terminal
   a live, active feel without relying on any animation library. */
void slow_print(const char *text, int delay_ms) {
    /* TB_FAST=1 disables the typewriter effect (handy for testing). */
    static int fast = -1;
    if (fast < 0) { const char *e = getenv("TB_FAST"); fast = (e && e[0] == '1'); }
    if (fast) { puts(text); fflush(stdout); return; }
    struct timespec ts;
    ts.tv_sec  = 0;
    ts.tv_nsec = (long)delay_ms * 1000000L;
    for (int i = 0; text[i] != '\0'; i++) {
        putchar(text[i]);
        fflush(stdout);
        nanosleep(&ts, NULL);
    }
    putchar('\n');
    fflush(stdout);
}

/* Prints a horizontal rule to visually separate sections of output. */
void print_separator(void) {
    printf(DIM "─────────────────────────────────────────────────────\n" RST);
}

/* Clears the terminal using the standard ANSI cursor-home + erase-display
   escape sequence. Works on any POSIX-compatible terminal emulator. */
void clear_screen(void) {
    printf("\033[H\033[2J");
    fflush(stdout);
}

/* Builds the shell prompt string into buf. The prompt reflects the player's
   current node IP and permission tier, giving constant spatial and access-level
   feedback without the player needing to run 'status' or 'whoami'. */
void get_prompt(GameState *gs, char *buf, int buflen) {
    Level       *l   = get_level(gs->current_level);
    NetworkNode *n   = &l->nodes[gs->current_node];
    const char  *prm = (gs->permission == PERM_ADMIN) ? "root" :
                       (gs->permission == PERM_USER)  ? "user" : "guest";
    /* Live countdowns in the prompt: the level timer and, once a silent
       alarm trips, the reverse-trace clock. */
    char clock[64] = "";
    time_t now = time(NULL);
    if (l->has_timer) {
        int rem = l->timer_seconds - (int)(now - gs->level_start);
        if (rem < 0) rem = 0;
        snprintf(clock, sizeof(clock), YEL "[T-%d]" RST, rem);
    }
    if (gs->trace_deadline) {
        int tr = (int)(gs->trace_deadline - now);
        if (tr < 0) tr = 0;
        size_t used = strlen(clock);
        snprintf(clock + used, sizeof(clock) - used, RED "[TRACE %d]" RST, tr);
    }
    snprintf(buf, (size_t)buflen,
             "%s" GRN "ghost@%s" RST DIM "[%s]" RST "%s",
             clock, n->ip, prm,
             ((gs->su_mask >> gs->current_node) & 1) ? RED ":~# " RST : GRN ":~$ " RST);
}

/* Renders the detection progress bar as a block-character fill scaled to a
   24-character wide display. The colour transitions from green to yellow at
   50% and from yellow to red at 80%, giving an intuitive urgency signal.
   Called after every action that increases the detection counter. */
void print_detection_bar(int detection, int max) {
    if (max <= 0) return;
    int pct    = (detection * 100) / max;
    int width  = 24;
    int filled = (detection * width) / max;
    if (filled > width) filled = width;

    const char *colour = (pct >= 80) ? RED :
                         (pct >= 50) ? YEL : GRN;

    printf(RED "  [DETECT] " RST "[");
    for (int i = 0; i < width; i++)
        printf("%s%s" RST, colour, (i < filled) ? "█" : "░");
    printf("] %s%3d%%" RST "\n", colour, pct);
    fflush(stdout);
}

/* Prints the mission briefing for a level. The objective text is word-wrapped
   at 54 columns so it fits cleanly inside the bordered display without any
   truncation on standard terminal widths. */
void print_mission_briefing(Level *l) {
    printf("\n");
    print_separator();
    printf(CYN "  ▶ MISSION BRIEFING — LEVEL %d\n" RST, l->id + 1);
    print_separator();
    printf(YEL "  TARGET     : " RST "%s\n",         l->name);
    printf(YEL "  DIFFICULTY : " RST "%s\n",         l->difficulty);
    printf(YEL "  OBJECTIVE  :\n" RST);
    const char *p = l->objective;
    while (*p) {
        printf("    ");
        int col = 0;
        while (*p && !(*p == '\n') && col < 54) {
            putchar(*p++); col++;
        }
        if (*p == '\n') p++;
        putchar('\n');
    }
    if (strlen(l->warnings) > 0) {
        printf(RED "  ⚠  WARNINGS : %s\n" RST, l->warnings);
    }
    if (l->has_timer) {
        printf(YEL "  ⏱  TIMER    : %d seconds\n" RST, l->timer_seconds);
    }
    print_separator();
    printf("\n");
}

/* Compares two command bitmasks and announces any commands that appear in cur
   but not in prev. Called during level transitions so the player knows exactly
   what new tools are available without having to re-read the help text. */
void show_new_commands(unsigned int prev, unsigned int cur) {
    unsigned int diff = cur & ~prev;
    if (!diff) return;
    printf(MAG "\n  [+] NEW COMMANDS UNLOCKED:\n" RST);
    if (diff & CMD_LOGIN)      printf(MAG "      login <password>\n" RST);
    if (diff & CMD_DECRYPT)    printf(MAG "      decrypt <file>\n" RST);
    if (diff & CMD_SAVE)       printf(MAG "      save <data>  |  inventory\n" RST);
    if (diff & CMD_SCAN)       printf(MAG "      scan\n" RST);
    if (diff & CMD_CONNECT)    printf(MAG "      connect <ip>\n" RST);
    if (diff & CMD_BRUTEFORCE) printf(MAG "      bruteforce\n" RST);
    if (diff & CMD_OVERRIDE)   printf(MAG "      override\n" RST);
    if (diff & CMD_SAVEGAME)   printf(MAG "      savegame  |  loadgame\n" RST);
    if (diff & CMD_HINT)       printf(MAG "      hint\n" RST);
    if (diff & CMD_LOGOUT)     printf(MAG "      logout\n" RST);
    if (diff & CMD_GREP)       printf(MAG "      grep <pattern> <file>\n" RST);
    if (diff & CMD_COMBINE)    printf(MAG "      combine [slots...]\n" RST);
    if (diff & CMD_DROP)       printf(MAG "      drop <slot|all>\n" RST);
    if (diff & CMD_KNOCK)      printf(MAG "      knock <host> <port>   -- port-knock filtered hosts\n" RST);
    if (diff & CMD_UNLOCK)     printf(MAG "      unlock <file> <code>  -- keypad-locked files\n" RST);
    if (diff & CMD_WIPE)       printf(MAG "      wipe                  -- scrub logs, lower detection\n" RST);
    if (diff & CMD_SU)         printf(MAG "      su <password>         -- root on the current host only\n" RST);
    if (diff & CMD_SU)         printf(MAG "      decrypt <file> <key>  -- [KEY] files need a key you find\n" RST);
    printf("\n");
}

/* Prints the ASCII art title banner in green. */
void print_banner(void) {
    printf(GRN);
    printf("  ████████╗███████╗██████╗ ███╗   ███╗██╗███╗   ██╗ █████╗ ██╗     \n");
    printf("     ██╔══╝██╔════╝██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗██║     \n");
    printf("     ██║   █████╗  ██████╔╝██╔████╔██║██║██╔██╗ ██║███████║██║     \n");
    printf("     ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██╔══██║██║     \n");
    printf("     ██║   ███████╗██║  ██║██║ ╚═╝ ██║██║██║ ╚████║██║  ██║███████╗\n");
    printf("     ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝\n");
    printf("  ██████╗ ██████╗ ███████╗ █████╗  ██████╗██╗  ██╗  v5.0           \n");
    printf("  ██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║                 \n");
    printf("  ██████╔╝██████╔╝█████╗  ███████║██║     ███████║                 \n");
    printf("  ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██║     ██╔══██║                 \n");
    printf("  ██████╔╝██║  ██║███████╗██║  ██║╚██████╗██║  ██║                 \n");
    printf("  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝                \n");
    printf(RST);
}

/* Runs the one-time animated startup sequence: clears the screen, scrolls
   through boot and network flavour messages, then shows the banner and a
   brief welcome prompt. The per-character delays are tuned so the sequence
   feels active without being slow enough to frustrate a returning player. */
void boot_sequence(void) {
    clear_screen();
    printf(GRN);
    slow_print("[BOOT] Initializing Terminal Breach OS v5.0...", 28);
    slow_print("[BOOT] Loading kernel modules...",               28);
    slow_print("[BOOT] Mounting encrypted partitions...",        28);
    slow_print("[NET]  Establishing anonymous connection...",    28);
    slow_print("[NET]  Routing: TOR → VPN → DARKNET",           20);
    slow_print("[SEC]  Spoofing MAC: DE:AD:BE:EF:CA:FE",         20);
    slow_print("[SEC]  Identity masked — you are GHOST.",        20);
    slow_print("[SYS]  Detection avoidance module: ACTIVE.",     20);
    slow_print("[SYS]  Command progression system: ACTIVE.",     20);
    slow_print("[SYS]  All systems operational.",                20);
    printf(RST "\n");
    print_separator();
    print_banner();
    print_separator();
    printf(YEL);
    slow_print("  Welcome, GHOST. Forty-five targets. One mission.", 22);
    slow_print("  Type 'help' to see available commands.", 22);
    printf(RST);
    print_separator();
    printf("\n");
}
