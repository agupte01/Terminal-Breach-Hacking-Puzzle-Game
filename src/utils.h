/*
 * utils.h — Terminal rendering and UI helpers.
 *
 * This module owns everything that outputs to the terminal but is not a
 * direct response to a player command: the animated boot sequence, the
 * mission briefing, the detection bar, the dynamic prompt string, and the
 * slow-print effect used throughout the game to simulate real-time activity.
 */

#ifndef UTILS_H
#define UTILS_H

#include "levels.h"

/* Prints 'text' one character at a time with a per-character delay of
   delay_ms milliseconds, then prints a newline. Used to give the UI a
   live, terminal-activity feel throughout the game. */
void slow_print(const char *text, int delay_ms);

/* Prints a single horizontal rule used to visually separate sections. */
void print_separator(void);

/* Clears the terminal using ANSI escape sequences. */
void clear_screen(void);

/* Prints the Terminal Breach ASCII art title banner. */
void print_banner(void);

/* Runs the animated startup sequence: boot messages, network routing
   flavour text, and the title banner. Called once at game start. */
void boot_sequence(void);

/* Builds the dynamic prompt string (e.g. ghost@10.0.0.1[user]:~$) into
   buf based on the player's current node and permission level. */
void get_prompt(GameState *gs, char *buf, int buflen);

/* Renders the detection progress bar with colour-coded fill. The bar
   turns yellow above 50% and red above 80%. */
void print_detection_bar(int detection, int max);

/* Prints the full mission briefing for a level, including objective text,
   difficulty, warnings, and timer duration if one is active. */
void print_mission_briefing(Level *l);

/* Compares two command bitmasks and announces any commands that are present
   in cur but not in prev — i.e. commands newly unlocked at this level. */
void show_new_commands(unsigned int prev_cmds, unsigned int new_cmds);

#endif
