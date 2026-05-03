/*
 * save.h — Save and load game state to disk.
 *
 * Progress is persisted to a plain-text key=value file so it is human-readable
 * and easy to inspect. The save includes the current level, cumulative score,
 * fail and command counts, and the full inventory. On load, the game loop
 * detects the level change and executes a level transition to restore context.
 */

#ifndef SAVE_H
#define SAVE_H

#include "levels.h"

#define SAVE_FILE "terminal_breach.sav"

/* Writes the current session state to SAVE_FILE.
   Returns 1 on success, 0 if the file could not be opened for writing. */
int save_game(const GameState *gs);

/* Reads SAVE_FILE and restores level, score, fail count, command count,
   and inventory into gs. Returns 1 on success, 0 if the file is absent. */
int load_game(GameState *gs);

#endif
