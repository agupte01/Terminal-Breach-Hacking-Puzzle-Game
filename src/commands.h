/*
 * commands.h — Public API for all player command handlers.
 *
 * Each function here corresponds to one command the player can type at the
 * prompt. They all take a GameState pointer so they can read and update the
 * current session. The process_command dispatcher is the single entry point
 * from the main loop; it tokenises raw input, validates the command against
 * the active level's bitmask, and routes to the appropriate handler.
 */

#ifndef COMMANDS_H
#define COMMANDS_H

#include "levels.h"

void cmd_help(GameState *gs);
void cmd_ls(GameState *gs, const char *flags);
void cmd_cat(GameState *gs, const char *filename);
void cmd_clear(void);
void cmd_whoami(GameState *gs);
void cmd_status(GameState *gs);
void cmd_hint(GameState *gs);
void cmd_login(GameState *gs, const char *password);
void cmd_logout(GameState *gs);
void cmd_decrypt(GameState *gs, const char *filename);
void cmd_save_item(GameState *gs, const char *data);
void cmd_inventory(GameState *gs);
void cmd_scan(GameState *gs);
void cmd_connect(GameState *gs, const char *target);
void cmd_bruteforce(GameState *gs);
void cmd_override(GameState *gs);
void cmd_savegame(GameState *gs);
void cmd_loadgame(GameState *gs);

/* Parses a raw input line, checks availability, and dispatches to the
   handler above that matches. Returns immediately on timer expiry. */
void process_command(GameState *gs, char *input);

#endif
