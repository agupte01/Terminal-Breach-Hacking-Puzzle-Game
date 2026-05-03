/*
 * save.c — Persist and restore game state to a plain-text save file.
 *
 * The save format is intentionally simple: one key=value pair per line,
 * easy to read in a text editor and easy to parse without any external
 * libraries. Only the fields that matter across sessions are saved — per-level
 * file state, detection, and node position are not persisted because they
 * are reset when a level starts anyway.
 */

#include "save.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Writes the current session to SAVE_FILE. The inventory is serialised as
   a count followed by one INV_n=value line per item, which makes loading
   straightforward without needing a dedicated delimiter. */
int save_game(const GameState *gs) {
    FILE *fp = fopen(SAVE_FILE, "w");
    if (!fp) return 0;

    fprintf(fp, "VERSION=2\n");
    fprintf(fp, "LEVEL=%d\n",       gs->current_level);
    fprintf(fp, "SCORE=%d\n",       gs->score);
    fprintf(fp, "TOTAL_FAILS=%d\n", gs->total_fails);
    fprintf(fp, "TOTAL_CMDS=%d\n",  gs->total_commands);
    fprintf(fp, "INV_COUNT=%d\n",   gs->inv_count);
    for (int i = 0; i < gs->inv_count; i++)
        fprintf(fp, "INV_%d=%s\n", i, gs->inventory[i]);

    fclose(fp);
    return 1;
}

/* Reads SAVE_FILE line by line and restores the fields written by save_game.
   Unknown keys are silently ignored, which means older save files remain
   loadable after new fields are added. The VERSION field is read but not
   currently acted on — it exists for forward compatibility. */
int load_game(GameState *gs) {
    FILE *fp = fopen(SAVE_FILE, "r");
    if (!fp) return 0;

    char line[512];
    int  version  = 0;
    int  inv_count = 0;

    while (fgets(line, sizeof(line), fp)) {
        /* Strip trailing newline or carriage return before comparing. */
        int len = (int)strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';

        if      (strncmp(line, "VERSION=",    8) == 0) version             = atoi(line + 8);
        else if (strncmp(line, "LEVEL=",      6) == 0) gs->current_level   = atoi(line + 6);
        else if (strncmp(line, "SCORE=",      6) == 0) gs->score           = atoi(line + 6);
        else if (strncmp(line, "TOTAL_FAILS=",12) == 0) gs->total_fails    = atoi(line + 12);
        else if (strncmp(line, "TOTAL_CMDS=", 11) == 0) gs->total_commands = atoi(line + 11);
        else if (strncmp(line, "INV_COUNT=",  10) == 0) inv_count          = atoi(line + 10);
        else if (strncmp(line, "INV_",         4) == 0) {
            char *eq = strchr(line + 4, '=');
            if (eq && inv_count > 0 && gs->inv_count < MAX_INV_ITEMS) {
                strncpy(gs->inventory[gs->inv_count], eq + 1, MAX_INV_LEN - 1);
                gs->inventory[gs->inv_count][MAX_INV_LEN - 1] = '\0';
                gs->inv_count++;
            }
        }
    }
    fclose(fp);
    (void)version;
    return 1;
}
