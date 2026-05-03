/*
 * network.c — Node navigation and file-state helpers.
 *
 * This module provides the building blocks that commands.c uses to navigate
 * the network topology and track per-file state. File unlock and decrypt
 * state is stored as bitmasks in GameState rather than in the Level structs,
 * which keeps all level data constant after initialisation and makes level
 * resets trivial — just zero out the relevant GameState fields.
 */

#include "network.h"
#include "levels.h"
#include <string.h>

/* Returns a pointer to the NetworkNode the player is currently connected to,
   looked up by the current_level and current_node indices in GameState. */
NetworkNode *get_current_node(GameState *gs) {
    Level *l = get_level(gs->current_level);
    return &l->nodes[gs->current_node];
}

/* Linear search through a node's file list for a file with the given name.
   File counts are small (at most MAX_FILES = 12), so linear search is fine. */
int find_file_index(NetworkNode *n, const char *name) {
    for (int i = 0; i < n->file_count; i++)
        if (strcmp(n->files[i].name, name) == 0)
            return i;
    return -1;
}

/* Checks whether file file_idx on node node_idx has had its lock cleared.
   Bounds-checks both indices before testing the bit to avoid undefined
   behaviour if a caller passes a stale index. */
int is_file_unlocked(GameState *gs, int node_idx, int file_idx) {
    if (node_idx < 0 || node_idx >= MAX_NODES) return 0;
    if (file_idx < 0 || file_idx >= MAX_FILES)  return 0;
    return (gs->node_files_unlocked[node_idx] >> file_idx) & 1;
}

/* Sets the unlock bit for the specified file. Subsequent calls to
   is_file_unlocked for the same file return 1 until the level resets. */
void unlock_file_bit(GameState *gs, int node_idx, int file_idx) {
    if (node_idx < 0 || node_idx >= MAX_NODES) return;
    if (file_idx < 0 || file_idx >= MAX_FILES)  return;
    gs->node_files_unlocked[node_idx] |= (1 << file_idx);
}

/* Returns 1 if the player has already successfully decoded this file during
   the current session. Once set, 'cat' on the same file will show the decoded
   content directly rather than prompting the player to run decrypt again. */
int is_file_decrypted(GameState *gs, int node_idx, int file_idx) {
    if (node_idx < 0 || node_idx >= MAX_NODES) return 0;
    if (file_idx < 0 || file_idx >= MAX_FILES)  return 0;
    return (gs->node_files_decrypted[node_idx] >> file_idx) & 1;
}

/* Records that the player has decoded this file. The decoded content is
   not stored — it is re-derived from the immutable file content each time
   the player reads it after this flag is set. */
void set_decrypted(GameState *gs, int node_idx, int file_idx) {
    if (node_idx < 0 || node_idx >= MAX_NODES) return;
    if (file_idx < 0 || file_idx >= MAX_FILES)  return;
    gs->node_files_decrypted[node_idx] |= (1 << file_idx);
}

/* Searches all nodes in a level for one whose IP address or hostname matches
   the given target string. Accepts either form so the player can type either
   the numeric IP or the human-readable hostname in a 'connect' command. */
int find_node_by_target(Level *l, const char *target) {
    for (int i = 0; i < l->node_count; i++) {
        if (strcmp(l->nodes[i].ip,       target) == 0) return i;
        if (strcmp(l->nodes[i].hostname, target) == 0) return i;
    }
    return -1;
}
