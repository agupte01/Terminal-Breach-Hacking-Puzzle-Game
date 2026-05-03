/*
 * network.h — Node navigation and file-state helpers.
 *
 * This module provides the low-level operations that commands.c builds on:
 * looking up nodes and files by name, and reading or writing the per-file
 * unlock and decrypt bitmasks stored in GameState. Keeping this logic here
 * avoids scattering bitmask arithmetic across the command handlers.
 */

#ifndef NETWORK_H
#define NETWORK_H

#include "levels.h"

/* Returns a pointer to the node the player is currently connected to. */
NetworkNode *get_current_node(GameState *gs);

/* Searches a node's file list for a file with the given name.
   Returns the index on success, or -1 if not found. */
int find_file_index(NetworkNode *n, const char *name);

/* Returns 1 if the specified file's lock condition has been satisfied
   this session (e.g. after bruteforce or a connect side-effect). */
int is_file_unlocked(GameState *gs, int node_idx, int file_idx);

/* Sets the unlock bit for the specified file, making it accessible. */
void unlock_file_bit(GameState *gs, int node_idx, int file_idx);

/* Returns 1 if the player has already decoded this file during the
   current session, so subsequent 'cat' calls show the plaintext. */
int is_file_decrypted(GameState *gs, int node_idx, int file_idx);

/* Records that a file has been successfully decrypted this session. */
void set_decrypted(GameState *gs, int node_idx, int file_idx);

/* Searches all nodes in a level for one matching the given IP address or
   hostname. Returns the node index, or -1 if no match is found. */
int find_node_by_target(Level *l, const char *target);

#endif
