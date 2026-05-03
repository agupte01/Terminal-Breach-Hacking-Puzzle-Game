/*
 * puzzles.h — Public API for the three file decryption algorithms.
 *
 * All encrypted files in the game use one of three encoding schemes. The
 * decode_content dispatcher selects the right algorithm based on a file's
 * puzzle_type field and writes the decoded result into a caller-supplied
 * buffer. The individual functions are also exposed so they can be tested
 * independently if needed.
 */

#ifndef PUZZLES_H
#define PUZZLES_H

#include "levels.h"

/* Dispatches to the correct decoder based on f->puzzle_type and writes the
   decoded text into output (which must be at least outlen bytes).
   Returns 1 on success, 0 if the puzzle type is unrecognised. */
int decode_content(const GameFile *f, char *output, int outlen);

/* Reverses the Caesar shift by subtracting 'shift' positions from each
   alphabetic character modulo 26. Non-alpha characters are copied verbatim.
   Returns the number of characters written. */
int puzzle_caesar(const char *input, char *output, int outlen, int shift);

/* Reverses the input string character by character.
   Returns the length of the reversed string. */
int puzzle_reverse(const char *input, char *output, int outlen);

/* Converts space-separated 8-bit binary tokens to their ASCII characters.
   Parsing stops at a newline or '['. Returns the number of characters written. */
int puzzle_binary(const char *input, char *output, int outlen);

#endif
