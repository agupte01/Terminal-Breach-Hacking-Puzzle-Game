/*
 * puzzles.c — File decryption algorithms for the three puzzle types.
 *
 * Each level's encrypted files use one of these three encoding schemes.
 * The content stored in a GameFile is always the raw encoded form; these
 * functions decode it into a temporary caller-supplied buffer without
 * modifying the original struct, keeping level data immutable.
 */

#include "puzzles.h"
#include <string.h>
#include <stdio.h>

/* Reverses a Caesar cipher by subtracting the shift from each alphabetic
   character modulo 26. The modular arithmetic handles wrap-around correctly
   for any shift value from 1 to 25. Non-alphabetic characters — digits,
   underscores, special characters — are copied unchanged, which preserves
   the format of passwords that mix letters with symbols and numbers. */
int puzzle_caesar(const char *input, char *output, int outlen, int shift) {
    int i = 0;
    for (; input[i] && i < outlen - 1; i++) {
        char c = input[i];
        if (c >= 'a' && c <= 'z')
            output[i] = (char)(((c - 'a' - shift % 26 + 26) % 26) + 'a');
        else if (c >= 'A' && c <= 'Z')
            output[i] = (char)(((c - 'A' - shift % 26 + 26) % 26) + 'A');
        else
            output[i] = c;
    }
    output[i] = '\0';
    return i;
}

/* Reverses the input string in place within the output buffer. This is the
   simplest puzzle type and is used early in the game to introduce the decrypt
   command before more complex encoding schemes appear. */
int puzzle_reverse(const char *input, char *output, int outlen) {
    int len = (int)strlen(input);
    if (len >= outlen) len = outlen - 1;
    for (int i = 0; i < len; i++)
        output[i] = input[len - 1 - i];
    output[len] = '\0';
    return len;
}

/* Converts a string of space-separated 8-bit binary tokens to ASCII text.
   Each token must be exactly 8 binary digits followed by a space or end of
   string. Parsing stops early at a newline or '[', which allows the content
   field to include trailing comments without interfering with decoding. */
int puzzle_binary(const char *input, char *output, int outlen) {
    int   out_idx = 0;
    const char *p = input;

    while (*p && out_idx < outlen - 1) {
        while (*p == ' ') p++;
        if (!*p || *p == '\n' || *p == '[') break;

        /* Require exactly 8 binary digits, then a delimiter. */
        int j;
        for (j = 0; j < 8; j++) {
            if (p[j] != '0' && p[j] != '1') goto done;
        }
        if (p[8] != ' ' && p[8] != '\0' && p[8] != '\n') goto done;

        int val = 0;
        for (j = 0; j < 8; j++)
            val = (val << 1) | (p[j] - '0');
        output[out_idx++] = (char)val;
        p += 8;
    }
done:
    output[out_idx] = '\0';
    return out_idx;
}

/* Selects and runs the appropriate decoder based on the file's puzzle_type.
   Returns 1 if decoding succeeded, 0 if the type is unrecognised. For plain
   files (PUZZLE_NONE) the content is copied verbatim, which allows the same
   code path to be used whether or not a file is encrypted. */
int decode_content(const GameFile *f, char *output, int outlen) {
    switch (f->puzzle_type) {
    case PUZZLE_CAESAR:
        return puzzle_caesar(f->content, output, outlen, f->cipher_shift) > 0;
    case PUZZLE_REVERSE:
        return puzzle_reverse(f->content, output, outlen) > 0;
    case PUZZLE_BINARY:
        return puzzle_binary(f->content, output, outlen) > 0;
    default:
        strncpy(output, f->content, (size_t)(outlen - 1));
        output[outlen - 1] = '\0';
        return 1;
    }
}
