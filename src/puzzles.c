/*
 * puzzles.c — File decryption algorithms for every puzzle type.
 *
 * Each level's encrypted files use one of these three encoding schemes.
 * The content stored in a GameFile is always the raw encoded form; these
 * functions decode it into a temporary caller-supplied buffer without
 * modifying the original struct, keeping level data immutable.
 */

#include "puzzles.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

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

/* Parses one hex digit, returning its value 0-15 or -1 on invalid input. */
static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Reads space-separated pairs of hex digits and emits the corresponding bytes.
   Stops at end of string or any malformed token. The format mirrors puzzle_binary
   so the same authoring style works for hex-encoded fragments. */
int puzzle_hex(const char *input, char *output, int outlen) {
    int out_idx = 0;
    const char *p = input;
    while (*p && out_idx < outlen - 1) {
        while (*p == ' ' || *p == '\n' || *p == '\t') p++;
        if (!*p) break;
        int hi = hexval(p[0]);
        int lo = (hi < 0) ? -1 : hexval(p[1]);
        if (lo < 0) break;
        output[out_idx++] = (char)((hi << 4) | lo);
        p += 2;
    }
    output[out_idx] = '\0';
    return out_idx;
}

/* XOR cipher: parses input as hex bytes (same format as puzzle_hex) and
   XORs each decoded byte against the corresponding byte of the key, which
   repeats. The key is treated as ASCII; an empty key passes the bytes
   through unchanged. */
int puzzle_xor(const char *input, char *output, int outlen, const char *key) {
    int len = puzzle_hex(input, output, outlen);
    int klen = key ? (int)strlen(key) : 0;
    if (klen == 0) return len;
    for (int i = 0; i < len; i++)
        output[i] = (char)((unsigned char)output[i] ^ (unsigned char)key[i % klen]);
    output[len] = '\0';
    return len;
}

/* Vigenère decode: for each alphabetic character in input, subtracts the
   corresponding letter of the key (cycling) modulo 26. Non-alphabetic
   characters are copied through. The key may be in any case. */
int puzzle_vigenere(const char *input, char *output, int outlen, const char *key) {
    int klen = key ? (int)strlen(key) : 0;
    if (klen == 0) {
        strncpy(output, input, (size_t)(outlen - 1));
        output[outlen - 1] = '\0';
        return (int)strlen(output);
    }
    int i = 0, ki = 0;
    for (; input[i] && i < outlen - 1; i++) {
        char c = input[i];
        char k = key[ki % klen];
        int  s = (k >= 'a' && k <= 'z') ? (k - 'a')
               : (k >= 'A' && k <= 'Z') ? (k - 'A') : 0;
        if (c >= 'a' && c <= 'z') {
            output[i] = (char)(((c - 'a' - s + 26) % 26) + 'a');
            ki++;
        } else if (c >= 'A' && c <= 'Z') {
            output[i] = (char)(((c - 'A' - s + 26) % 26) + 'A');
            ki++;
        } else {
            output[i] = c;
        }
    }
    output[i] = '\0';
    return i;
}

/* Decodes a base64 string. Whitespace and '=' padding are skipped. */
int puzzle_base64(const char *input, char *output, int outlen) {
    static const char *alpha =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int  out_idx = 0;
    int  buf = 0, bits = 0;
    for (const char *p = input; *p && out_idx < outlen - 1; p++) {
        if (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t' || *p == '=') continue;
        const char *q = strchr(alpha, *p);
        if (!q) break;
        buf = (buf << 6) | (int)(q - alpha);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            output[out_idx++] = (char)((buf >> bits) & 0xFF);
        }
    }
    output[out_idx] = '\0';
    return out_idx;
}

/* Atbash: mirrors each letter across the alphabet (A<->Z, B<->Y ...).
   The cipher is its own inverse. Non-letters pass through unchanged. */
int puzzle_atbash(const char *input, char *output, int outlen) {
    int i = 0;
    for (; input[i] && i < outlen - 1; i++) {
        char c = input[i];
        if (c >= 'a' && c <= 'z')      output[i] = (char)('z' - (c - 'a'));
        else if (c >= 'A' && c <= 'Z') output[i] = (char)('Z' - (c - 'A'));
        else                           output[i] = c;
    }
    output[i] = '\0';
    return i;
}

/* Rail-fence decode. The plaintext was written in a zig-zag across 'rails'
   rows and read off row by row. To invert, we recompute which rail every
   position lands on, slice the ciphertext into per-rail runs, then walk the
   zig-zag again pulling the next character from each rail in turn. */
int puzzle_rail(const char *input, char *output, int outlen, int rails) {
    int n = (int)strlen(input);
    if (n >= outlen) n = outlen - 1;
    if (rails < 2 || rails >= n) {
        memcpy(output, input, (size_t)n);
        output[n] = '\0';
        return n;
    }
    int rail_of[MAX_CONTENT];
    int counts[64] = {0};
    if (rails > 64) rails = 64;
    int r = 0, dir = 1;
    for (int i = 0; i < n; i++) {
        rail_of[i] = r;
        counts[r]++;
        if (r == 0) dir = 1; else if (r == rails - 1) dir = -1;
        r += dir;
    }
    int start[64], cursor[64];
    int acc = 0;
    for (int k = 0; k < rails; k++) { start[k] = acc; cursor[k] = 0; acc += counts[k]; }
    for (int i = 0; i < n; i++) {
        int k = rail_of[i];
        output[i] = input[start[k] + cursor[k]++];
    }
    output[n] = '\0';
    return n;
}

/* ---------------------------------------------------------------------
 * Onion files: several encodings stacked on top of each other. The layer
 * spec lives in cipher_key as '>'-separated tokens, outermost first:
 *     b64 | hex | rev | bin | atb | rail:N | caesar:N | xor:KEY | vig:KEY
 * 'decrypt' peels one layer per call, so the player watches the payload
 * change shape and has to keep going until plaintext emerges.
 * ------------------------------------------------------------------- */

/* Copies the idx-th layer token from spec into tok. Returns 1 if found. */
static int onion_token(const char *spec, int idx, char *tok, int toklen) {
    const char *p = spec;
    for (int i = 0; i < idx; i++) {
        p = strchr(p, '>');
        if (!p) return 0;
        p++;
    }
    int k = 0;
    while (*p && *p != '>' && k < toklen - 1) tok[k++] = *p++;
    tok[k] = '\0';
    return k > 0;
}

int onion_layer_count(const char *spec) {
    if (!spec || !spec[0]) return 0;
    int c = 1;
    for (const char *p = spec; *p; p++) if (*p == '>') c++;
    return c;
}

/* Human-readable name for layer idx, used in decrypt feedback. */
void onion_layer_name(const char *spec, int idx, char *out, int outlen) {
    char tok[64];
    if (!onion_token(spec, idx, tok, sizeof(tok))) { snprintf(out, (size_t)outlen, "unknown"); return; }
    const char *arg = strchr(tok, ':');
    if      (strncmp(tok, "b64", 3) == 0)    snprintf(out, (size_t)outlen, "Base64 shell");
    else if (strncmp(tok, "hex", 3) == 0)    snprintf(out, (size_t)outlen, "Hex shell");
    else if (strncmp(tok, "rev", 3) == 0)    snprintf(out, (size_t)outlen, "Reversal shell");
    else if (strncmp(tok, "bin", 3) == 0)    snprintf(out, (size_t)outlen, "Binary shell");
    else if (strncmp(tok, "atb", 3) == 0)    snprintf(out, (size_t)outlen, "Atbash shell");
    else if (strncmp(tok, "rail", 4) == 0)   snprintf(out, (size_t)outlen, "Rail-fence shell (%s rails)", arg ? arg + 1 : "?");
    else if (strncmp(tok, "caesar", 6) == 0) snprintf(out, (size_t)outlen, "Caesar shell (shift %s)", arg ? arg + 1 : "?");
    else if (strncmp(tok, "xor", 3) == 0)    snprintf(out, (size_t)outlen, "XOR shell");
    else if (strncmp(tok, "vig", 3) == 0)    snprintf(out, (size_t)outlen, "Vigenere shell");
    else snprintf(out, (size_t)outlen, "unknown");
}

/* Applies a single decode layer described by tok. */
static int onion_apply(const char *tok, const char *in, char *out, int outlen) {
    const char *arg = strchr(tok, ':');
    arg = arg ? arg + 1 : "";
    if (strncmp(tok, "b64", 3) == 0)    return puzzle_base64(in, out, outlen);
    if (strncmp(tok, "hex", 3) == 0)    return puzzle_hex(in, out, outlen);
    if (strncmp(tok, "rev", 3) == 0)    return puzzle_reverse(in, out, outlen);
    if (strncmp(tok, "bin", 3) == 0)    return puzzle_binary(in, out, outlen);
    if (strncmp(tok, "atb", 3) == 0)    return puzzle_atbash(in, out, outlen);
    if (strncmp(tok, "rail", 4) == 0)   return puzzle_rail(in, out, outlen, atoi(arg));
    if (strncmp(tok, "caesar", 6) == 0) return puzzle_caesar(in, out, outlen, atoi(arg));
    if (strncmp(tok, "xor", 3) == 0)    return puzzle_xor(in, out, outlen, arg);
    if (strncmp(tok, "vig", 3) == 0)    return puzzle_vigenere(in, out, outlen, arg);
    return 0;
}

/* Peels the first 'layers' layers off content. layers=0 copies verbatim. */
int onion_peel(const char *content, const char *spec, int layers, char *out, int outlen) {
    char a[MAX_CONTENT], b[MAX_CONTENT];
    strncpy(a, content, MAX_CONTENT - 1);
    a[MAX_CONTENT - 1] = '\0';
    int total = onion_layer_count(spec);
    if (layers > total) layers = total;
    for (int i = 0; i < layers; i++) {
        char tok[64];
        if (!onion_token(spec, i, tok, sizeof(tok))) return 0;
        if (onion_apply(tok, a, b, MAX_CONTENT) <= 0) return 0;
        memcpy(a, b, MAX_CONTENT);
    }
    strncpy(out, a, (size_t)(outlen - 1));
    out[outlen - 1] = '\0';
    return (int)strlen(out);
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
    case PUZZLE_HEX:
        return puzzle_hex(f->content, output, outlen) > 0;
    case PUZZLE_XOR:
        return puzzle_xor(f->content, output, outlen, f->cipher_key) > 0;
    case PUZZLE_VIGENERE:
        return puzzle_vigenere(f->content, output, outlen, f->cipher_key) > 0;
    case PUZZLE_BASE64:
        return puzzle_base64(f->content, output, outlen) > 0;
    case PUZZLE_ATBASH:
        return puzzle_atbash(f->content, output, outlen) > 0;
    case PUZZLE_RAIL:
        return puzzle_rail(f->content, output, outlen, f->cipher_shift) > 0;
    case PUZZLE_ONION:
        return onion_peel(f->content, f->cipher_key,
                          onion_layer_count(f->cipher_key), output, outlen) > 0;
    default:
        strncpy(output, f->content, (size_t)(outlen - 1));
        output[outlen - 1] = '\0';
        return 1;
    }
}
