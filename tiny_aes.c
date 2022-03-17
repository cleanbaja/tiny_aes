#include "tiny_aes.h"
#include <stdio.h>
#include <stdlib.h>

/*-
 * MIT License
 *
 * Copyright (c) 2022 cleanbaja
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifdef CPU_BASED_ACCELERATION
#define ASM_STUB_CALL(func, ...) func(__VA_ARGS__)
#else
#define ASM_STUB_CALL(func, ...)
#endif

// S-box transformation table
extern uint8_t s_box[];
extern uint8_t inv_s_box[];

// AES-128 EBC constants...
#define NUM_COLUMNS 4
#define NUM_ROUNDS 10
#define KEY_SIZE 4

// Defines the mode for encrypting
enum {
  AES_ENCODING_MODE_INVALID,  // Invalid, means that mode is not yet determined
  AES_ENCODING_MODE_SW,  // Software, encrypting is completly done in software,
                         // with no specialized CPU instructions
  AES_ENCODING_MODE_HW   // Hardware, encrypting is done primarily with
                         // specialized CPU instructions/assembly
} encoding_mode;

/*
 * GF(2^8) Multiplication
 * Powered by a lookup table in tables.c, might be a actual function in the
 * future
 */
#define gmult(a, b) gmult_swap_table[256 * a + b]
extern uint8_t gmult_swap_table[];

static void determine_mode() {
#ifndef CPU_BASED_ACCELERATION
  encoding_mode = AES_ENCODING_MODE_SW;
#else
  if (aes_supported) {
    encoding_mode = AES_ENCODING_MODE_HW;
  } else {
    encoding_mode = AES_ENCODING_MODE_SW;
  }
#endif
}

// Adds 4 bytes (1 word) together
static void add_coefficent(uint8_t a[], uint8_t b[], uint8_t d[]) {
  d[0] = a[0] ^ b[0];
  d[1] = a[1] ^ b[1];
  d[2] = a[2] ^ b[2];
  d[3] = a[3] ^ b[3];
}

static void subtract_bytes(uint8_t* state) {
  uint8_t i, j;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < NUM_COLUMNS; j++) {
      state[NUM_COLUMNS * i + j] = s_box[state[NUM_COLUMNS * i + j]];
    }
  }
}

void inverse_subtract(uint8_t* state) {
  uint8_t i, j;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < NUM_COLUMNS; j++) {
      state[NUM_COLUMNS * i + j] = inv_s_box[state[NUM_COLUMNS * i + j]];
    }
  }
}

static void shift_rows(uint8_t* state) {
  uint8_t i, k, s, tmp;

  for (i = 1; i < 4; i++) {
    s = 0;
    while (s < i) {
      tmp = state[NUM_COLUMNS * i + 0];

      for (k = 1; k < NUM_COLUMNS; k++) {
        state[NUM_COLUMNS * i + k - 1] = state[NUM_COLUMNS * i + k];
      }

      state[NUM_COLUMNS * i + NUM_COLUMNS - 1] = tmp;
      s++;
    }
  }
}

static void inverse_shift(uint8_t* state) {
  uint8_t i, k, s, tmp;

  for (i = 1; i < 4; i++) {
    s = 0;
    while (s < i) {
      tmp = state[NUM_COLUMNS * i + NUM_COLUMNS - 1];

      for (k = NUM_COLUMNS - 1; k > 0; k--) {
        state[NUM_COLUMNS * i + k] = state[NUM_COLUMNS * i + k - 1];
      }

      state[NUM_COLUMNS * i + 0] = tmp;
      s++;
    }
  }
}

// Applies s_box to a single word
void subtract_word(uint8_t* w) {
  uint8_t i;

  for (i = 0; i < 4; i++) {
    w[i] = s_box[w[i]];
  }
}

// Rotates a single word (cyclic permutation)
void rotate_word(uint8_t* w) {
  uint8_t tmp;
  uint8_t i;
  tmp = w[0];

  for (i = 0; i < 3; i++) {
    w[i] = w[i + 1];
  }
  w[3] = tmp;
}

// Generates the constant R
uint8_t R[] = {0x02, 0x00, 0x00, 0x00};
static uint8_t* RCON(uint8_t i) {
  if (i == 1) {
    R[0] = 0x01;
  } else if (i > 1) {
    R[0] = 0x02;
    i--;
    while (i > 1) {
      R[0] = gmult(R[0], 0x02);
      i--;
    }
  }

  return R;
}

// Multiplies 4 byte words
void multiply_coefficent(uint8_t* a, uint8_t* b, uint8_t* d) {
  d[0] = gmult(a[0], b[0]) ^ gmult(a[3], b[1]) ^ gmult(a[2], b[2]) ^
         gmult(a[1], b[3]);
  d[1] = gmult(a[1], b[0]) ^ gmult(a[0], b[1]) ^ gmult(a[3], b[2]) ^
         gmult(a[2], b[3]);
  d[2] = gmult(a[2], b[0]) ^ gmult(a[1], b[1]) ^ gmult(a[0], b[2]) ^
         gmult(a[3], b[3]);
  d[3] = gmult(a[3], b[0]) ^ gmult(a[2], b[1]) ^ gmult(a[1], b[2]) ^
         gmult(a[0], b[3]);
}

void merge_key(uint8_t* state, uint8_t* w, uint8_t r) {
  uint8_t c;

  for (c = 0; c < NUM_COLUMNS; c++) {
    state[NUM_COLUMNS * 0 + c] =
        state[NUM_COLUMNS * 0 + c] ^ w[4 * NUM_COLUMNS * r + 4 * c + 0];
    state[NUM_COLUMNS * 1 + c] =
        state[NUM_COLUMNS * 1 + c] ^ w[4 * NUM_COLUMNS * r + 4 * c + 1];
    state[NUM_COLUMNS * 2 + c] =
        state[NUM_COLUMNS * 2 + c] ^ w[4 * NUM_COLUMNS * r + 4 * c + 2];
    state[NUM_COLUMNS * 3 + c] =
        state[NUM_COLUMNS * 3 + c] ^ w[4 * NUM_COLUMNS * r + 4 * c + 3];
  }
}

static void mix_columns(uint8_t* state) {
  uint8_t a[] = {0x02, 0x01, 0x01, 0x03};
  uint8_t i, j, col[4], res[4];

  for (j = 0; j < NUM_COLUMNS; j++) {
    for (i = 0; i < 4; i++) {
      col[i] = state[NUM_COLUMNS * i + j];
    }

    multiply_coefficent(a, col, res);

    for (i = 0; i < 4; i++) {
      state[NUM_COLUMNS * i + j] = res[i];
    }
  }
}

static void inverse_mix(uint8_t* state) {
  uint8_t a[] = {0x0e, 0x09, 0x0d,
                 0x0b};  // a(x) = {0e} + {09}x + {0d}x2 + {0b}x3
  uint8_t i, j, col[4], res[4];

  for (j = 0; j < NUM_COLUMNS; j++) {
    for (i = 0; i < 4; i++) {
      col[i] = state[NUM_COLUMNS * i + j];
    }

    multiply_coefficent(a, col, res);

    for (i = 0; i < 4; i++) {
      state[NUM_COLUMNS * i + j] = res[i];
    }
  }
}

// Expands a 16-bit AES key into 20 round keys...
static void sw_expand_keys(struct aes_context* ctx, uint8_t* key) {
  uint8_t tmp[4];
  uint8_t i;
  uint8_t len = NUM_COLUMNS * (NUM_ROUNDS + 1);
  char* key_ptr = (char*)ctx->round_keys;

  // Initial merge
  for (i = 0; i < KEY_SIZE; i++) {
    key_ptr[4 * i + 0] = key[4 * i + 0];
    key_ptr[4 * i + 1] = key[4 * i + 1];
    key_ptr[4 * i + 2] = key[4 * i + 2];
    key_ptr[4 * i + 3] = key[4 * i + 3];
  }

  for (i = KEY_SIZE; i < len; i++) {
    tmp[0] = key_ptr[4 * (i - 1) + 0];
    tmp[1] = key_ptr[4 * (i - 1) + 1];
    tmp[2] = key_ptr[4 * (i - 1) + 2];
    tmp[3] = key_ptr[4 * (i - 1) + 3];

    if (i % KEY_SIZE == 0) {
      rotate_word(tmp);
      subtract_word(tmp);
      add_coefficent(tmp, RCON(i / KEY_SIZE), tmp);
    } else if (KEY_SIZE > 6 && i % KEY_SIZE == 4) {
      subtract_word(tmp);
    }

    key_ptr[4 * i + 0] = key_ptr[4 * (i - KEY_SIZE) + 0] ^ tmp[0];
    key_ptr[4 * i + 1] = key_ptr[4 * (i - KEY_SIZE) + 1] ^ tmp[1];
    key_ptr[4 * i + 2] = key_ptr[4 * (i - KEY_SIZE) + 2] ^ tmp[2];
    key_ptr[4 * i + 3] = key_ptr[4 * (i - KEY_SIZE) + 3] ^ tmp[3];
  }
}

static void sw_encrypt_block(struct aes_context* ctx, void* d) {
  uint8_t state[4 * KEY_SIZE];
  uint8_t r, i, j;
  uint8_t* data = (uint8_t*)d;
  uint8_t* w = (uint8_t*)ctx->round_keys;

  // Read in the data...
  for (i = 0; i < 4; i++) {
    for (j = 0; j < KEY_SIZE; j++) {
      state[KEY_SIZE * i + j] = data[i + 4 * j];
    }
  }

  // Merge the first key (original key), before merging the rest (round keys)
  merge_key(state, w, 0);
  for (r = 1; r < NUM_ROUNDS; r++) {
    subtract_bytes(state);
    shift_rows(state);
    mix_columns(state);
    merge_key(state, w, r);
  }

  // Perform the final encrypting round
  subtract_bytes(state);
  shift_rows(state);
  merge_key(state, w, NUM_ROUNDS);

  // Copy the output
  for (i = 0; i < 4; i++) {
    for (j = 0; j < KEY_SIZE; j++) {
      data[i + 4 * j] = state[KEY_SIZE * i + j];
    }
  }
}

void sw_decrypt_block(struct aes_context* ctx, void* d) {
  uint8_t state[4 * NUM_COLUMNS];
  uint8_t r, i, j;
  uint8_t* data = (uint8_t*)d;
  uint8_t* w = (uint8_t*)ctx->round_keys;

  // Load in the input data
  for (i = 0; i < 4; i++) {
    for (j = 0; j < NUM_COLUMNS; j++) {
      state[NUM_COLUMNS * i + j] = data[i + 4 * j];
    }
  }

  // Preform the first inverse round, then subsequent ones...
  merge_key(state, w, NUM_ROUNDS);
  for (r = NUM_ROUNDS - 1; r >= 1; r--) {
    inverse_shift(state);
    inverse_subtract(state);
    merge_key(state, w, r);
    inverse_mix(state);
  }

  // Preform the final inverse round
  inverse_shift(state);
  inverse_subtract(state);
  merge_key(state, w, 0);

  // Store the input
  for (i = 0; i < 4; i++) {
    for (j = 0; j < NUM_COLUMNS; j++) {
      data[i + 4 * j] = state[NUM_COLUMNS * i + j];
    }
  }
}

struct aes_context* aes_create(uint8_t* key) {
  // No key, no context!
  if (key == NULL)
    return NULL;

  // Create the context, and determine how we will generate the keys.
  struct aes_context* c = malloc(sizeof(struct aes_context));
  if (c == NULL)
    return NULL;
  if (encoding_mode == AES_ENCODING_MODE_INVALID)
    determine_mode();

  // Expand the keys
  if (encoding_mode == AES_ENCODING_MODE_SW) {
    c->round_keys =
        (aes_128_key_t*)malloc(11 * 16);  // 11 round keys of 16-bytes each
    sw_expand_keys(c, key);
  } else {
    c->round_keys =
        (aes_128_key_t*)malloc(20 * 16);  // 20 round keys of 16-bytes each
    c->key = key;

    // Assume hardware-based encoding...
    ASM_STUB_CALL(asm_expand_key_128, key, c->round_keys);
  }

  return c;
}

void aes_encrypt_block(struct aes_context* ctx, void* data) {
  if (encoding_mode == AES_ENCODING_MODE_SW) {
    sw_encrypt_block(ctx, data);
  } else {
    ASM_STUB_CALL(asm_encrypt_block_128, ctx->key, ctx->round_keys, data);
  }
}

void aes_decrypt_block(struct aes_context* ctx, void* data) {
  if (encoding_mode == AES_ENCODING_MODE_SW) {
    sw_decrypt_block(ctx, data);
  } else {
    ASM_STUB_CALL(asm_decrypt_block_128, ctx->key, ctx->round_keys, data);
  }
}
