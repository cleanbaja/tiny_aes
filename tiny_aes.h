#ifndef TINY_AES_H
#define TINY_AES_H

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

#include <stdbool.h>
#include <stdint.h>

typedef uint8_t aes_128_key_t[16];

struct aes_context {
  aes_128_key_t* round_keys;
  uint8_t* key;
};

#ifdef CPU_BASED_ACCELERATION
extern bool aes_supported();  // Tests for AES support (via CPUID or some kind
                              // of CPU mechanism)

extern void asm_expand_key_128(uint8_t* key, aes_128_key_t* output);
extern void asm_encrypt_block_128(
    uint8_t* orig_key,
    aes_128_key_t* keys,
    void* input);  // Input must a pointer to a 16-byte memory block
extern void asm_decrypt_block_128(uint8_t* orig_key,
                                  aes_128_key_t* keys,
                                  void* input);  // Same here
#endif

struct aes_context* aes_create(
    uint8_t* key);  // Creates a context for operations with the provided key
void aes_encrypt_block(struct aes_context* ctx,
                       void* data);  // Encodes one 128-bit block of data
void aes_decrypt_block(struct aes_context* ctx,
                       void* data);  // Decodes one 128-bit block of data

#endif  // TINY_AES_H
