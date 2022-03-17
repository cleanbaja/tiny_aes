#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tiny_aes.h"

__attribute__((weak)) bool aes_supported() {
  return false;
}

static void print_128(uint8_t* data) {
  for (int i = 0; i < 8; i++) {
    printf("%x", data[i]);
  }
 
  printf("-");

  for (int i = 8; i < 16; i++) {
    printf("%x", data[i]);
  }
}

int main(int argc, char** argv) {
  if (aes_supported()) {
    puts("[INFO] CPU-based AES acceleration is supported!");
  } else {
    puts("[ERROR] CPU-based AES acceleration is unsupported!");
  }

  // Setup and print the key
  uint8_t key[16] = {
    0x0A, 0xDE, 0x29, 0x12, 0x3B, 0xF3, 0x43, 0x91,
    0x80, 0xFE, 0xAD, 0xBC, 0x0F, 0x75, 0xD4, 0x29
  };
  printf("[INFO] Current Key:\n\t");
  print_128(key);
  putc('\n', stdout);

  // Generate the round keys
  struct aes_context* ctx = aes_create(key);

  // Encrypt the data
  uint8_t* data = (uint8_t*)strdup("This is a demo!");

  printf("[INFO] Data Before Encryption: ");
  print_128(data);
  putc('\n', stdout);
  aes_encrypt_block(ctx, data);
  
  printf("[INFO] Data After Encryption: ");
  print_128(data);
  putc('\n', stdout);

  aes_decrypt_block(ctx, data);
  printf("[INFO] Data After Decryption: ");
  print_128(data);
  putc('\n', stdout);
}
