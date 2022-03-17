.section .text

/*
 * bool aes_supported();
 * Test for the AES-NI instruction set by enumeration of CPUID
 * Specifically bit 25 of ECX, leaf 0x00000001
 */
.global aes_supported
aes_supported:
  push %rbx
  push %rcx
  push %rdx

  movq $0x1, %rax
  cpuid

  andl $33554432, %ecx
  testl %ecx, %ecx
  je unsupported
  movq $0x1, %rax
  jmp exit
unsupported:
  movq $0x0, %rax
exit:
  pop %rbx
  pop %rcx
  pop %rdx
  ret

/* Generates a new round key by combining (XOR'ing) previous bytes, along with the new key 
 * INPUTS:  xmm0 -> previos round key, xmm1 -> aeskeygenassist result, xmm2 -> first word is zero
 * OUTPUTS: xmm0 -> newly created round key, xmm2 -> first word is still zero
 */
combine_key:
    pshufd $0b11111111, %xmm1, %xmm1
    shufps $0b00010000, %xmm0, %xmm2
    pxor   %xmm2, %xmm0
    shufps $0b10001100, %xmm0, %xmm2
    pxor   %xmm2, %xmm0
    pxor   %xmm1, %xmm0
    ret

/* A simple macro to expand keys, and it takes 3 parameters, which are as follows...
 * RCON -> A round constant, for use in generating the round key
 * DEST -> destination register for the completly generated key
 * INV  -> whether to generate linear or inverse keys
 * OUTPUTS: DEST and xmm0, the latter of which contains a non-inverse round key
 */
.macro expand_key RCON DEST INV=0
    aeskeygenassist \RCON, %xmm0, %xmm1
    call combine_key
.if \INV
    aesimc %xmm0, \DEST
.else
    movaps %xmm0, \DEST
.endif
.endm

/*
 * void asm_expand_key_128(uint8_t* key, aes_128_key_t* output);
 * Expand the 128-bit AES key in 'key' and expand it into a form
 * suitable for encryption/decryption
 */
.global asm_expand_key_128
asm_expand_key_128:
  /* Load the variables and prepare to expand the keys */
  movaps (%rdi), %xmm0
  movaps (%rdi), %xmm5
  pxor %xmm2, %xmm2

  /* Generate the keys */
  expand_key $1,   %xmm6
  expand_key $2,   %xmm7
  expand_key $4,   %xmm8
  expand_key $8,   %xmm9
  expand_key $16,  %xmm10
  expand_key $32,  %xmm11
  expand_key $64,  %xmm12
  expand_key $128, %xmm13
  expand_key $27,  %xmm14
  expand_key $54,  %xmm15

  /* Store the new keys */
  movaps %xmm6,    (%rsi)
  movaps %xmm7,  16(%rsi)
  movaps %xmm8,  32(%rsi)
  movaps %xmm9,  48(%rsi)
  movaps %xmm10, 64(%rsi)
  movaps %xmm11, 80(%rsi)
  movaps %xmm12, 96(%rsi)
  movaps %xmm13, 112(%rsi)
  movaps %xmm14, 128(%rsi)
  movaps %xmm15, 144(%rsi)


  /* Reset the registers and start over (for the inverse keys) */
  movaps (%rdi), %xmm0
  movaps (%rdi), %xmm5
  pxor %xmm2, %xmm2


  /* Then generate the decoding keys and store them... */
  expand_key $1,   %xmm6,  1
  expand_key $2,   %xmm7,  1
  expand_key $4,   %xmm8,  1
  expand_key $8,   %xmm9,  1
  expand_key $16,  %xmm10, 1
  expand_key $32,  %xmm11, 1
  expand_key $64,  %xmm12, 1
  expand_key $128, %xmm13, 1
  expand_key $27,  %xmm14, 1
  expand_key $54,  %xmm15, 0 # Don't do AESIMC on the last round
  
  /* Finally, store the new (reverse) keys */
  movaps %xmm6,  160(%rsi)
  movaps %xmm7,  176(%rsi)
  movaps %xmm8,  192(%rsi)
  movaps %xmm9,  208(%rsi)
  movaps %xmm10, 224(%rsi)
  movaps %xmm11, 240(%rsi)
  movaps %xmm12, 256(%rsi)
  movaps %xmm13, 272(%rsi)
  movaps %xmm14, 288(%rsi)
  movaps %xmm15, 304(%rsi)

  ret

/*
 * void asm_encrypt_block_128(uint8_t* orig_key, aes_128_key_t* keys, void* input);
 * Encodes a single 128-bit (16-byte) block of memory, by using 'orig_key' in the first round,
 * then 'keys' in the subsequent rounds that follow.
 */
.global asm_encrypt_block_128
asm_encrypt_block_128:
    // Load the original key and block of data
    movaps (%rdx), %xmm0
    movaps (%rdi), %xmm5

    // Then load the list of round keys
    movaps (%rsi),    %xmm6
    movaps 16(%rsi),  %xmm7
    movaps 32(%rsi),  %xmm8
    movaps 48(%rsi),  %xmm9
    movaps 64(%rsi),  %xmm10
    movaps 80(%rsi),  %xmm11
    movaps 96(%rsi),  %xmm12
    movaps 112(%rsi), %xmm13
    movaps 128(%rsi), %xmm14
    movaps 144(%rsi), %xmm15

    // Encrypt the block itself
    pxor       %xmm5,   %xmm0
    aesenc     %xmm6,   %xmm0
    aesenc     %xmm7,   %xmm0
    aesenc     %xmm8,   %xmm0
    aesenc     %xmm9,   %xmm0
    aesenc     %xmm10,  %xmm0
    aesenc     %xmm11,  %xmm0
    aesenc     %xmm12,  %xmm0
    aesenc     %xmm13,  %xmm0
    aesenc     %xmm14,  %xmm0
    aesenclast %xmm15,  %xmm0
    
    // Load the encrypted block back into memory
    movaps %xmm0, (%rdx)

    ret

/*
 * void asm_decrypt_block_128(uint8_t* orig_key, aes_128_key_t* keys, void* input);
 * Decodes a single 128-bit (16-byte) block of memory, by using 'orig_key' in the first round,
 * then 'keys' in the subsequent rounds that follow.
 */
.global asm_decrypt_block_128
asm_decrypt_block_128:
    // Load the original key and block of data
    movaps (%rdx), %xmm0
    movaps (%rdi), %xmm5

    // Then load the list of round keys
    movaps 160(%rsi),  %xmm6
    movaps 176(%rsi),  %xmm7
    movaps 192(%rsi),  %xmm8
    movaps 208(%rsi),  %xmm9
    movaps 224(%rsi),  %xmm10
    movaps 240(%rsi),  %xmm11
    movaps 256(%rsi),  %xmm12
    movaps 272(%rsi),  %xmm13
    movaps 288(%rsi),  %xmm14
    movaps 304(%rsi),  %xmm15

    // Decrypt the block itself
    pxor       %xmm15, %xmm0
    aesdec     %xmm14, %xmm0
    aesdec     %xmm13, %xmm0
    aesdec     %xmm12, %xmm0
    aesdec     %xmm11, %xmm0
    aesdec     %xmm10, %xmm0
    aesdec     %xmm9,  %xmm0
    aesdec     %xmm8,  %xmm0
    aesdec     %xmm7,  %xmm0
    aesdec     %xmm6,  %xmm0
    aesdeclast %xmm5,  %xmm0

    // Load the decrypted block back into memory
    movaps %xmm0, (%rdx)

    ret

