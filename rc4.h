
/* 
 * @file   rc4.h
 * @author EHN Group 
 * @brief RC4 Algorithm
 * Created on May 11, 2017, 5:11 PM
 */

#ifndef RC4_H
#define RC4_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/**
 * @brief Rc4 Context structure used to store RC4 context and indexes which will determine the state value to be used.
 *
 */

typedef struct {

  uint8_t index_1;
  uint8_t index_2;
  uint8_t S[256];

}rc4ctx_t;


void rc4_init(rc4ctx_t* rc4c, unsigned char* key, int keylen);
unsigned char rc4_getbyte(rc4ctx_t* rc4c);
void swap(rc4ctx_t* rc4c, uint8_t i, uint8_t j);
void encrypt_decrypt(FILE * text_input, FILE * text_output, rc4ctx_t * rc4c);

#endif /* RC4_H */

