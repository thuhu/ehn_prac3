
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
 * @param index_1 
 * @param index_2
 * @param S A 256-byte state vector.
 */

typedef struct {

  uint8_t index_1;
  uint8_t index_2;
  uint8_t S[256];

}rc4ctx_t;

/** @brief RC4_init initalises the rc4 context structure.
 * 
 * @param rc4c A pointer to rc4 context structure that have to be initialised.
 * @param key The variable length key provided to encrypt or decrypt a file. 
 * @param keylen The length of the key string.
 */
void rc4_init(rc4ctx_t* rc4c, unsigned char* key, int keylen);




/** @brief Get the next byte in the RC4 state vector S to generate the stream. 
 * 
 * @param rc4c A pointer to RC4 context structure which contains the state vector.
 * @return The next byte.
 */
unsigned char rc4_getbyte(rc4ctx_t* rc4c);


/**
 * 
 * @param rc4c A pointer to rc4 context structure.
 * @param i First index of the byte to be swapped.
 * @param j Second index of the byte to be swapped.
 */
void swap(rc4ctx_t* rc4c, uint8_t i, uint8_t j);



/**@brief Encrypt or decrypt a file and write the encrypted or decrypted file.
 * 
 * @param text_input Input file where data will be read from.
 * @param text_output Output file where data will be written to.
 * @param rc4c A pointer to rc4 context structure.
 */
void encrypt_decrypt(FILE * text_input, FILE * text_output, rc4ctx_t * rc4c);

#endif /* RC4_H */

