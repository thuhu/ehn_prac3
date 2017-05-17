#ifndef	_DEFINES_H
#define _DEFINES_H


#include <stdio.h>
#include <gmp.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// Context for rsa
typedef struct {
	mpz_t e; // User generated public key
	mpz_t d; // User generated private key
	mpz_t p;
	mpz_t q;
	mpz_t n;
	mpz_t phi;
}rsactx_t;

typedef enum{
	RSA_SUCCESS,
	RSA_INVERT_FAILED,	
	RSA_FILE_ERROR,

	RSA_KEY_ENCRYPT_ERROR,
	RSA_KEY_ENCRYPT_SUCCESS
}RSA_CODE;


void rsa_init(rsactx_t * rsactx){
	// Initialise contex
	mpz_init(rsactx->e);
	mpz_init(rsactx->d);
	mpz_init(rsactx->p);
	mpz_init(rsactx->q);
	mpz_init(rsactx->n);
	mpz_init(rsactx->phi);

	mpz_set_ui(rsactx->e, 0);
	mpz_set_ui(rsactx->d, 0);
	mpz_set_ui(rsactx->p, 0);
	mpz_set_ui(rsactx->q, 0);
	mpz_set_ui(rsactx->n, 0);	
	mpz_set_ui(rsactx->phi, 0);	

}
void rsa_clean(rsactx_t * rsactx){
	// Clean up contex to prevent memory leaks
	mpz_clear(rsactx->e);
	mpz_clear(rsactx->d);
	mpz_clear(rsactx->p);
	mpz_clear(rsactx->q);
	mpz_clear(rsactx->n);
	mpz_clear(rsactx->phi);
}

#endif