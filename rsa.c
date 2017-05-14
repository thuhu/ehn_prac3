#include <stdio.h>
#include <gmp.h>
#include <stdint.h>

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
	RSA_FILE_ERROR
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
int rsakeygen(char * public_key_filename,
				char * private_key_filename,
				char * num_p,
				char * num_q,
				mpz_t key,				
				mpz_t bits
	){
	// Open the files
	FILE  * public_key_fp, *private_key_fp;
	rsactx_t rsactx;
	mpz_t var1;
	mpz_t var2;


	public_key_fp = fopen(public_key_filename, "wb");
	private_key_fp = fopen(private_key_filename, "wb");

	if (!public_key_fp){
		printf( "Couldn't open file \"%s\"\n", public_key_filename);
		return RSA_FILE_ERROR;
	}	
	if (!private_key_fp){
		printf( "Couldn't open file \"%s\"\n", private_key_filename);
		return RSA_FILE_ERROR;
	}		
	// initialize context
	rsa_init(&rsactx);
	mpz_set_ui(rsactx.e,  65537);
	mpz_init(var1);
	mpz_init(var2);

	mpz_set_str(rsactx.p, num_p, 10);
	mpz_set_str(rsactx.q, num_q, 10);

	// Compute n
  	mpz_mul(rsactx.n, rsactx.p, rsactx.q);

	// Calculate our phi
	// (p - 1) x (q -1)
	mpz_sub_ui(var1, rsactx.p, 1);
	mpz_sub_ui(var2, rsactx.q, 1);
	mpz_mul(rsactx.phi, var1, var2);

	// Calculate d
	if (mpz_invert(rsactx.d, rsactx.e, rsactx.phi) == 0){
		return RSA_INVERT_FAILED;
	}
	// mpz_out_str(stdout, 10, rsactx.d);

	// Write keys to files	
	mpz_out_str(private_key_fp, 10, rsactx.n);	
	fprintf(private_key_fp,"\n");
	mpz_out_str(private_key_fp, 10, rsactx.d);	
	fprintf(private_key_fp,"\n");
	mpz_out_str(public_key_fp, 10, rsactx.n);
	fprintf(public_key_fp,"\n");
	mpz_out_str(public_key_fp, 10, rsactx.e);	
	fprintf(public_key_fp,"\n");

	// Clean up
	rsa_clean(&rsactx);
	fclose(public_key_fp);
	fclose(private_key_fp);
	return RSA_SUCCESS;
}

int main(int argc, char ** argv ){
	mpz_t key;
	mpz_t bits;

	rsakeygen(argv[1], argv[2],
				"12622624516681506749",
				"10325958134448386513",
	 key, bits);
	return 0;
}

