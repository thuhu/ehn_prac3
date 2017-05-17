#include "defines.h"

int rsakeygen(char * public_key_filename, char * private_key_filename, char * num_p, char * num_q, mpz_t key, mpz_t bits){
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
  	printf ("P :   "), mpz_out_str(stdout, 16, rsactx.p); putchar('\n');
  	printf ("Q :   "), mpz_out_str(stdout, 16, rsactx.q); putchar('\n');

	// Compute n
  	mpz_mul(rsactx.n, rsactx.p, rsactx.q);
  	printf ("N :   "), mpz_out_str(stdout, 16, rsactx.n); putchar('\n');

	// Calculate our phi
	// (p - 1) x (q -1)
	mpz_sub_ui(var1, rsactx.p, 1);
	mpz_sub_ui(var2, rsactx.q, 1);
	mpz_mul(rsactx.phi, var1, var2);
	printf ("Phi : "), mpz_out_str(stdout, 16, rsactx.phi); putchar('\n');

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
int get_cmd_arg(char * src, int argc, char ** argv, char * tag){
	for (int i = 0; i < argc; i++){
		if (!strcmp(argv[i], tag)){
			if (!(i + 1 > argc)){
				strcpy(src, argv[i + 1]);
				return 1;
			}
		}
	}
	return 0;
}
void usage(void){
	printf("Usage:\n\trsaencrypt -key key -fo outputfile -KU public_key_file\n");
}
int main(int argc, char ** argv ){
	mpz_t key;
	mpz_t bits;
	// char user_rc4_key[20] = {0};
	// char user_rc4_hex_key [256] = {0};
	// char tmp[100] = {0};
	// char output_filename[100];
	// char input_filename[100];
	char public_key_filename[100];
	char private_key_filename[100];
	// FILE * user_key_fp;

	if (!get_cmd_arg(public_key_filename, argc, argv, "-KU")){
		usage();
		return 2;
	}
	if (!get_cmd_arg(private_key_filename, argc, argv, "-KR")){
		usage();
		return 2;
	}	
	rsakeygen(public_key_filename, private_key_filename,
				"12622624516681506749",
				"10325958134448386513",
	key, bits);	
}