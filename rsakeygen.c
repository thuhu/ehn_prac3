#include "defines.h"
#include "rc4.h"
// //
// uint32_t rc4_i = 0;
// uint32_t rc4_j = 0;

// // Random number gen
// void rc4_init(uint8_t *S, uint8_t * T, uint8_t * user_key, size_t key_length){
// 	uint32_t j = 0;
// 	for (int i = 0; i < 256; i++){
// 		S[i] = i;
// 		T[i] = user_key[i % key_length];
// 	}	
// 	for (int i = 0; i < 256; i++){
// 		uint8_t tmp;
// 		j = (j + S[i] + T[i]) % 256;
// 		tmp = S[i];
// 		S[i] = T[i];
// 		T[i] = tmp;
//  	}
// }

// void rc4_rand(uint8_t *S, uint8_t *rand){
// 	uint8_t tmp;
// 	uint32_t t = 0;

// 	rc4_i = (rc4_i + 1) % 256;
// 	rc4_j = (rc4_j + S[rc4_i]) % 256;

// 	tmp = S[rc4_i];
// 	S[rc4_i] = S[rc4_j];
// 	S[rc4_j] = tmp;

// 	t = (S[rc4_i] + S[rc4_j]) % 256;
// 	*rand = S[t];
// }
int rsakeygen(char * public_key_filename, char * private_key_filename, mpz_t num_p, mpz_t num_q){
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

	mpz_set(rsactx.p, num_p);
	mpz_set(rsactx.q, num_q);
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
int convert_key(char * key, uint8_t * converted_key, uint32_t key_length){
	if (key_length % 2){
		printf("Invalid Hex string.");
		return 3;
	}
	for (int i = 0; i < key_length; i += 2){
		uint8_t hex_digit = 0;
		uint8_t tmp = key[i];			
		
		if (tmp >= 48 &&  tmp <= 57){
			// Check if its a digit 0 - 9
			tmp -= 48;
			hex_digit = tmp << 4;
		} else if (tmp >= 97 &&  tmp <= 102){
			// Check if its an alphabet a - f
			tmp -= 87;
			hex_digit = tmp << 4;
		}else{
			// Invalid input detected
			printf("Invalid input detected at %d\n", i);
			return 3;
		}
		
		// Get second key from file
		tmp = key[i + 1];
		// Lower byte
		if (tmp >= 48 &&  tmp <= 57){
			// Check if its a digit 0 - 9
			tmp -= 48;
			hex_digit |= tmp;
		} else if (tmp >= 97 &&  tmp <= 102){
			// Check if its an alphabet a - f
			tmp -= 87;
			hex_digit |= tmp;
		}else{
			// Invalid input detected
			printf("Invalid input detected at %d\n", i);
			return 3;
		}
		converted_key[i / 2] = hex_digit;		
	}	
	return 0	;
}
uint8_t get_bit_from_byte(uint8_t c){
	return c & 0x01;
}
int main(int argc, char ** argv ){
	uint8_t test_vector[] = "abcdefghi";

	//mpz_t key;
	mpz_t p;
	mpz_t q;
	mpz_t bits;
	rc4ctx_t rc4ctx;
	char user_init_key[512] = {0};
	uint8_t user_rc4_hex_key [512] = {0};
	char tmp[100] = {0};
	int flag;
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
	if (!get_cmd_arg(user_init_key, argc, argv, "-key")){
		usage();
		return 2;
	}	
	if (!get_cmd_arg(tmp, argc, argv, "-b")){
		usage();
		return 2;
	}

	mpz_init(bits);
	mpz_init_set_ui(q, 1);
	mpz_init_set_ui(p, 1);
	if (mpz_set_str(bits, tmp, 10)){
		printf ("Invalid bits provided\n");
		return 2;
	}
	//
	if (convert_key(user_init_key, user_rc4_hex_key, strlen(user_init_key)) != 0){
		return 0;
	}

	rc4_init(&rc4ctx, test_vector, strlen(test_vector));	
	// rc4_init(&rc4ctx, user_rc4_hex_key, 8);	
	// printf("For %ld-bits\n", mpz_get_ui(bits));
	for (int i = 1; i <= mpz_get_ui(bits)/2 - 1; i++){
		uint8_t random = rc4_getbyte(&rc4ctx);
		mpz_mul_2exp(p, p, 1);
		get_bit_from_byte(random) == 1 ? mpz_add_ui(p, p, 1) : 1;
		printf("Bit %d: rn 0x%x\t\tbitval - %d\n", i, random, get_bit_from_byte(random));
	}		
	for (int i = 1; i <= mpz_get_ui(bits)/2 - 1; i++){
		uint8_t random = rc4_getbyte(&rc4ctx);
		mpz_mul_2exp(q, q, 1);
		get_bit_from_byte(random) == 1 ? mpz_add_ui(q, q, 1) : 1;
		printf("Bit %d: rn 0x%x\t\tbitval - %d\n", i, random, get_bit_from_byte(random));
	}
	gmp_printf("First Random values:\nP -> %Zd\nQ -> %Zd\n", p, q);
	mpz_nextprime(p, p);
	mpz_nextprime(q, q);

	rsakeygen(public_key_filename, private_key_filename, p, q);
}