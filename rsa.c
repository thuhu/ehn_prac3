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

RSA_CODE rsaencrypt(char *  key, char * output_filename, char * public_key_filename){
	char key_buff[256] = {};
	char * line_buff = NULL;
	size_t len = 0;
	mpz_t cipher_text;
	mpz_t public_key;
	mpz_t n;
	mpz_t encrypted_key;

	if (strlen(key) > 32){
		return RSA_KEY_ENCRYPT_ERROR;
	}
	// Retrive public key
	FILE * public_key_fp = fopen(public_key_filename, "rb");
	FILE * output_file_fp = fopen(output_filename, "wb");

	mpz_init(cipher_text);
	mpz_init(public_key);
	mpz_init(encrypted_key);
	mpz_init(n);

	if (!public_key_fp){
		printf( "Couldn't open file \"%s\"\n", public_key_filename);
		return RSA_FILE_ERROR;
	}	 
	if (!output_file_fp){
		printf( "Couldn't open file \"%s\"\n", output_filename);
		return RSA_FILE_ERROR;		
	}
	// Get n from the file 
	getline(&line_buff, &len, public_key_fp);
	printf("Read n: %s<size-%ld>\n", line_buff, strlen(line_buff));
	if (mpz_set_str(n, line_buff, 10)){
		return RSA_KEY_ENCRYPT_ERROR;
	}			
	// Get public key from the file
	getline(&line_buff, &len, public_key_fp);
	printf("Read public key: %s<size-%ld>\n", line_buff, strlen(line_buff));
	if (mpz_set_str(public_key, line_buff, 10)){
		return RSA_KEY_ENCRYPT_ERROR;
	}		
	if (mpz_set_str(cipher_text, key,16)){
		return RSA_KEY_ENCRYPT_ERROR;
	}	
	printf("RC4 Key: "); mpz_out_str(stdout, 16, cipher_text); putchar('\n');
	mpz_powm(cipher_text, cipher_text, public_key, n);
	printf("Encrypted RC4 key: "); mpz_out_str(stdout, 16, cipher_text); putchar('\n');
	fclose(public_key_fp);
	fclose(output_file_fp);
	// Save to file
	mpz_out_str(output_file_fp, 10, cipher_text); fprintf(output_file_fp, "\n");
	return RSA_SUCCESS;
}
RSA_CODE rsadecrypt(char *  input_filename, char * output_filename, char * private_key_filename){
	char * line_buff = NULL;
	size_t len = 0;
	mpz_t plain_text;
	mpz_t private_key;
	mpz_t n;
	mpz_t encrypted_key;

	// Retrive private key
	FILE * private_key_fp = fopen(private_key_filename, "rb");
	FILE * output_file_fp = fopen(output_filename, "wb");
	FILE * input_file_fp = fopen(input_filename, "rb");

	mpz_init(plain_text);
	mpz_init(private_key);
	mpz_init(encrypted_key);
	mpz_init(n);

	if (!private_key_fp){
		printf( "Couldn't open file \"%s\"\n", private_key_filename);
		return RSA_FILE_ERROR;
	}	 
	if (!output_file_fp){
		printf( "Couldn't open file \"%s\"\n", output_filename);
		return RSA_FILE_ERROR;		
	}
	if (!input_file_fp){
		printf( "Couldn't open file \"%s\"\n", input_filename);
		return RSA_FILE_ERROR;		
	}	
	mpz_init(plain_text);
	mpz_init(private_key);
	mpz_init(encrypted_key);
	mpz_init(n);
	// Get n from the file 
	getline(&line_buff, &len, private_key_fp);
	printf("Read n: %s<size-%ld>\n", line_buff, strlen(line_buff));
	if (mpz_set_str(n, line_buff, 10)){
		return RSA_KEY_ENCRYPT_ERROR;
	}			
	// Get private key from the file
	getline(&line_buff, &len, private_key_fp);
	printf("Read private key: %s<size-%ld>\n", line_buff, strlen(line_buff));
	if (mpz_set_str(private_key, line_buff, 10)){
		return RSA_KEY_ENCRYPT_ERROR;
	}		
	// Get 	RC4 key from file.
	getline(&line_buff, &len, input_file_fp);
	printf("Read RC4 (Encrypted) key: %s<size-%ld>\n", line_buff, strlen(line_buff));
	if (mpz_set_str(encrypted_key, line_buff, 10)){
		return RSA_KEY_ENCRYPT_ERROR;
	}			
	mpz_powm(plain_text, encrypted_key, private_key, n);
	printf("Decrypted RC4 key: "); mpz_out_str(stdout, 16, plain_text); putchar('\n');

	fclose(private_key_fp);
	fclose(input_file_fp);
	fclose(output_file_fp);
	return RSA_SUCCESS;
}

int get_cmd_arg(char * src, int argc, char ** argv, char * tag);
void usage(void);
int main(int argc, char ** argv ){
	mpz_t key;
	mpz_t bits;
	char user_rc4_key[20] = {0};
	char user_rc4_hex_key [256] = {0};
	char tmp[100] = {0};
	char output_filename[100];
	char public_key_filename[100];
	char private_key_filename[100];
	FILE * user_key_fp;
	
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

	// Make sure that the key is 16 bytes long
	// char user_rc4_key[20] = {0};
	// char user_rc4_hex_key [256] = {0};
	// char tmp[100] = {0};
	// char output_filename[100];
	// char public_key_filename[100];
	// FILE * user_key_fp;

	// // Get output file
	// if (!get_cmd_arg(output_filename, argc, argv, "-fo")){
	// 	usage();
	// 	return 2;
	// }
	// if (!get_cmd_arg(public_key_filename, argc, argv, "-KU")){
	// 	usage();
	// 	return 2;
	// }

	// // Check if user provided key file.
	// if (!get_cmd_arg(tmp, argc, argv, "-key")){
	// 	printf("Enter RC4 key (Plain text): ");
	// 	scanf("%32s", user_rc4_key);

	// }else {
	// 	char * line_buff = NULL;
	// 	size_t len = 0;
	// 	get_cmd_arg(tmp, argc, argv, "-key");
	// 	user_key_fp = fopen(tmp, "rb");
	// 	if (!user_key_fp){
	// 		printf( "Couldn't open file \"%s\"\n", tmp);
	// 		return 1;
	// 	}
	// 	getline(&line_buff, &len, user_key_fp);
	// 	strncpy(user_rc4_key, line_buff, strlen(line_buff) - 1); // Remove the new line.
	// }
	// for (int i = 0; i < 16; i++){
	// 	sprintf(tmp, "%02x", user_rc4_key[i]);
	// 	strcat(user_rc4_hex_key, tmp);
	// }	
	// printf("User key (Base-16): %s\n", user_rc4_hex_key);

	// rsaencrypt(user_rc4_key, output_filename, public_key_filename);
	// rsadecrypt(argv[1], argv[2], argv[3]);
	return 0;
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