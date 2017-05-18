#include "defines.h"

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
	mpz_out_str(output_file_fp, 16, plain_text); fprintf(output_file_fp, "\n");

	fclose(private_key_fp);
	fclose(input_file_fp);
	fclose(output_file_fp);
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
	// mpz_t key;
	// mpz_t bits;
	// char user_rc4_key[20] = {0};
	// char user_rc4_hex_key [256] = {0};
	// char tmp[100] = {0};
	char output_filename[100];
	char input_filename[100];
	// char public_key_filename[100];
	char private_key_filename[100];
	// FILE * user_key_fp;

	// Decrypt key file
	if (!get_cmd_arg(input_filename, argc, argv, "-fi")){
		usage();
		return 2;
	}	
	if (!get_cmd_arg(output_filename, argc, argv, "-fo")){
		usage();
		return 2;
	}
	if (!get_cmd_arg(private_key_filename, argc, argv, "-KR")){
		usage();
		return 2;
	}
	rsadecrypt(input_filename, output_filename, private_key_filename);
	return 0;
}	