#include "defines.h"

RSA_CODE rsaencrypt(char *  key, char * output_filename, char * public_key_filename){
	// char key_buff[256] = {};
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
	mpz_powm(cipher_text, cipher_text, public_key, n);
	// Save to file
	mpz_out_str(output_file_fp, 10, cipher_text); fprintf(output_file_fp, "\n");
	printf("Encrypted RC4 key: "); mpz_out_str(stdout, 16, cipher_text); putchar('\n');

	fclose(public_key_fp);
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
	char user_rc4_key[20] = {0};
	char user_rc4_hex_key [256] = {0};
	char tmp[100] = {0};
	char output_filename[100];
	// char input_filename[100];
	char public_key_filename[100];
	// char private_key_filename[100];
	FILE * user_key_fp;

	// // Get output file
	if (!get_cmd_arg(output_filename, argc, argv, "-fo")){
		usage();
		return 2;
	}
	if (!get_cmd_arg(public_key_filename, argc, argv, "-KU")){
		usage();
		return 2;
	}

	// Check if user provided key file.
	if (!get_cmd_arg(tmp, argc, argv, "-key")){
		printf("Enter RC4 key (Plain text): ");
		scanf("%32s", user_rc4_key);

	}else {
		char * line_buff = NULL;
		size_t len = 0;
		get_cmd_arg(tmp, argc, argv, "-key");
		user_key_fp = fopen(tmp, "rb");
		if (!user_key_fp){
			printf( "Couldn't open file \"%s\"\n", tmp);
			return 1;
		}
		getline(&line_buff, &len, user_key_fp);
		strncpy(user_rc4_key, line_buff, strlen(line_buff) - 1); // Remove the new line.
	}
	for (int i = 0; i < 16; i++){
		sprintf(tmp, "%02x", user_rc4_key[i]);
		strcat(user_rc4_hex_key, tmp);
	}	
	printf("User key (Base-16): %s\n", user_rc4_hex_key);

	rsaencrypt(user_rc4_hex_key, output_filename, public_key_filename);	
	return 0;
}