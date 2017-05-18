#include "rc4.h"
#define MAX 256




void swap(rc4ctx_t* rc4c, uint8_t i, uint8_t j){
    uint8_t temp = rc4c->S[i];
    rc4c->S[i] = rc4c->S[j];
    rc4c->S[j] = temp;
}


void rc4_init(rc4ctx_t* rc4c, unsigned char* key, int keylen){
    uint8_t temp[MAX] = {0};
    int j = 0;
    /* Initialization of S vector in ascending order*/
    
    rc4c->index_1 = 0;
    rc4c->index_2 = 0;
   
    for(int i = 0; i < MAX; i++){
        
        rc4c->S[i] = i;
        temp[i] = key[i % keylen];
        
        
    }
    
    
    
    /*Permutation of S*/
    
    for(int i = 0; i < MAX; i++ ){
        j = (j + rc4c->S[i] + temp[i]) % MAX;
        swap(rc4c, i, j);
    }
    
    
    
}



unsigned char rc4_getbyte(rc4ctx_t* rc4c){
int t = 0;

/*Byte generation from state vector S used to generate the stream*/
rc4c->index_1 = (rc4c->index_1 + 1) % MAX;
rc4c->index_2 = (rc4c->index_2 + rc4c->S[rc4c->index_1]) % MAX;
swap(rc4c,rc4c->index_1,rc4c->index_2);
t = (rc4c->S[rc4c->index_1] + rc4c->S[rc4c->index_2]) % MAX;
return rc4c->S[t];
}


void encrypt_decrypt(FILE * text_input, FILE * text_output, rc4ctx_t * rc4c){
    
    
    uint8_t buffer[512] = {0};
    uint8_t buffer2[512] = {0};
    int size = fread(buffer,1,sizeof(buffer),text_input);

    /*Stream cipher generation*/
    while(size > 0){
    
        for(int i = 0; i < size; i++)
            buffer2[i] = buffer[i] ^ rc4_getbyte(rc4c);    
        
        
        for(int i = 0; i < size; i++)
            fprintf(text_output, "%c", buffer2[i]);
        
        size = fread(buffer,1,sizeof(buffer),text_input);
        
    }
    
}


// int main (int argc, char* argv[]){
//     rc4ctx_t *rc4;
//     unsigned char *key;
//     FILE *text_input;
//     FILE *text_output;
//     FILE *k;
//     int keylen = 0;
    
//     if(argc >= 2){
        
//         if(strcmp(argv[1],"-fi") == 0){
            
//             if(argc >= 2){
//             text_input = fopen(argv[2],"rb");
            
//             if(text_input == NULL){
//                 printf("Invalid file\n");
//                 return 0;
//             }
//             }else{ 
//                 printf("Provide name of the input file\n");
//                 return 0;
//             }
//             }else{
//             printf("Incorrect command, please use -fi\n");
//             return 0;
//         }
        
        
//         if(argv[3] != NULL){
//             if(strcmp(argv[3],"-fo") == 0){
//                 text_output = fopen(argv[4],"wb");
                
//             }else{
//                 printf("Incorrect command, please use -fo\n");
//                 return 0;
//             }
//         }else{
//             printf("Provide name of the output file\n");
//             return 0;
        
//         }
        
        
//         if(argv[5] != NULL){
//             if(strcmp(argv[5],"-kf") == 0){
//                 k = fopen(argv[6],"rb");
                
//                 if(k == NULL){
//                     printf("Invalid file\n");
//                     return 0;
//                 }
//                 fseek(k,0,SEEK_END);
                
//                 if(ftell(k) > 16){
//                     printf("Key larger than 16 bytes. Provide a small key.\n");
//                     return 0;
//                 }else{
                    
                    
                   
                    
//                     key = malloc(ftell(k));
                    
//                     fseek(k,0,SEEK_SET);
                    
//                     int byte;
//                     while((byte = fgetc(k)) != EOF){
//                         printf("%c\n",byte);
//                         key[keylen] = (unsigned char) byte;
//                         keylen++;
//                     }
                   
//                 }
                
                
//             }else {
//                 printf("Invalid command. Use -kf\n");
//                 return 0;
//             }
//         }else{
           
//            /*Prompts the user for a key when there's no key file specified.*/
//            while(1){
//                key = malloc(16);
//                printf("Enter a key with max 16 characters and no spaces:\n");
//                scanf("%s", key);
//                keylen = strlen(key);
               
//                if(keylen <= 16) break;
//                else printf("Key entered had more than 16 characters please try again\n\n");
               
//            }
//         }
        
//         /*Initialise rc4 context structure and encrypt or decrypt the opened file.*/
//         rc4_init(rc4,key,keylen);
//         encrypt_decrypt(text_input, text_output,rc4);
        
//     }else{
//         printf("Please give command line arguments\n");
//         return 0;
//     }
    
//     /*Close all the files opened.*/
//     fclose(text_input);
//     fclose(text_output);
//     fclose(k);
    
    
// }
