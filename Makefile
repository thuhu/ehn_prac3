all: rsakeygen.c rsa.c rsadecrypt.c rsaencrypt.c 
	gcc -Wall -g -o  rsakeygen rsakeygen.c rc4.c -lgmp	
	gcc -Wall -g -o  rsaencrypt rsaencrypt.c -lgmp
	gcc -Wall -g -o  rsadecrypt rsadecrypt.c -lgmp
	

clean:
	rm *.o
	