rsa.o: rsa.c
	gcc -Wall -g -o  rsa rsa.c -lgmp	
rsakeygen.o: rsakeygen.c
	gcc -Wall -g -o  rsakeygen rsakeygen.c rc4.c -lgmp	
rsaencrypt.o: rsaencrypt.c
	gcc -Wall -g -o  rsaencrypt rsaencrypt.c -lgmp
rsadecrypt.o: rsadecrypt.c
	gcc -Wall -g -o  rsadecrypt rsadecrypt.c -lgmp