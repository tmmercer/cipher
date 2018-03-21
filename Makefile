# Makefile for cipher test code and cipher libraries
# Todd Mercer 2018

PROG_NAME = cipher_test
CEASAR_LIB_NAME = libcaesar
VIGENERE_LIB_NAME = libvigenere

all: $(PROG_NAME)

$(PROG_NAME): cipher_test.o $(CEASAR_LIB_NAME).a $(VIGENERE_LIB_NAME).a 
	gcc -lm -o $(PROG_NAME) cipher_test.o -L. -lcaesar -lvigenere -lcheck

cipher_test.o: cipher_test.c
	gcc -O -c cipher_test.c 

ceasar_cipher.o: caesar_cipher.c caesar_cipher.h
	gcc -O -c caesar_cipher.c

$(CEASAR_LIB_NAME).a: caesar_cipher.o
	ar rcs $(CEASAR_LIB_NAME).a caesar_cipher.o 

vigenere_cipher.o: vigenere_cipher.c vigenere_cipher.h
	gcc -O -c vigenere_cipher.c

$(VIGENERE_LIB_NAME).a: vigenere_cipher.o
	ar rcs $(VIGENERE_LIB_NAME).a vigenere_cipher.o 

libs: $(CEASAR_LIB_NAME).a $(VIGENERE_LIB_NAME).a

clean:
	rm -f $(PROG_NAME) *.o *.a *.gch 
