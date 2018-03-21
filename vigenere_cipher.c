/* 
 * Implementation file for vigenere encryption library
 *
 * Todd Mercer 2018
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#include "caesar_cipher.h"

#define MAX_VIGENERE_STR_LENGTH 200
#define UPPER_BASE 'A'
#define UPPER_END 'Z'
#define LOWER_BASE 'a'
#define LOWER_END 'z'
#define ALPHA_NUM 26

/*
 * vigenere_make_full_length_key
 *
 * This function makes a Vigenere key 
 * of the specified length
 *
 * Argument: char *key
 *           Key to calculate encrypted value. 
 *
 * Argument: size_t key_length
 *           Length of key to create.
 *
 * Returns: int errno error
 *
 * Returns: char *key_buffer 
 *          Key matching length specified
 * 
 */ 
int
vigenere_make_full_length_key(char *key, size_t key_length, char *key_buffer) 
{
    int rc = 0, pos = 0, key_pos = 0;

    // Sanity check inputs to function
    if (key == NULL) {
        fprintf(stderr, "%s: Key input is NULL.\n", __FUNCTION__);
        return EINVAL;
    }

    if (key_buffer == NULL) {
        fprintf(stderr, "%s: key_buffer input is NULL.\n", __FUNCTION__);
        return EINVAL;
    }

    if (key_length == 0) {
        fprintf(stderr, "%s: key_length is 0.\n", __FUNCTION__);
        return EINVAL;
    }

    for (pos = 0, key_pos = 0; pos < key_length; pos ++, key_pos++) {
        /* 
         * If we have reached the end of the supplied key
         * then start from the beginning of the supplied key
         */ 
        if ((pos % strlen(key)) == 0) {
            key_pos = 0;
        }
 
       
        // If key character is not alphabetical, return an error
        if (!isalpha(key[key_pos])) {
	    fprintf(stderr, "%s: Key character '%c' at position %d is not alphabetical. \n",
                    __FUNCTION__, key[key_pos], key_pos);
            return EINVAL;
        }
        key_buffer[pos] = toupper(key[key_pos]);
    }

    key_buffer[pos] = '\0';

    return rc;
}

/*
 * vigenere_encrypt_text
 *
 * This function does in-place encryption based on 
 * the Vigenere's algorithm
 *
 * Argument: char *key
 *           Key to calculate encrypted value. 
 *
 * Argument: char *text_to_encrypt
 *           Pointer to text to encrypt
 *
 * Argument: bool decypher
 *           If true, decypher text, else encypher text
 *
 * Returns: int errno error
 * 
 */ 
int
vigenere_encrypt_text(char *key, char *text_to_encrypt, bool decypher) 
{
    char base_char;
    int rc = 0, pos = 0;
    char key_buffer[MAX_VIGENERE_STR_LENGTH];

    memset(key_buffer, 0, MAX_VIGENERE_STR_LENGTH);
    
    //Sanity check inputs to function
    if (text_to_encrypt == NULL) {
        fprintf(stderr, "%s: text_to_encrypt is NULL.\n", __FUNCTION__);
        return EINVAL;
    }

    if (key == NULL) {
        fprintf(stderr, "%s: Key input is NULL.\n", __FUNCTION__);
        return EINVAL;
    }

    if (strlen(text_to_encrypt) > MAX_VIGENERE_STR_LENGTH-1) {
        fprintf(stderr, "%s: text_to_encrypt of size %lu is larger than max supported" 
	        " size of %d.\n", __FUNCTION__, strlen(text_to_encrypt), 
                MAX_VIGENERE_STR_LENGTH-1);
        return EINVAL;
    }

    rc = vigenere_make_full_length_key(key, strlen(text_to_encrypt), key_buffer);
    if (rc != 0) {
        return rc;
    }
  
    for (pos = 0; pos < strlen(text_to_encrypt); pos++) {
        if (!isalpha(text_to_encrypt[pos])) {
	    continue;
        }
        if (islower(text_to_encrypt[pos])) {
	    if (decypher) {
	        if (text_to_encrypt[pos] - (tolower(key_buffer[pos])) < 0 ) {
		   text_to_encrypt[pos] = (text_to_encrypt[pos] - tolower(key_buffer[pos]) + LOWER_END) + 1;
                } else {
		   text_to_encrypt[pos] = text_to_encrypt[pos] - tolower(key_buffer[pos]) + LOWER_BASE;
                }
            } else {
                text_to_encrypt[pos] = ((text_to_encrypt[pos]- LOWER_BASE) + (key_buffer[pos]- UPPER_BASE)) 
                                         % ALPHA_NUM + LOWER_BASE;
            }
        } else if (isupper(text_to_encrypt[pos])) {
	    if (decypher) {
	        if ((text_to_encrypt[pos] - key_buffer[pos]) < 0) {
                    text_to_encrypt[pos] = text_to_encrypt[pos] - key_buffer[pos] + UPPER_END + 1;
                } else {
		    text_to_encrypt[pos] = text_to_encrypt[pos] - key_buffer[pos] + UPPER_BASE;
                }                                 
            } else {
                text_to_encrypt[pos] = ((text_to_encrypt[pos]- UPPER_BASE) + (key_buffer[pos]- UPPER_BASE)) 
                                         % ALPHA_NUM + UPPER_BASE;
            }
        }
    }

    return rc;
}
            
        
           
         
        
    





    
 
