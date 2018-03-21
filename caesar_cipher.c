/* 
 * Implementation file for Caesar encryption library
 *
 * Todd Mercer 2018
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "caesar_cipher.h"

#define LOWER_CHAR 'a'
#define UPPER_CHAR 'A'
#define MAX_CEASAR_KEY_SIZE 26

/*
 * ceasar_encrypt_text
 *
 * This functions does in-place encryption based on 
 * the Caesar's shift algorithm
 *
 * Argument: unsigned int key
 *           Key to calculate encrypted value. 
 *           Max value is 26.
 *
 * Argument: char *text_to_encrypt
 *           Pointer to text to encrypt
 *
 * Returns: int errno error
 * 
 */ 
int
ceasar_encrypt_text(unsigned int key, char *text_to_encrypt) 
{
    char base_char;
    int rc = 0;

    //Sanity check inputs to function
    if (text_to_encrypt == NULL) {
        fprintf(stderr, "%s: text_to_encrypt is NULL.\n", __FUNCTION__);
        return EINVAL;
    }

    if (key > MAX_CEASAR_KEY_SIZE) {
        fprintf(stderr, "%s: Key input of %d greater than max key %d.\n",
               __FUNCTION__, key, MAX_CEASAR_KEY_SIZE);
        return EINVAL;
    }

    for (int pos = 0; pos < strlen(text_to_encrypt); pos++) {
        if (isupper(text_to_encrypt[pos])) {
            text_to_encrypt[pos] = ((text_to_encrypt[pos] - UPPER_CHAR + 
                                    key) % MAX_CEASAR_KEY_SIZE) + UPPER_CHAR; 
        } else if (islower(text_to_encrypt[pos])) {
            text_to_encrypt[pos] = ((text_to_encrypt[pos] - LOWER_CHAR + 
                                    key) % MAX_CEASAR_KEY_SIZE) + LOWER_CHAR; 
        }  
    }

    return rc;
}
            
        
           
         
        
    





    
 
