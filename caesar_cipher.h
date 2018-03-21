/* 
 * Header file for Caesar encryption library
 *
 * Todd Mercer 2018
 */

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
int ceasar_encrypt_text(unsigned int key, char *text_to_encrypt);
