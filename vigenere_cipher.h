/* 
 * Header file for vigenere encryption library
 *
 * Todd Mercer 2018
 */


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
int vigenere_make_full_length_key(char *key, size_t key_length, char *key_buffer);

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
 */ 
int vigenere_encrypt_text(char *key, char *text_to_encrypt, bool decypher); 

