/*
 * This Program Tests Cipher Encryption Libraries
 * 
 * Todd Mercer 2018
 * 
 */
#include <stdio.h>
#include <stdlib.h>
#include <check.h>
#include <errno.h>
#include <stdbool.h>

#include "caesar_cipher.h"
#include "vigenere_cipher.h"

/*
 * Tests invalid key
 */ 
START_TEST(test_ceasar_cipher_invalid_key)
{
    int key = 28;
    char text_to_encrypt[] = "Ceasar encryption test";
    int rc = ceasar_encrypt_text(key, text_to_encrypt);

    ck_assert_int_eq(EINVAL, rc);
}
END_TEST

/*
 * Tests NULL text
 */ 
START_TEST(test_ceasar_cipher_null_text)
{
    int key = 10;
    int rc = ceasar_encrypt_text(key, NULL);

    ck_assert_int_eq(EINVAL, rc);
}
END_TEST

/*
 * Tests encryption accuracy 
 */ 
START_TEST(test_ceasar_cipher_encryption)
{
    /* 
     * hfjxfw yjxy xywnsl" is the known encrypted
     * value for the "Caesar Test String" with 
     * a key value of 5.
     */
    char encrypted_text[] = "Hfjxfw Yjxy Xywnsl";
    char unencrypted_text[] = "Caesar Test String";
    int key = 5;

    int rc = ceasar_encrypt_text(key, unencrypted_text);
    
    ck_assert_str_eq(unencrypted_text, encrypted_text);
    ck_assert_int_eq(0, rc);
}
END_TEST

/*
 * Test suite for validating Vigenere cipher library
 */ 
Suite * ceasar_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Ceasar Cipher");
  
    tc_core = tcase_create("Core");

    // Add test cases to suite
    tcase_add_test(tc_core, test_ceasar_cipher_invalid_key);
    tcase_add_test(tc_core, test_ceasar_cipher_null_text);
    tcase_add_test(tc_core, test_ceasar_cipher_encryption); 

    suite_add_tcase(s, tc_core);

    return s;
}

/*
 * Tests vigenere_make_full_length_key function
 * with key size > length of supplied key
 */ 
START_TEST(test_vigenere_cipher_make_large_key)
{
    char key_buffer[10];
    int rc = vigenere_make_full_length_key("beef", 6, key_buffer);
    
    ck_assert_str_eq(key_buffer, "BEEFBE");
    ck_assert_int_eq(0, rc);

}
END_TEST

/*
 * Tests vigenere_make_full_length_key function
 * with key size < length of supplied key
 */ 
START_TEST(test_vigenere_cipher_make_small_key)
{
    char key_buffer[10];
    int rc = vigenere_make_full_length_key("beeffeed", 7, key_buffer);
    
    ck_assert_str_eq(key_buffer, "BEEFFEE");
    ck_assert_int_eq(0, rc);

}
END_TEST

/*
 * Tests vigenere_make_full_length_key function
 * with upper case key
 */ 
START_TEST(test_vigenere_cipher_make_upper_case_key)
{
    char key_buffer[10];
    int rc = vigenere_make_full_length_key("BEEF", 6, key_buffer);
    
    ck_assert_str_eq(key_buffer, "BEEFBE");
    ck_assert_int_eq(0, rc);

}
END_TEST

/*
 * Tests vigenere_make_full_length_key function
 * with key = NULL
 */ 
START_TEST(test_vigenere_cipher_make_key_null)
{
    char key_buffer[10];
    int rc = vigenere_make_full_length_key(NULL, 7, key_buffer);
   
    ck_assert_int_eq(EINVAL, rc);

}
END_TEST

/*
 * Tests vigenere_make_full_length_key function
 * with key size = 0
 */ 
START_TEST(test_vigenere_cipher_make_key_size_0)
{
    char key_buffer[10];
    int rc = vigenere_make_full_length_key("test", 0, key_buffer);
   
    ck_assert_int_eq(EINVAL, rc);

}
END_TEST

/*
 * Tests vigenere_make_full_length_key function
 * with key buffer = NULL
 */ 
START_TEST(test_vigenere_cipher_make_key_buffer_null)
{
    char key_buffer[10];
    int rc = vigenere_make_full_length_key("test", 5, NULL);
   
    ck_assert_int_eq(EINVAL, rc);

}
END_TEST

/*
 * Tests vigenere_make_full_length_key function
 * with key containing non-alphabetical character
 */ 
START_TEST(test_vigenere_cipher_make_key_non_alpha)
{
    char key_buffer[10];
    int rc = vigenere_make_full_length_key("test1", 8, key_buffer);
   
    ck_assert_int_eq(EINVAL, rc);

}
END_TEST

/*
 * Tests vigenere_encrypt_text function
 * with known key/text pair
 */ 
START_TEST(test_vigenere_cipher_encypher_decypher)
{
    char text_to_encrypt[] = "vigenere ";
    char key_buffer[] = "sas";
    int rc = vigenere_encrypt_text(key_buffer, text_to_encrypt, 0);
   
    ck_assert_str_eq(text_to_encrypt, "niywnwje ");
    ck_assert_int_eq(0, rc);

    rc = vigenere_encrypt_text(key_buffer, text_to_encrypt, 1);
    ck_assert_str_eq(text_to_encrypt, "vigenere ");
    ck_assert_int_eq(0, rc);    
}
END_TEST

/*
 * Tests vigenere_encrypt_text function
 * with known key/text pair
 * text will have numbers
 */ 
START_TEST(test_vigenere_cipher_encypher_number)
{
    char text_to_encrypt[] = "vigenere1";
    char key_buffer[] = "sas";
    int rc = vigenere_encrypt_text(key_buffer, text_to_encrypt, 0);
   
    ck_assert_str_eq(text_to_encrypt, "niywnwje1");
    ck_assert_int_eq(0, rc);

    rc = vigenere_encrypt_text(key_buffer, text_to_encrypt, 1);
    ck_assert_str_eq(text_to_encrypt, "vigenere1");
    ck_assert_int_eq(0, rc);
}
END_TEST

/*
 * Tests vigenere_encrypt_text function 
 * with NULL text
 */ 
START_TEST(test_vigenere_cipher_encypher_null_text)
{
    char key_buffer[] = "sas";
    
    int rc = vigenere_encrypt_text(key_buffer, NULL, 0);
  
    ck_assert_int_eq(EINVAL, rc);

}
END_TEST

/*
 * Tests vigenere_encrypt_text function 
 * with NULL key
 */ 
START_TEST(test_vigenere_cipher_encypher_null_key);
{
    int rc = vigenere_encrypt_text(NULL, "TEXT", 0);
  
    ck_assert_int_eq(EINVAL, rc);

}
END_TEST


/*
 * Test suite for validating Vigenere cipher library
 */ 
Suite * vigenere_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Vigenere Cipher");
  
    tc_core = tcase_create("Core");

    // Add test cases to suite
    tcase_add_test(tc_core, test_vigenere_cipher_make_large_key);
    tcase_add_test(tc_core, test_vigenere_cipher_make_small_key);
    tcase_add_test(tc_core, test_vigenere_cipher_make_upper_case_key);
    tcase_add_test(tc_core, test_vigenere_cipher_make_key_null);
    tcase_add_test(tc_core, test_vigenere_cipher_make_key_size_0);
    tcase_add_test(tc_core, test_vigenere_cipher_make_key_buffer_null);
    tcase_add_test(tc_core, test_vigenere_cipher_make_key_non_alpha);
    tcase_add_test(tc_core, test_vigenere_cipher_encypher_decypher);
    tcase_add_test(tc_core, test_vigenere_cipher_encypher_number);
    tcase_add_test(tc_core, test_vigenere_cipher_encypher_null_key);
    tcase_add_test(tc_core, test_vigenere_cipher_encypher_null_text);

    suite_add_tcase(s, tc_core);

    return s;
}

int main()
{
    int num_failed;
    Suite *cs, *vs;
    SRunner *cs_sr, *vs_sr;

    //Create and run Caesar test suite
    cs = ceasar_suite();
    cs_sr = srunner_create(cs);
    srunner_run_all(cs_sr, CK_NORMAL);

    num_failed = srunner_ntests_failed(cs_sr);
    srunner_free(cs_sr);

    //Create and run Vigenere test suite
    vs = vigenere_suite();
    vs_sr = srunner_create(vs);
    srunner_run_all(vs_sr, CK_NORMAL);

    num_failed = srunner_ntests_failed(vs_sr);
    srunner_free(vs_sr);

    if (num_failed != 0) {
        return EXIT_SUCCESS;
    }
}

