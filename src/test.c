/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2018 Zhou Zhi Gang
 * Email: keorapetse.finger@yahoo.com
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "twofish.h"

static int errnos = 0;

typedef struct twofish_test_t
{
    uint8_t len;
    char *key;
    char *plain;
    char *cypher;
}twofish_test_t;

const twofish_test_t twofish_test[] =
{
    {64, "a0b253bb056bb710","90afe91bb288544f2c32dc239b2635e6","ffd764db025a90bda8f04dfd41a3dfdb"},
    {128,"cf5553bc00ff56c3ee51a04511bc54d9","90afe91bb288544f2c32dc239b2635e6","4ac085c729dbc814fe98d5a1d8bdce7e"}
};

// Converts a string of hex codes to a string of code words
void hex_to_codeword(uint8_t *dest, const char *src, int len)
{
    for(int j=0; j<len;++j)
    {
        uint8_t w=0;
        for (int g=0; g<2; ++g)
        {
            int n = 4*(1-g);
            if((*src>='0') && (*src<='9')){
                w|=((*src-'0')<<n);
            }
            else{
                w|=((*src-'a'+10)<<n);
            }
            src++;
        }
        *(dest++)=w;
    }
}

// Assert function
void assert_twofish(int m,const char *msg,const twofish_test_t *tf,uint8_t *given,uint8_t *derived, int expected)
{
    if(memcmp(given,derived,16) == expected)
    {
        fprintf(stdout,"Assertion passed(%d): %s\n",m,msg);
    }else
    {
        fprintf(stdout,"Assertion failed(%d): %s\n",m,msg);
        fprintf(stdout,"\texpected\t\t= %d\n",expected);
        errnos++;
    }
    fprintf(stdout,"\tkey\t\t\t= %s\n",tf->key);
    fprintf(stdout,"\tresults expected\t= ");
    for(int j=0;j<16;++j)
        fprintf(stdout,"%x",*given++);
    fprintf(stdout,"\n\tresults generated\t= ");
    for(int j=0;j<16;++j)
        fprintf(stdout,"%x",*derived++);
    fprintf(stdout,"\n");
}

/* Test$ ./twofish "*secretkey*" "secret message.." */
int main(int argc, char** argv)
{
    uint8_t test_cypher[16],test_plain[16],test_key[32],cypher[16],plain[16];
    twofish_t* tf_twofish = NULL;
    int demo = 0;
    char *secret_key = NULL, *message = NULL;
    
    if (argc > 1){
        demo = 1;
        secret_key = argv[1];
        message = argv[2];
    }
    
    if (demo)
    {
        tf_twofish = Twofish_setup((uint8_t*)secret_key,sizeof(secret_key)*8);
        Twofish_encryt(tf_twofish,(uint8_t*)message,cypher);
        Twofish_decryt(tf_twofish,cypher,plain);

        fprintf(stdout,"\tkey\t= %s\n", secret_key);
        fprintf(stdout,"\tplain\t= %s\n", message);
        fprintf(stdout,"\tcypher\t= ");
        for(int j=0;j<16;++j)
            fprintf(stdout,"%c",*(cypher+j));
        fprintf(stdout,"\n\tplain\t= ");
        for(int j=0;j<16;++j)
            fprintf(stdout,"%c",*(plain+j));
    }else
    {
        for (int j=0; j<2;++j)
        {
            const twofish_test_t *tf = &twofish_test[j];

            hex_to_codeword(test_key,tf->key, tf->len/8);
            hex_to_codeword(test_plain,tf->plain,16);
            hex_to_codeword(test_cypher,tf->cypher,16);

            tf_twofish = Twofish_setup(test_key, tf->len);
            Twofish_encryt(tf_twofish,test_plain,cypher);
            Twofish_decryt(tf_twofish,cypher,plain);
            
            assert_twofish(j,"Encryption",tf,test_cypher,cypher,0);
            assert_twofish(j,"Decryption",tf,test_plain,plain,0);
        }
        fprintf(stdout,"Test complete!\n");
        fprintf(stdout,"Errors: %d\n",errnos);
    }

    free(tf_twofish);
    return 0;
}
