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
#ifndef __TWOFISH__H
#define __TWOFISH__H
#include <stdint.h>

#define TWOFISH
#ifdef  TWOFISH
typedef struct twofish_t 
{
    uint8_t len;
    uint32_t k[40];
    uint32_t s[4][256];
}twofish_t;
#endif
/*
 * Twofish MDS Multiply Function
 * 
 * Description:
 *
 * @param   tf_twofish
 * @param   data
 * @param   cypher
 * @usage
 * {@code}
 */
void Twofish_encryt(twofish_t* tf_twofish, uint8_t *data, uint8_t *cypher);
/*
 * Twofish Decryption Function
 * 
 * Description:
 *
 * @param	tf_twofish
 * @param   cypher
 * @param   data
 * @usage
 * {@code}
 */
void Twofish_decryt(twofish_t* tf_twofish, uint8_t *cypher, uint8_t *data);
/*
 * Twofish Setup Function
 * 
 * Description:
 *
 * @param   s
 * @param   len
 * @usage
 * {@code}
 */
twofish_t*  Twofish_setup(uint8_t *s, uint32_t len);

#endif
