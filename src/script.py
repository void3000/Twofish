# -*- coding: utf-8 -*-
#
# The MIT License (MIT)
#
# Copyright (c) 2018 Zhou Zhi Gang
# Email: keorapetse.finger@yahoo.com
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

header ='''
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
 #ifndef __TABLES__H
 #define __TABLES__H
 
 /* The MDS Matrix */
 uint8_t mds[4][4]=
 {
    {0x01, 0xef, 0x5b, 0x5b},
    {0x5b, 0xef, 0xef, 0x01},
    {0xef, 0x5b, 0x01, 0xef},
    {0xef, 0x01, 0xef, 0x5b}
 };
 
 /*
 * The Permutations q0 and q1 The permutations q0 and q1 are xed permutations on 
 * 8-bit values. They are constructed from four dierent 4-bit permutations each. 
 * We ha ve in vestigated the resulting 8-bit permutations, q0 and q1, extensively,
 * and believe them to be at least no weaker than randomly selected 8-bit permutations.
 */

 '''

upper_body = '''
uint8_t q[2][256] =
{
    /* q0 */
    {
        '''
lower_body = '''
    /* q1 */
    {
'''

footer = '''
};

#endif
'''

path = "./include/tables.h"

# s-box 1
q0 =[
    [0x8,0x1,0x7,0xD,0x6,0xF,0x3,0x2,0x0,0xB,0x5,0x9,0xE,0xC,0xA,0x4],
    [0xE,0xC,0xB,0x8,0x1,0x2,0x3,0x5,0xF,0x4,0xA,0x6,0x7,0x0,0x9,0xD],
    [0xB,0xA,0x5,0xE,0x6,0xD,0x9,0x0,0xC,0x8,0xF,0x3,0x2,0x4,0x7,0x1],
    [0xD,0x7,0xF,0x4,0x1,0x2,0x6,0xE,0x9,0xB,0x3,0x0,0x8,0x5,0xC,0xA]
]

# s-box 2
q1 =[
    [0x2,0x8,0xB,0xD,0xF,0x7,0x6,0xE,0x3,0x1,0x9,0x4,0x0,0xA,0xC,0x5],
    [0x1,0xE,0x2,0xB,0x4,0xC,0x3,0x7,0x6,0xD,0xA,0x5,0xF,0x9,0x0,0x8],
    [0x4,0xC,0x7,0x5,0x1,0x6,0x9,0xA,0x0,0xE,0xD,0x8,0x2,0xB,0x3,0xF],
    [0xB,0x9,0x5,0x1,0xC,0x3,0xD,0xE,0x6,0x4,0x7,0xF,0x2,0x0,0x8,0xA]
]

# Rotate a 4-bit nibble
def ror(a,b):
    return (((a>>b)&0xf)|((a<<(4-b))&0xf))

# Left-shift a 4-bit nibble
def lsh(a,b):
    return ((a<<b)&0xf)

# Derives a and b from previous paramters
def h(a,b):
    a1 = a^b
    b1 = a^ror(b,1)^lsh(a,3)
    return (a1,b1)

# Generate permutation value
def permute(q,x):
    '''
    The permutations q0 and q1 are ﬁxed permutations on 8-bit values.
    They are constructed from four different 4-bit permutations each.
    For the input value x, we deﬁne the corresponding output value y.
    '''
    a0,b0 = ((x>>4)&0xf),(x&0xf)
    a1,b1 = h(a0,b0)
    a2,b2 = q[0][a1],q[1][b1]
    a3,b3 = h(a2,b2)
    a4,b4 = q[2][a3],q[3][b3]
    return ((b4<<4|a4)&0xff)

def write_body(q,t):
    for x in range(255):
        y = permute(q,x)
        if x%16 == 0:
            t.write("\n\t\t0x%x," % y)
        else:
            t.write("0x%x," % y)
    t.write("0x%x" % permute(q,255))
    pass

if __name__ == "__main__":
    t = open(path,"w+")
    t.write(header)
    t.write(upper_body)
    write_body(q0,t)
    t.write('''\n\t},''')
    t.write(lower_body)
    write_body(q1,t)
    t.write('''\n\t}''')
    t.write(footer)
    t.close()
    pass

