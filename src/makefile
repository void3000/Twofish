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

# define any compile-time flags
#
# CFLAGS = -Wall -Wunused-variable
CFLAGS = -Wall

# define library paths in addition to /usr/lib
#   if I wanted to include libraries not in /usr/lib I'd specify
#   their path using -Lpath, something like:
#
LIBFLAGS = -L./lib

# define the C compiler to use
#
CC = gcc

# define any directories containing header files other than /usr/include
#
INCLUDES = -I./include

# define any libraries to link into executable:
#   if I want to link in libraries {libx.so or libx.a} I use the -llibname 
#   option, something like {this will link in libmylib.so and libm.so:
# 
# LIBS = -lmylib -lm
LIBS =

# define the C source files
#
SRCS = ${wildcard *.c}

# define the C object files 
#
# This uses Suffix Replacement within a macro:
#   ${name:string1=string2}
#         For each word in 'name' replace 'string1' with 'string2'
# Below we are replacing the suffix .c of all words in the macro SRCS
# with the .o suffix
#
OBJS = ${SRCS:.c=.o}

# define the executable file
#
TARGET = twofish

#
# The following part of the makefile is generic; it can be used to 
# build any executable just by changing the definitions above and by
# deleting dependencies appended to the file from 'make depend'
#
all: compile

compile: ${TARGET} install clean
  
${TARGET}: ${SRCS}
	${CC} ${CFLAGS} -o $@ $^ ${LIBFLAGS} ${INCLUDES}

install:
	mkdir -p ./bin
	mv ${TARGET} ./bin

clean:
	rm -f ${OBJS}
