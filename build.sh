#! /bin/bash

FILE="./include/tables.h"
SCRIPT="./script.py"
MAKEFILE="./makefile"

if [ "$(command -v python)" ] 
    then
    PYTHON_EXITS=1
else
    echo "Python not installed."
    echo "Build exiting..."
    exit 0
fi

if [ $PYTHON_EXITS -eq 1 ]
    then
    PYTHON_VERSION=$(python -V)
else
    PYTHON_VERSION=
fi

cd src

if [ -f $FILE ]
    then
    echo "Tables already created..."
else
    if [ -f $SCRIPT ]
        then
        echo "Python version : $PYTHON_VERSION"
        echo "Building..."
        echo "Creating tables..."
        python script.py                            # Run the script
        echo "Tables created successfully..."
    else
        echo "Fail error: 'script.py' missing."
        echo "Build exiting..."
        exit 0
    fi
fi

if [ -f $MAKEFILE ]
    then
    echo "Running makefile..."
    make                                            # Run the makefile
    echo "Makefile completed..."
else
    echo "Fail error: 'makefile' missing."
    echo "Build exiting..."
    exit 0
fi

echo "Build complete!"
