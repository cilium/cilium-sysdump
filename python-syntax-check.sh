#!/bin/bash
SCRIPTS_DIR="$(dirname ${0})"

if [ -z "$1" ]
  then
    echo "Please provide the source code folder location."
    echo "Example: ./python-syntax-check.sh SOURCE_DIR"
    exit 1
fi

SOURCE_DIR="$1"

echo "Syntax check for all python code..."
while read f; do
    echo $f
    if ! python -m py_compile "${f}"; then
        echo "Error: Please check ${f} for Python 2 syntax errors"
        exit 1
    fi
    if ! python3 -m py_compile "${f}"; then
        echo "Error: Please check ${f} for Python 3 syntax errors"
        exit 1
    fi
done < <(find "${SOURCE_DIR}" -name "*.py" -prune -type f)
