#!/bin/bash
SCRIPTS_DIR="$(dirname ${0})"

echo "Syntax check for all python code..."
while read f; do
    if ! python -m py_compile "${f}"; then
        echo "Error: Please check ${f} for Python 2 syntax errors"
        exit 1
    fi
    if ! python3 -m py_compile "${f}"; then
        echo "Error: Please check ${f} for Python 3 syntax errors"
        exit 1
    fi
done < <(find "${SCRIPTS_DIR}/cluster-diagnosis" -name "*.py" -prune -type f)
