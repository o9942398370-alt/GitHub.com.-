#!/bin/bash
# استفاده: ./sign.sh input.apk output.apk "نام برنامه"
# نیازمند python3 و پکیج cryptography   (pip install cryptography)
# رمز از key.txt خوانده می‌شود
set -e
cd "$(dirname "$0")"
PW=$(grep -m1 'Store password' key.txt | awk '{print $3}')
python3 resign.py "$1" "$2" servers-release.p12 "$PW" "${3:-servers}"
