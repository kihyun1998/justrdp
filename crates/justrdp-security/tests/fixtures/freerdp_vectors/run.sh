#!/bin/sh
# Regenerates vectors.txt. Needs gcc, libssl-dev and gh. Run from this directory.
set -eu
COMMIT=9e9f2148e8512295ada764757ed5030b77b77817
gh api "repos/FreeRDP/FreeRDP/contents/libfreerdp/core/security.c?ref=$COMMIT" --jq .content | base64 -d > security.c.orig
sed '/^#include/d; /^#define TAG/d' security.c.orig > security_body.c
gcc -w -O1 -I. harness.c -o harness -lcrypto
./harness > vectors.txt
rm -f harness security_body.c security.c.orig
