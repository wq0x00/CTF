#!/bin/bash

gcc -o exploit -static exploit.c
cp exploit initramfs/home/ctf/.

rm initramfs.cpio.gz

./pack.sh compress

./launch.sh
