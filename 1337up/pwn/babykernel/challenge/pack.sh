#!/bin/bash

# Function to uncompress the initramfs.cpio.gz file
uncompress_initramfs() {
  local file=$1
  if [[ -f "$file" ]]; then
    echo "Uncompressing $file..."
    # First, decompress .gz to .cpio
    gunzip -c "$file" > initramfs.cpio
    # Then, extract the .cpio archive
    mkdir -p initramfs
    cd initramfs || exit
    cpio -id < ../initramfs.cpio
    cd ..
    echo "Uncompression complete. The initramfs is now extracted to the 'initramfs' directory."
  else
    echo "Error: $file not found."
    exit 1
  fi
}

# Function to compress the initramfs.cpio back into .cpio.gz
compress_initramfs() {
  echo "Compressing initramfs back into initramfs.cpio.gz..."
  # First, create the .cpio archive
  cd initramfs || exit
  find . | cpio -o --format=newc > ../initramfs.cpio
  cd ..
  # Then, compress the .cpio file
  gzip initramfs.cpio
  chmod 766 initramfs.cpio.gz
  echo "Compression complete. The new initramfs.cpio.gz is ready."
}

# Main script logic
case $1 in
  "uncompress")
    if [[ -z "$2" ]]; then
      echo "Please provide the initramfs.cpio.gz file to uncompress."
      exit 1
    fi
    uncompress_initramfs "$2"
    ;;
  "compress")
    compress_initramfs
    ;;
  *)
    echo "Usage: $0 {uncompress <initramfs.cpio.gz> | compress}"
    exit 1
    ;;
esac
