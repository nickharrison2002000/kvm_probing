#!/bin/bash
set -e

# Update and install required packages
sudo apt update
sudo apt install -y make xxd gdb build-essential binutils linux-compiler-gcc-12-x86 linux-kbuild-6.1 wget

# Download kernel headers
wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-common_6.1.90-1_all.deb
wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-amd64_6.1.90-1_amd64.deb
sudo dpkg -i linux-headers-6.1.0-21-common_6.1.90-1_all.deb
sudo dpkg -i linux-headers-6.1.0-21-amd64_6.1.90-1_amd64.deb

# Build C sources
make || true

# Move files and build kernel module
mkdir -p ~/build/kvm_probe
mv kvm_prober.c ~/build/kvm_probe
mv kvm_probe_drv.c ~/build/kvm_probe
mv Makefile ~/build/kvm_probe
cd ~/build/kvm_probe
make
sudo insmod *.ko
sudo cp kvm_prober /usr/bin

# Install Python dependencies
pip install -r requirements.txt
