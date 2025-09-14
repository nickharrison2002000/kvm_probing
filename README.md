
# kvm_probing

## Overview

`kvm_probing` is a toolkit for probing, analyzing, and experimenting with KVM (Kernel-based Virtual Machine) environments. It includes utilities for kernel module probing, host escape testing, and automated exploitation workflows. The project is intended for research, security analysis, and educational purposes related to virtualization and kernel security.

## Features
- Kernel module probing and analysis
- Host escape testing scripts
- Automated exploit runner
- Python utilities for probing and automation

## File Descriptions
- `kvm_probe.c`: C source for probing KVM kernel modules.
- `kvm_probe_drv.c`: C source for a kernel driver used in probing.
- `host_escape.py`: Python script for testing host escape scenarios.
- `prober.py`: Python utility for probing and automation.
- `exploit_runner.sh`: Shell script to automate exploit execution and testing.
- `README.md`: Project documentation.

## Requirements
- Linux system with KVM support
- GCC (for building C sources)
- Linux kernel headers (for building kernel modules)
- Python 3.x
- Root privileges (for kernel module operations)

## Setup

1. **Clone the repository:**
	```bash
	git clone https://github.com/nickharrison2002000/kvm_probing.git
	cd kvm_probing
	```

2. **Install required packages:**
	```bash
	sudo apt update
	sudo apt install -y make xxd gdb build-essential binutils linux-compiler-gcc-12-x86 linux-kbuild-6.1 wget
	wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-common_6.1.90-1_all.deb
	wget -q https://debian.sipwise.com/debian-security/pool/main/l/linux/linux-headers-6.1.0-21-amd64_6.1.90-1_amd64.deb
	sudo dpkg -i linux-headers-6.1.0-21-common_6.1.90-1_all.deb
	sudo dpkg -i linux-headers-6.1.0-21-amd64_6.1.90-1_amd64.deb
	```

3. **Build the C sources:**
	```bash
	gcc -o kvm_probe kvm_probe.c
	gcc -o kvm_probe_drv kvm_probe_drv.c
	```

4. **Move files and build kernel module:**
	```bash
	mkdir -p ~/build/kvm_probe
	mv kvm_prober.c ~/build/kvm_probe
	mv kvm_probe_drv.c ~/build/kvm_probe
	mv Makefile ~/build/kvm_probe
	cd ~/build/kvm_probe
	make
	sudo insmod *.ko
	sudo cp kvm_prober /usr/bin
	```

## Usage
### Kernel Probing
Run the kernel probe utility:
```bash
sudo ./kvm_probe
```

### Host Escape Testing
Run the host escape script:
```bash
sudo python3 host_escape.py
```

### Automated Exploit Runner
Use the shell script to automate exploit tests:
```bash
sudo bash exploit_runner.sh
```

### Prober Utility
Run the prober script for custom probing:
```bash
python3 prober.py
```

## Example
To probe the KVM kernel module and test for vulnerabilities:
```bash
sudo ./kvm_probe
sudo python3 host_escape.py
```

## Author
Nicholas Harrison

---
For more details, see comments in each source file and script.
