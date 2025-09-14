#!/usr/bin/env python3

import os
import sys
import struct
import fcntl
import mmap
import ctypes
import socket
import ipaddress
from enum import IntEnum
from typing import Optional, List, Tuple, Any

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

class VirtioDeviceID(IntEnum):
    NET = 1
    BLOCK = 2
    CONSOLE = 3
    RNG = 4

class Prober:
    def __init__(self, device_path: str = "/dev/kvm_probe_dev"):
        self.device_path = device_path
        self.fd = None
        self.vq_pfn = None
        self.vq_mem = None
        self.flag_addr = 0
        self.virtio_devices = {}
        
    def open(self) -> bool:
        """Open the device file"""
        try:
            self.fd = os.open(self.device_path, os.O_RDWR)
            return True
        except OSError as e:
            print(f"Failed to open device: {e}")
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
        
    def read_port(self, port: int, size: int = 4) -> int:
        """Read from an I/O port"""
        data = PortIOData(port=port, size=size, value=0)
        self._ioctl(IOCTL_READ_PORT, data)
        return data.value
        
    def write_port(self, port: int, value: int, size: int = 4) -> None:
        """Write to an I/O port"""
        data = PortIOData(port=port, size=size, value=value)
        self._ioctl(IOCTL_WRITE_PORT, data)
        
    def read_mmio(self, phys_addr: int, size: int) -> bytes:
        """Read from MMIO region"""
        buf = ctypes.create_string_buffer(size)
        data = MMIOData(phys_addr=phys_addr, size=size, user_buffer=ctypes.addressof(buf), 
                       single_value=0, value_size=0)
        self._ioctl(IOCTL_READ_MMIO, data)
        return bytes(buf)
        
    def write_mmio(self, phys_addr: int, value: int, size: int = 4) -> None:
        """Write to MMIO region"""
        data = MMIOData(phys_addr=phys_addr, size=0, user_buffer=None, 
                       single_value=value, value_size=size)
        self._ioctl(IOCTL_WRITE_MMIO, data)
        
    def alloc_vq_page(self) -> int:
        """Allocate a virtqueue page"""
        pfn = ctypes.c_ulong()
        self._ioctl(IOCTL_ALLOC_VQ_PAGE, ctypes.byref(pfn))
        self.vq_pfn = pfn.value
        return self.vq_pfn
        
    def free_vq_page(self) -> None:
        """Free the virtqueue page"""
        self._ioctl(IOCTL_FREE_VQ_PAGE, 0)
        self.vq_pfn = None
        
    def write_vq_desc(self, index: int, phys_addr: int, length: int, 
                     flags: int = 0, next_idx: int = 0) -> None:
        """Write a virtqueue descriptor"""
        data = VQDescUserData(index=index, phys_addr=phys_addr, len=length,
                             flags=flags, next_idx=next_idx)
        self._ioctl(IOCTL_WRITE_VQ_DESC, data)
        
    def trigger_hypercall(self) -> int:
        """Trigger a hypercall"""
        result = ctypes.c_ulong()
        self._ioctl(IOCTL_TRIGGER_HYPERCALL, ctypes.byref(result))
        return result.value
        
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
        
    def patch_instructions(self, va: int, patch_data: bytes) -> None:
        """Patch kernel instructions"""
        buf = ctypes.create_string_buffer(patch_data)
        data = VAScanData(va=va, size=len(patch_data), user_buffer=ctypes.addressof(buf))
        self._ioctl(IOCTL_PATCH_INSTRUCTIONS, data)
        
    def get_flag_addr(self) -> int:
        """Get flag address"""
        addr = ctypes.c_ulong()
        self._ioctl(IOCTL_READ_FLAG_ADDR, ctypes.byref(addr))
        self.flag_addr = addr.value
        return self.flag_addr
        
    def set_flag_addr(self, addr: int) -> None:
        """Set flag address"""
        self.flag_addr = addr
        self._ioctl(IOCTL_WRITE_FLAG_ADDR, ctypes.c_ulong(addr))
        
    def get_kaslr_slide(self) -> int:
        """Get KASLR slide"""
        slide = ctypes.c_ulong()
        self._ioctl(IOCTL_GET_KASLR_SLIDE, ctypes.byref(slide))
        return slide.value
        
    def virt_to_phys(self, virt_addr: int) -> int:
        """Convert virtual address to physical"""
        phys_addr = ctypes.c_ulong()
        self._ioctl(IOCTL_VIRT_TO_PHYS, ctypes.byref(ctypes.c_ulong(virt_addr)))
        return phys_addr.value
        
    def scan_va(self, va: int, size: int) -> bytes:
        """Scan virtual address space"""
        buf = ctypes.create_string_buffer(size)
        data = VAScanData(va=va, size=size, user_buffer=ctypes.addressof(buf))
        self._ioctl(IOCTL_SCAN_VA, data)
        return bytes(buf)
        
    def write_va(self, va: int, data: bytes) -> None:
        """Write to virtual address"""
        buf = ctypes.create_string_buffer(data)
        write_data = VAWriteData(va=va, size=len(data), user_buffer=ctypes.addressof(buf))
        self._ioctl(IOCTL_WRITE_VA, write_data)
        
    def hypercall_args(self, nr: int, arg0: int = 0, arg1: int = 0, 
                      arg2: int = 0, arg3: int = 0) -> int:
        """Hypercall with arguments"""
        args = HypercallArgs(nr=nr, arg0=arg0, arg1=arg1, arg2=arg2, arg3=arg3)
        result = ctypes.c_ulong()
        self._ioctl(IOCTL_HYPERCALL_ARGS, ctypes.byref(args))
        return result.value
        
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
        
    def scan_phys(self, phys_addr: int, size: int) -> bytes:
        """Scan physical memory"""
        buf = ctypes.create_string_buffer(size)
        data = MMIOData(phys_addr=phys_addr, size=size, user_buffer=ctypes.addressof(buf),
                       single_value=0, value_size=0)
        self._ioctl(IOCTL_SCAN_PHYS, data)
        return bytes(buf)
        
    def fire_all_virtqueues(self) -> None:
        """Trigger all attached virtqueues"""
        self._ioctl(IOCTL_FIRE_VQ_ALL, 0)
        
    def send_net_packet(self, packet_data: bytes, device_id: int = VirtioDeviceID.NET) -> None:
        """Send a network packet through virtio-net"""
        buf = ctypes.create_string_buffer(packet_data)
        data = NetPacketData(packet_data=ctypes.addressof(buf), 
                           packet_len=len(packet_data),
                           device_id=device_id)
        self._ioctl(IOCTL_SEND_NET_PACKET, data)
        
    def recv_net_packet(self, device_id: int = VirtioDeviceID.NET) -> bytes:
        """Receive a network packet through virtio-net"""
        # First get the packet length
        data = NetPacketData(packet_data=None, packet_len=0, device_id=device_id)
        self._ioctl(IOCTL_RECV_NET_PACKET, ctypes.byref(data))
        
        # Now receive the actual packet
        buf = ctypes.create_string_buffer(data.packet_len)
        data.packet_data = ctypes.addressof(buf)
        self._ioctl(IOCTL_RECV_NET_PACKET, ctypes.byref(data))
        
        return bytes(buf)
        
    def create_virtio_net_packet(self, dest_ip: str, dest_port: int, 
                               src_ip: str = "10.0.0.2", src_port: int = 1234,
                               payload: str = "CTF_PACKET") -> bytes:
        """Create a simple network packet"""
        # Ethernet header
        eth_dest = b'\xff\xff\xff\xff\xff\xff'  # broadcast
        eth_src = b'\x00\x00\x00\x00\x00\x00'   # source MAC
        eth_type = b'\x08\x00'                  # IPv4
        
        # IP header
        ip_ver_ihl = 0x45                       # IPv4, 5 words header
        ip_tos = 0
        ip_total_len = 20 + 8 + len(payload)    # IP + UDP + payload
        ip_id = 54321
        ip_frag_off = 0
        ip_ttl = 64
        ip_proto = 17                           # UDP
        ip_check = 0
        ip_src = int(ipaddress.IPv4Address(src_ip))
        ip_dest = int(ipaddress.IPv4Address(dest_ip))
        
        # UDP header
        udp_src = src_port
        udp_dest = dest_port
        udp_len = 8 + len(payload)
        udp_check = 0
        
        # Build packet
        packet = (
            eth_dest + eth_src + eth_type +
            struct.pack('!BBHHHBBHII', 
                       ip_ver_ihl, ip_tos, ip_total_len, ip_id, 
                       ip_frag_off, ip_ttl, ip_proto, ip_check,
                       ip_src, ip_dest) +
            struct.pack('!HHHH', udp_src, udp_dest, udp_len, udp_check) +
            payload.encode()
        )
        
        return packet

def main():
    """Example usage of the prober"""
    with Prober() as prober:
        print("KVM Prober initialized")
        
        # Example: Allocate virtqueue page
        vq_pfn = prober.alloc_vq_page()
        print(f"Allocated VQ page at PFN: 0x{vq_pfn:x}")
        
        # Example: Attach to virtio-net device
        try:
            prober.attach_virtqueue(VirtioDeviceID.NET, vq_pfn, 0)
            print("Attached to virtio-net device")
            
            # Example: Send a network packet
            packet = prober.create_virtio_net_packet("10.0.0.1", 80)
            prober.send_net_packet(packet)
            print("Sent network packet")
            
        except Exception as e:
            print(f"Virtio operations not available: {e}")
        
        # Example: Trigger hypercall
        result = prober.trigger_hypercall()
        print(f"Hypercall result: 0x{result:x}")
        
        # Example: Get KASLR slide
        slide = prober.get_kaslr_slide()
        print(f"KASLR slide: 0x{slide:x}")

if __name__ == "__main__":
    main()