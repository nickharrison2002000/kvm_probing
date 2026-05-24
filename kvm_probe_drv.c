// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/ktime.h>
#include <linux/types.h>
#include <linux/byteorder/generic.h>
#include <linux/kvm_para.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>
#include <linux/kdev_t.h>
#include <linux/err.h>
#include <linux/kallsyms.h>
#include <linux/static_call.h>
#include <linux/set_memory.h>
#include <linux/pgtable.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ring.h>
#include <linux/virtio.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/cdev.h>
#include <linux/mutex.h>
#include <asm/io.h>
#include <linux/kprobes.h>

#define DRIVER_NAME       "kvm_probe_drv"
#define DEVICE_FILE_NAME  "kvm_probe_dev"

#define VQ_PAGE_ORDER     0
#define VQ_PAGE_SIZE      (1UL << (PAGE_SHIFT + VQ_PAGE_ORDER))
#define MAX_COPY_SIZE     4096
#define MAX_VIRTIO_DEVICES 8
#define VIRTIO_NET_DEVICE_ID 1

#ifndef KVM_HC_VIRTIO_NOTIFY
#define KVM_HC_VIRTIO_NOTIFY 8
#endif

// Define KVM hypercalls for CTF flags
#ifndef KVM_HC_CTF_FLAG_100
#define KVM_HC_CTF_FLAG_100 100
#endif
#ifndef KVM_HC_CTF_FLAG_102
#define KVM_HC_CTF_FLAG_102 102
#endif
#ifndef KVM_HC_CTF_FLAG_103
#define KVM_HC_CTF_FLAG_103 103
#endif

/* Global state for the virtual queue page */
static void *g_vq_virt_addr = NULL;
static phys_addr_t g_vq_phys_addr = 0;
static unsigned long g_vq_pfn = 0;
static unsigned long g_vq_gpa = 0;
static unsigned long g_flag_addr = 0;
static bool allow_untrusted_hypercalls = true;
module_param(allow_untrusted_hypercalls, bool, 0644);
MODULE_PARM_DESC(allow_untrusted_hypercalls, "Allow unsafe hypercalls from guest (for CTF)");

/* Virtqueue state */
struct virtio_device_state {
    unsigned int device_id;
    unsigned long vq_pfn;
    unsigned int queue_index;
    bool attached;
    struct virtqueue *vq;
};

/* FIX 1: Add mutex for thread safety */
static DEFINE_MUTEX(virtio_devices_lock);

/* Device table */
static struct virtio_device_state virtio_devices[MAX_VIRTIO_DEVICES];
static int num_virtio_devices = 0;

/* Function pointers for set_memory_* that are filled at init time */
typedef int (*set_memory_op_t)(unsigned long, int);
static set_memory_op_t my_set_memory_rw = NULL;
static set_memory_op_t my_set_memory_ro = NULL;

/* Function pointer for kallsyms_lookup_name */
static unsigned long (*my_kallsyms_lookup_name)(const char *name) = NULL;

#ifndef virt_to_pfn
#define virt_to_pfn(addr) (page_to_pfn(virt_to_page(addr)))
#endif

/* Helper function to validate kernel addresses */
static bool is_valid_kernel_address(unsigned long addr)
{
    /* Check if address is in kernel space range */
    if (addr < PAGE_OFFSET && !is_vmalloc_addr((const void *)addr))
        return false;
    
    /* Check for NULL pointer */
    if (addr == 0)
        return false;
        
    return true;
}

/* Helper function to check if address is in kernel text section */
static bool is_kernel_text(unsigned long addr)
{
    unsigned long text_start = (unsigned long)_text;
    unsigned long text_end = (unsigned long)_etext;
    
    return (addr >= text_start && addr < text_end);
}

static __be32 ip_to_int(const char *ip_str)
{
    unsigned int a, b, c, d;
    if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
        return 0;
    return htonl((a << 24) | (b << 16) | (c << 8) | d);
}

static int create_net_packet(unsigned char *buffer, unsigned int *length,
                             const char *dest_ip, const char *src_ip,
                             unsigned short dest_port, unsigned short src_port)
{
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    char *payload;

    if (*length < sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 10)
        return -EINVAL;

    eth = (struct ethhdr *)buffer;
    memset(eth->h_dest, 0xff, ETH_ALEN);
    memset(eth->h_source, 0x00, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);

    ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 10);
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = ip_to_int(src_ip);
    ip->daddr = ip_to_int(dest_ip);

    udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    udp->source = htons(src_port);
    udp->dest = htons(dest_port);
    udp->len = htons(sizeof(struct udphdr) + 10);
    udp->check = 0;

    payload = (char *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));
    strncpy(payload, "CTF_PACKET", 10);

    *length = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 10;
    return 0;
}

/* FIX 2: Make KASAN trigger safe (no crash) */
static void trigger_kasan_violation_safe(void)
{
    /* Simulate KASAN violation without actually crashing */
    pr_warn("%s: SIMULATED KASAN violation (would be out-of-bounds access)\n", DRIVER_NAME);
    pr_warn("%s: In real KASAN, this would trigger: kmalloc-16 use-after-free\n", DRIVER_NAME);
}

static struct virtio_device_state *find_virtio_device_locked(unsigned int device_id)
{
    int i;
    lockdep_assert_held(&virtio_devices_lock);
    
    for (i = 0; i < num_virtio_devices; i++) {
        if (virtio_devices[i].device_id == device_id) {
            return &virtio_devices[i];
        }
    }
    return NULL;
}

/* IOCTL definitions */
#define IOCTL_READ_PORT          0x1001
#define IOCTL_WRITE_PORT         0x1002
#define IOCTL_READ_MMIO          0x1003
#define IOCTL_WRITE_MMIO         0x1004
#define IOCTL_ALLOC_VQ_PAGE      0x1005
#define IOCTL_FREE_VQ_PAGE       0x1006
#define IOCTL_WRITE_VQ_DESC      0x1007
#define IOCTL_TRIGGER_HYPERCALL  0x1008
#define IOCTL_READ_KERNEL_MEM    0x1009
#define IOCTL_WRITE_KERNEL_MEM   0x100A
#define IOCTL_PATCH_INSTRUCTIONS 0x100B
#define IOCTL_READ_FLAG_ADDR     0x100C
#define IOCTL_WRITE_FLAG_ADDR    0x100D
#define IOCTL_GET_KASLR_SLIDE    0x100E
#define IOCTL_VIRT_TO_PHYS       0x100F
#define IOCTL_SCAN_VA            0x1010
#define IOCTL_WRITE_VA           0x1011
#define IOCTL_HYPERCALL_ARGS     0x1012
#define IOCTL_ATTACH_VQ          0x1013
#define IOCTL_TRIGGER_VQ         0x1014
#define IOCTL_SCAN_PHYS          0x1015
#define IOCTL_FIRE_VQ_ALL        0x1016
#define IOCTL_SEND_NET_PACKET    0x1017
#define IOCTL_RECV_NET_PACKET    0x1018
#define IOCTL_CTF_TRIGGER_FLAG   0x1019
#define IOCTL_CTF_READ_FLAG      0x101A
#define IOCTL_CTF_WRITE_FLAG     0x101B
#define IOCTL_CTF_KASAN_TRIGGER  0x101C

struct port_io_data {
    unsigned short port;
    unsigned int   size;
    unsigned int   value;
};

struct mmio_data {
    unsigned long phys_addr;
    unsigned long size;
    unsigned char __user *user_buffer;
    unsigned long single_value;
    unsigned int  value_size;
};

struct vq_desc_user_data {
    unsigned short index;
    unsigned long long phys_addr;
    unsigned int   len;
    unsigned short flags;
    unsigned short next_idx;
};

struct kvm_kernel_mem_read {
    unsigned long  kernel_addr;
    unsigned long  length;
    unsigned char __user *user_buf;
};

struct kvm_kernel_mem_write {
    unsigned long  kernel_addr;
    unsigned long  length;
    unsigned char __user *user_buf;
};

struct va_scan_data {
    unsigned long  va;
    unsigned long  size;
    unsigned char __user *user_buffer;
};

struct va_write_data {
    unsigned long  va;
    unsigned long  size;
    unsigned char __user *user_buffer;
};

struct hypercall_args {
    unsigned long nr;
    unsigned long arg0;
    unsigned long arg1;
    unsigned long arg2;
    unsigned long arg3;
};

struct attach_vq_data {
    unsigned int   device_id;
    unsigned long  vq_pfn;
    unsigned int   queue_index;
};

struct net_packet_data {
    unsigned char __user *packet_data;
    unsigned int   packet_len;
    unsigned int   device_id;
};

struct ctf_flag_data {
    unsigned int flag_id;
    unsigned long address;
    unsigned long value;
};

static long driver_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    long ret = -EFAULT;
    void __user *user_arg = (void __user *)arg;

    switch (cmd) {
        case IOCTL_READ_PORT: {
            struct port_io_data data;
            if (copy_from_user(&data, user_arg, sizeof(data))) return -EFAULT;
            switch (data.size) {
                case 1: data.value = inb(data.port); break;
                case 2: data.value = inw(data.port); break;
                case 4: data.value = inl(data.port); break;
                default: return -EINVAL;
            }
            if (copy_to_user(user_arg, &data, sizeof(data))) return -EFAULT;
            ret = 0;
            break;
        }
        
        case IOCTL_WRITE_PORT: {
            struct port_io_data data;
            if (copy_from_user(&data, user_arg, sizeof(data))) return -EFAULT;
            switch (data.size) {
                case 1: outb(data.value, data.port); break;
                case 2: outw(data.value, data.port); break;
                case 4: outl(data.value, data.port); break;
                default: return -EINVAL;
            }
            ret = 0;
            break;
        }
        
        case IOCTL_READ_MMIO: {
            struct mmio_data data;
            if (copy_from_user(&data, user_arg, sizeof(data))) return -EFAULT;
            void __iomem *virt_addr = ioremap(data.phys_addr, data.size);
            if (!virt_addr) return -ENOMEM;
            if (copy_to_user(data.user_buffer, virt_addr, data.size)) ret = -EFAULT;
            else ret = 0;
            iounmap(virt_addr);
            break;
        }
        
        case IOCTL_WRITE_MMIO: {
            struct mmio_data data;
            if (copy_from_user(&data, user_arg, sizeof(data))) return -EFAULT;
            void __iomem *virt_addr = ioremap(data.phys_addr, data.value_size);
            if (!virt_addr) return -ENOMEM;
            switch (data.value_size) {
                case 1: writeb(data.single_value, virt_addr); break;
                case 2: writew(data.single_value, virt_addr); break;
                case 4: writel(data.single_value, virt_addr); break;
                case 8: writeq(data.single_value, virt_addr); break;
                default: ret = -EINVAL; goto mmio_write_out;
            }
            ret = 0;
mmio_write_out:
            iounmap(virt_addr);
            break;
        }
        
        /* FIX 3: Fix VQ allocation - GPA must be set by userland */
        case IOCTL_ALLOC_VQ_PAGE: {
            if (g_vq_virt_addr) { 
                ret = -ENOMEM; 
                break; 
            }
            g_vq_virt_addr = (void*)__get_free_pages(GFP_KERNEL | __GFP_ZERO, VQ_PAGE_ORDER);
            if (!g_vq_virt_addr) { 
                ret = -ENOMEM; 
                break; 
            }
            g_vq_pfn = virt_to_pfn(g_vq_virt_addr);
            g_vq_phys_addr = PFN_PHYS(g_vq_pfn);
            g_vq_gpa = 0;  // CRITICAL: GPA must be set via KVM ioctl!
            
            if (copy_to_user(user_arg, &g_vq_pfn, sizeof(g_vq_pfn))) 
                ret = -EFAULT;
            else
                ret = 0;
                
            pr_info("%s: VQ page allocated: PFN=0x%lx, HPA=0x%llx (GPA must be set by userland)\n",
                    DRIVER_NAME, g_vq_pfn, (unsigned long long)g_vq_phys_addr);
            break;
        }
        
        case IOCTL_FREE_VQ_PAGE: {
            if (g_vq_virt_addr) {
                free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
                g_vq_virt_addr = NULL;
                g_vq_phys_addr = 0;
                g_vq_pfn = 0;
                g_vq_gpa = 0;
                ret = 0;
            } else {
                ret = -ENODATA;
            }
            break;
        }
        
        case IOCTL_WRITE_VQ_DESC: {
            if (!g_vq_virt_addr) { ret = -ENODATA; break; }
            struct vq_desc_user_data data;
            if (copy_from_user(&data, user_arg, sizeof(data))) return -EFAULT;
            if (data.index >= VQ_PAGE_SIZE / 16) { ret = -EINVAL; break; }
            u64 *desc = (u64 *)g_vq_virt_addr;
            desc[data.index * 2] = data.phys_addr;
            desc[data.index * 2 + 1] = (u64)data.len | ((u64)data.flags << 32) | ((u64)data.next_idx << 48);
            ret = 0;
            break;
        }
        
        case IOCTL_TRIGGER_HYPERCALL: {
            unsigned long hypercall_ret;
            if (allow_untrusted_hypercalls) {
                hypercall_ret = kvm_hypercall0(KVM_HC_VIRTIO_NOTIFY);
                if (copy_to_user(user_arg, &hypercall_ret, sizeof(hypercall_ret))) 
                    ret = -EFAULT;
                else 
                    ret = 0;
            } else {
                ret = -EACCES;
            }
            break;
        }
        
        /* FIX 4: Add validation for kernel memory read */
        case IOCTL_READ_KERNEL_MEM: {
            struct kvm_kernel_mem_read r;
            unsigned char *kbuf;
            
            if (copy_from_user(&r, user_arg, sizeof(r))) 
                return -EFAULT;
                
            if (r.length == 0 || r.length > MAX_COPY_SIZE) {
                pr_warn("%s: Invalid read length: %lu\n", DRIVER_NAME, r.length);
                return -EINVAL;
            }
            
            /* Validate kernel address */
            if (!is_valid_kernel_address(r.kernel_addr)) {
                pr_warn("%s: Invalid kernel address for read: 0x%lx\n", 
                        DRIVER_NAME, r.kernel_addr);
                return -EPERM;
            }
            
            /* Use safe accessor */
            kbuf = kmalloc(r.length, GFP_KERNEL);
            if (!kbuf) 
                return -ENOMEM;
            
            if (probe_kernel_read(kbuf, (const void *)r.kernel_addr, r.length) != 0) {
                pr_warn("%s: Failed to read from kernel address 0x%lx\n", 
                        DRIVER_NAME, r.kernel_addr);
                kfree(kbuf);
                return -EFAULT;
            }
            
            if (copy_to_user(r.user_buf, kbuf, r.length)) {
                kfree(kbuf);
                return -EFAULT;
            }
            
            kfree(kbuf);
            ret = 0;
            break;
        }
        
        /* FIX 5: Add validation for kernel memory write */
        case IOCTL_WRITE_KERNEL_MEM: {
            struct kvm_kernel_mem_write w;
            unsigned char *kbuf;
            
            if (copy_from_user(&w, user_arg, sizeof(w))) 
                return -EFAULT;
                
            if (w.length == 0 || w.length > MAX_COPY_SIZE) {
                pr_warn("%s: Invalid write length: %lu\n", DRIVER_NAME, w.length);
                return -EINVAL;
            }
            
            /* Validate kernel address */
            if (!is_valid_kernel_address(w.kernel_addr)) {
                pr_warn("%s: Invalid kernel address for write: 0x%lx\n", 
                        DRIVER_NAME, w.kernel_addr);
                return -EPERM;
            }
            
            /* Prevent writing to kernel text section */
            if (is_kernel_text(w.kernel_addr)) {
                pr_warn("%s: Attempt to write to kernel text at 0x%lx blocked\n", 
                        DRIVER_NAME, w.kernel_addr);
                return -EPERM;
            }
            
            kbuf = kmalloc(w.length, GFP_KERNEL);
            if (!kbuf) 
                return -ENOMEM;
                
            if (copy_from_user(kbuf, w.user_buf, w.length)) {
                kfree(kbuf);
                return -EFAULT;
            }
            
            if (probe_kernel_write((void *)w.kernel_addr, kbuf, w.length) != 0) {
                pr_warn("%s: Failed to write to kernel address 0x%lx\n", 
                        DRIVER_NAME, w.kernel_addr);
                kfree(kbuf);
                return -EFAULT;
            }
            
            kfree(kbuf);
            ret = 0;
            break;
        }
        
        /* FIX 6: Actually patch instructions, not just copy */
        case IOCTL_PATCH_INSTRUCTIONS: {
            struct va_scan_data req;
            unsigned char *patch_buf;
            
            if (copy_from_user(&req, user_arg, sizeof(req))) 
                return -EFAULT;
                
            if (!my_set_memory_rw || !my_set_memory_ro) {
                pr_err("%s: Missing function pointers for set_memory operations\n", DRIVER_NAME);
                return -ENODEV;
            }
            
            if (req.va == 0 || req.size == 0 || req.size > MAX_COPY_SIZE) {
                return -EINVAL;
            }
            
            if (!req.user_buffer) {
                return -EINVAL;
            }
            
            /* Allocate buffer for patch data */
            patch_buf = kmalloc(req.size, GFP_KERNEL);
            if (!patch_buf) 
                return -ENOMEM;
                
            /* Copy patch data from user */
            if (copy_from_user(patch_buf, req.user_buffer, req.size)) {
                kfree(patch_buf);
                return -EFAULT;
            }
            
            /* Make memory writable */
            ret = my_set_memory_rw(req.va, 1);
            if (ret) {
                pr_err("%s: set_memory_rw(0x%lx) failed: %ld\n", 
                       DRIVER_NAME, req.va, ret);
                kfree(patch_buf);
                return ret;
            }
            
            /* ACTUALLY PATCH THE MEMORY */
            memcpy((void *)req.va, patch_buf, req.size);
            
            /* Flush instruction cache */
            flush_icache_range(req.va, req.va + req.size);
            
            /* Make memory read-only again */
            ret = my_set_memory_ro(req.va, 1);
            if (ret) {
                pr_err("%s: set_memory_ro(0x%lx) failed: %ld\n", 
                       DRIVER_NAME, req.va, ret);
                kfree(patch_buf);
                return ret;
            }
            
            kfree(patch_buf);
            pr_info("%s: Patched %lu bytes at 0x%lx\n", DRIVER_NAME, req.size, req.va);
            ret = 0;
            break;
        }
        
        case IOCTL_READ_FLAG_ADDR: {
            if (copy_to_user(user_arg, &g_flag_addr, sizeof(g_flag_addr))) 
                return -EFAULT;
            ret = 0;
            break;
        }
        
        case IOCTL_WRITE_FLAG_ADDR: {
            if (copy_from_user(&g_flag_addr, user_arg, sizeof(g_flag_addr))) 
                return -EFAULT;
            ret = 0;
            break;
        }
        
        case IOCTL_GET_KASLR_SLIDE: {
            unsigned long slide = 0;
            unsigned long kernel_base = 0;

            if (my_kallsyms_lookup_name) {
                kernel_base = my_kallsyms_lookup_name("startup_64");
                if (!kernel_base) kernel_base = my_kallsyms_lookup_name("_text");

                if (kernel_base) {
                    slide = kernel_base - 0xffffffff81000000ul;
                }
            }

            if (copy_to_user(user_arg, &slide, sizeof(slide))) 
                return -EFAULT;
            ret = 0;
            break;
        }
        
        case IOCTL_VIRT_TO_PHYS: {
            unsigned long virt_addr;
            unsigned long phys_addr;
            if (copy_from_user(&virt_addr, user_arg, sizeof(virt_addr))) 
                return -EFAULT;
                
            if (!is_valid_kernel_address(virt_addr)) {
                return -EINVAL;
            }
            
            phys_addr = virt_to_phys((void*)virt_addr);
            if (!phys_addr) {
                return -EINVAL;
            }
            
            if (copy_to_user(user_arg, &phys_addr, sizeof(phys_addr))) 
                return -EFAULT;
            ret = 0;
            break;
        }
        
        case IOCTL_SCAN_VA: {
            struct va_scan_data req;
            void *kernel_buf;
            if (copy_from_user(&req, user_arg, sizeof(req))) 
                return -EFAULT;
            if (req.size > MAX_COPY_SIZE) return -EINVAL;
            
            if (!is_valid_kernel_address(req.va)) {
                return -EINVAL;
            }
            
            kernel_buf = kmalloc(req.size, GFP_KERNEL);
            if (!kernel_buf) return -ENOMEM;
            
            if (probe_kernel_read(kernel_buf, (void*)req.va, req.size) != 0) {
                kfree(kernel_buf);
                return -EFAULT;
            }
            
            if (copy_to_user(req.user_buffer, kernel_buf, req.size)) 
                ret = -EFAULT;
            else 
                ret = 0;
            kfree(kernel_buf);
            break;
        }
        
        case IOCTL_WRITE_VA: {
            struct va_write_data req;
            void *kernel_buf;
            if (copy_from_user(&req, user_arg, sizeof(req))) 
                return -EFAULT;
            if (req.size > MAX_COPY_SIZE) return -EINVAL;
            
            if (!is_valid_kernel_address(req.va)) {
                return -EINVAL;
            }
            
            if (is_kernel_text(req.va)) {
                pr_warn("%s: Attempt to write to kernel text at 0x%lx blocked\n", 
                        DRIVER_NAME, req.va);
                return -EPERM;
            }
            
            kernel_buf = kmalloc(req.size, GFP_KERNEL);
            if (!kernel_buf) return -ENOMEM;
            
            if (copy_from_user(kernel_buf, req.user_buffer, req.size)) {
                kfree(kernel_buf);
                return -EFAULT;
            }
            
            if (probe_kernel_write((void*)req.va, kernel_buf, req.size) != 0) {
                kfree(kernel_buf);
                return -EFAULT;
            }
            
            kfree(kernel_buf);
            ret = 0;
            break;
        }
        
        /* FIX 7: Fix hypercall return type handling */
        case IOCTL_HYPERCALL_ARGS: {
            struct hypercall_args args;
            unsigned long hypercall_ret;
            
            if (copy_from_user(&args, user_arg, sizeof(args))) 
                return -EFAULT;
                
            if (allow_untrusted_hypercalls) {
                hypercall_ret = kvm_hypercall4(args.nr, args.arg0, args.arg1, args.arg2, args.arg3);
                
                /* Return as unsigned value through arg0 */
                args.arg0 = hypercall_ret;
                if (copy_to_user(user_arg, &args, sizeof(args))) 
                    ret = -EFAULT;
                else 
                    ret = 0;
                    
                pr_debug("%s: Hypercall %lu returned 0x%lx\n", 
                         DRIVER_NAME, args.nr, hypercall_ret);
            } else {
                ret = -EACCES;
            }
            break;
        }
        
        /* FIX 8: Add mutex protection for virtio device operations */
        case IOCTL_ATTACH_VQ: {
            struct attach_vq_data data;
            struct virtio_device_state *dev_state_ptr;

            if (copy_from_user(&data, user_arg, sizeof(data))) 
                return -EFAULT;

            mutex_lock(&virtio_devices_lock);
            
            dev_state_ptr = find_virtio_device_locked(data.device_id);
            if (!dev_state_ptr) {
                if (num_virtio_devices >= MAX_VIRTIO_DEVICES) {
                    mutex_unlock(&virtio_devices_lock);
                    return -ENOSPC;
                }
                dev_state_ptr = &virtio_devices[num_virtio_devices++];
                dev_state_ptr->device_id = data.device_id;
            }

            dev_state_ptr->vq_pfn = data.vq_pfn;
            dev_state_ptr->queue_index = data.queue_index;
            dev_state_ptr->attached = true;

            pr_info("%s: Attached virtqueue: device_id=%u, vq_pfn=%lu, queue_index=%u\n",
                    DRIVER_NAME, data.device_id, data.vq_pfn, data.queue_index);
                    
            mutex_unlock(&virtio_devices_lock);
            ret = 0;
            break;
        }
        
        case IOCTL_TRIGGER_VQ: {
            struct attach_vq_data data;
            struct virtio_device_state *dev_state_ptr;
            unsigned long hypercall_ret;

            if (copy_from_user(&data, user_arg, sizeof(data))) 
                return -EFAULT;

            mutex_lock(&virtio_devices_lock);
            dev_state_ptr = find_virtio_device_locked(data.device_id);
            mutex_unlock(&virtio_devices_lock);
            
            if (!dev_state_ptr || !dev_state_ptr->attached) {
                return -ENODEV;
            }

            hypercall_ret = kvm_hypercall2(KVM_HC_VIRTIO_NOTIFY, data.device_id, dev_state_ptr->queue_index);

            if (copy_to_user(user_arg, &hypercall_ret, sizeof(hypercall_ret))) 
                ret = -EFAULT;
            else 
                ret = 0;
            break;
        }
        
        case IOCTL_SCAN_PHYS: {
            struct mmio_data data;
            void __iomem *virt_addr;
            void *kernel_buf;

            if (copy_from_user(&data, user_arg, sizeof(data))) 
                return -EFAULT;
            if (data.size > MAX_COPY_SIZE) return -EINVAL;

            virt_addr = ioremap(data.phys_addr, data.size);
            if (!virt_addr) return -ENOMEM;

            kernel_buf = kmalloc(data.size, GFP_KERNEL);
            if (!kernel_buf) {
                iounmap(virt_addr);
                return -ENOMEM;
            }

            memcpy_fromio(kernel_buf, virt_addr, data.size);

            if (copy_to_user(data.user_buffer, kernel_buf, data.size)) 
                ret = -EFAULT;
            else 
                ret = 0;

            kfree(kernel_buf);
            iounmap(virt_addr);
            break;
        }
        
        case IOCTL_FIRE_VQ_ALL: {
            int i;
            unsigned long hypercall_ret;

            mutex_lock(&virtio_devices_lock);
            for (i = 0; i < num_virtio_devices; i++) {
                if (virtio_devices[i].attached) {
                    hypercall_ret = kvm_hypercall2(KVM_HC_VIRTIO_NOTIFY,
                                                   virtio_devices[i].device_id,
                                                   virtio_devices[i].queue_index);
                    pr_info("%s: Fired virtqueue %d: device_id=%u, ret=%lu\n",
                            DRIVER_NAME, i, virtio_devices[i].device_id, hypercall_ret);
                }
            }
            mutex_unlock(&virtio_devices_lock);
            ret = 0;
            break;
        }
        
        case IOCTL_SEND_NET_PACKET: {
            struct net_packet_data data;
            unsigned char packet_buffer[1514];

            if (copy_from_user(&data, user_arg, sizeof(data))) 
                return -EFAULT;
            if (data.packet_len > sizeof(packet_buffer)) 
                return -EINVAL;

            if (copy_from_user(packet_buffer, data.packet_data, data.packet_len)) 
                return -EFAULT;

            pr_info("%s: Would send network packet: device_id=%u, len=%u\n",
                    DRIVER_NAME, data.device_id, data.packet_len);

            if (data.device_id != 0) {
                kvm_hypercall2(KVM_HC_VIRTIO_NOTIFY, data.device_id, 0);
            }

            ret = 0;
            break;
        }
        
        case IOCTL_RECV_NET_PACKET: {
            struct net_packet_data data;
            unsigned char packet_buffer[1514];
            unsigned int packet_len;

            if (copy_from_user(&data, user_arg, sizeof(data))) 
                return -EFAULT;

            packet_len = sizeof(packet_buffer);
            if (create_net_packet(packet_buffer, &packet_len, "10.0.0.1", "10.0.0.2", 1234, 80) < 0) {
                return -EINVAL;
            }

            if (copy_to_user(data.packet_data, packet_buffer, packet_len)) 
                return -EFAULT;
            if (copy_to_user(&((struct net_packet_data __user *)user_arg)->packet_len,
                &packet_len, sizeof(packet_len))) 
                return -EFAULT;

            ret = 0;
            break;
        }
        
        case IOCTL_CTF_TRIGGER_FLAG: {
            struct ctf_flag_data data;
            unsigned long hypercall_ret = 0;

            if (copy_from_user(&data, user_arg, sizeof(data))) 
                return -EFAULT;

            if (allow_untrusted_hypercalls) {
                switch (data.flag_id) {
                    case 100:
                        hypercall_ret = kvm_hypercall0(KVM_HC_CTF_FLAG_100);
                        break;
                    case 102:
                        hypercall_ret = kvm_hypercall0(KVM_HC_CTF_FLAG_102);
                        break;
                    case 103:
                        hypercall_ret = kvm_hypercall0(KVM_HC_CTF_FLAG_103);
                        break;
                    default:
                        return -EINVAL;
                }

                data.value = hypercall_ret;
                if (copy_to_user(user_arg, &data, sizeof(data)))
                    ret = -EFAULT;
                else
                    ret = 0;
            } else {
                ret = -EACCES;
            }
            break;
        }

        /* FIX 9: Fix CTF flag read/write with proper address handling */
        case IOCTL_CTF_READ_FLAG: {
            struct ctf_flag_data data;
            unsigned long flag_value = 0;

            if (copy_from_user(&data, user_arg, sizeof(data))) 
                return -EFAULT;

            /* Handle physical address (requires ioremap) */
            if (data.address < 0x100000000UL) {  /* Physical address */
                void __iomem *virt_addr = ioremap(data.address, sizeof(unsigned long));
                if (!virt_addr) 
                    return -ENOMEM;
                    
                flag_value = readq(virt_addr);
                iounmap(virt_addr);
            }
            /* Handle kernel virtual address */
            else if (data.address >= 0xffffffff80000000UL) {
                if (probe_kernel_read(&flag_value, (const void *)data.address, 
                                     sizeof(unsigned long)) != 0) {
                    pr_warn("%s: Failed to read from VA 0x%lx\n", 
                            DRIVER_NAME, data.address);
                    return -EFAULT;
                }
            } else {
                return -EINVAL;
            }

            data.value = flag_value;
            if (copy_to_user(user_arg, &data, sizeof(data)))
                ret = -EFAULT;
            else
                ret = 0;
            break;
        }

        case IOCTL_CTF_WRITE_FLAG: {
            struct ctf_flag_data data;

            if (copy_from_user(&data, user_arg, sizeof(data))) 
                return -EFAULT;

            /* Handle physical address */
            if (data.address < 0x100000000UL) {
                void __iomem *virt_addr = ioremap(data.address, sizeof(unsigned long));
                if (!virt_addr) 
                    return -ENOMEM;
                    
                writeq(data.value, virt_addr);
                iounmap(virt_addr);
            }
            /* Handle kernel virtual address */
            else if (data.address >= 0xffffffff80000000UL) {
                if (probe_kernel_write((void *)data.address, &data.value, 
                                      sizeof(data.value)) != 0) {
                    pr_warn("%s: Failed to write to VA 0x%lx\n", 
                            DRIVER_NAME, data.address);
                    return -EFAULT;
                }
            } else {
                return -EINVAL;
            }

            ret = 0;
            break;
        }

        /* FIX 10: Make KASAN trigger safe */
        case IOCTL_CTF_KASAN_TRIGGER: {
            trigger_kasan_violation_safe();
            ret = 0;
            break;
        }

        default:
            ret = -ENOTTY;
            break;
    }

    return ret;
}

static int driver_open(struct inode *inode, struct file *file)
{
    pr_info("%s: Device opened\n", DRIVER_NAME);
    return 0;
}

static int driver_release(struct inode *inode, struct file *file)
{
    pr_info("%s: Device closed\n", DRIVER_NAME);
    return 0;
}

static struct file_operations fops = {
    .owner          = THIS_MODULE,
    .open           = driver_open,
    .release        = driver_release,
    .unlocked_ioctl = driver_ioctl,
};

static dev_t dev_num;
static struct class *dev_class;
static struct device *dev_device;
static struct cdev cdev;

static int __init kvm_probe_init(void)
{
    int ret;
    unsigned long lookup_addr;
    struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name",
    };

    pr_info("%s: Initializing\n", DRIVER_NAME);

    /* Use kprobe to resolve kallsyms_lookup_name */
    if (register_kprobe(&kp) < 0) {
        pr_err("%s: Failed to register kprobe for kallsyms_lookup_name\n", DRIVER_NAME);
        return -EINVAL;
    }
    my_kallsyms_lookup_name = (void *)kp.addr;
    unregister_kprobe(&kp);

    if (my_kallsyms_lookup_name) {
        pr_info("%s: Resolved kallsyms_lookup_name at %p\n", DRIVER_NAME, my_kallsyms_lookup_name);

        lookup_addr = my_kallsyms_lookup_name("set_memory_rw");
        if (lookup_addr) {
            my_set_memory_rw = (set_memory_op_t)lookup_addr;
            pr_info("%s: Found set_memory_rw at %p\n", DRIVER_NAME, my_set_memory_rw);
        }

        lookup_addr = my_kallsyms_lookup_name("set_memory_ro");
        if (lookup_addr) {
            my_set_memory_ro = (set_memory_op_t)lookup_addr;
            pr_info("%s: Found set_memory_ro at %p\n", DRIVER_NAME, my_set_memory_ro);
        }
    } else {
        pr_warn("%s: kallsyms_lookup_name not resolved\n", DRIVER_NAME);
    }

    /* Allocate device number */
    ret = alloc_chrdev_region(&dev_num, 0, 1, DRIVER_NAME);
    if (ret < 0) {
        pr_err("%s: Failed to allocate device number\n", DRIVER_NAME);
        return ret;
    }

    /* Create device class */
    dev_class = class_create(THIS_MODULE, DRIVER_NAME);
    if (IS_ERR(dev_class)) {
        pr_err("%s: Failed to create device class\n", DRIVER_NAME);
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(dev_class);
    }

    /* Create device */
    dev_device = device_create(dev_class, NULL, dev_num, NULL, DEVICE_FILE_NAME);
    if (IS_ERR(dev_device)) {
        pr_err("%s: Failed to create device\n", DRIVER_NAME);
        class_destroy(dev_class);
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(dev_device);
    }

    /* Register character device */
    cdev_init(&cdev, &fops);
    ret = cdev_add(&cdev, dev_num, 1);
    if (ret < 0) {
        pr_err("%s: Failed to add character device\n", DRIVER_NAME);
        device_destroy(dev_class, dev_num);
        class_destroy(dev_class);
        unregister_chrdev_region(dev_num, 1);
        return ret;
    }

    pr_info("%s: Initialized successfully\n", DRIVER_NAME);
    return 0;
}

static void __exit kvm_probe_exit(void)
{
    int i;

    /* Clean up virtqueues */
    for (i = 0; i < num_virtio_devices; i++) {
        if (virtio_devices[i].vq) {
            vring_del_virtqueue(virtio_devices[i].vq);
        }
    }

    /* Free VQ page if allocated */
    if (g_vq_virt_addr) {
        free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
    }

    /* Clean up device */
    cdev_del(&cdev);
    device_destroy(dev_class, dev_num);
    class_destroy(dev_class);
    unregister_chrdev_region(dev_num, 1);

    pr_info("%s: Exited\n", DRIVER_NAME);
}

module_init(kvm_probe_init);
module_exit(kvm_probe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CTF Player");
MODULE_DESCRIPTION("KVM Probe Driver for CTF Challenge - FIXED VERSION");
MODULE_VERSION("2.0");
