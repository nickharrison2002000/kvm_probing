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
#include <asm/io.h>

#define DRIVER_NAME       "kvm_probe_drv"
#define DEVICE_FILE_NAME  "kvm_probe_dev"

#define VQ_PAGE_ORDER     0
#define VQ_PAGE_SIZE      (1UL << (PAGE_SHIFT + VQ_PAGE_ORDER))
#define MAX_COPY_SIZE     4096
#define MAX_VIRTIO_DEVICES 8
#define VIRTIO_NET_DEVICE_ID 1

// Define KVM_HC_VIRTIO_NOTIFY if not available in headers
#ifndef KVM_HC_VIRTIO_NOTIFY
#define KVM_HC_VIRTIO_NOTIFY 6
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

static struct virtio_device_state virtio_devices[MAX_VIRTIO_DEVICES];
static int num_virtio_devices = 0;

// Forward declaration
static struct virtio_device_state *find_virtio_device(unsigned int device_id);

/* IOCTL command definitions (must match prober) */
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

/* Structures (mirror prober) */
struct port_io_data {
    unsigned short port;
    unsigned int   size;
    unsigned int   value;
};
struct mmio_data {
    unsigned long phys_addr;
    unsigned long size;
    unsigned char *user_buffer;
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
    unsigned char *user_buf;
};
struct kvm_kernel_mem_write {
    unsigned long  kernel_addr;
    unsigned long  length;
    unsigned char *user_buf;
};
struct va_scan_data {
    unsigned long  va;
    unsigned long  size;
    unsigned char *user_buffer;
};
struct va_write_data {
    unsigned long  va;
    unsigned long  size;
    unsigned char *user_buffer;
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
    unsigned char *packet_data;
    unsigned int   packet_len;
    unsigned int   device_id;
};

/* Function pointers for set_memory_* that are filled at init time */
typedef int (*set_memory_op_t)(unsigned long, int);
static set_memory_op_t my_set_memory_rw = NULL;
static set_memory_op_t my_set_memory_ro = NULL;

/* Function pointer for kallsyms_lookup_name */
static unsigned long (*my_kallsyms_lookup_name)(const char *name) = NULL;

// Simple address range check
static bool is_valid_kernel_addr(unsigned long addr)
{
    return (addr >= PAGE_OFFSET);
}

// Fallback implementation of virt_to_pfn if not available
#ifndef virt_to_pfn
#define virt_to_pfn(addr) (page_to_pfn(virt_to_page(addr)))
#endif

// Virtqueue callback function
static bool vq_callback(struct virtqueue *vq)
{
    pr_info("%s: Virtqueue callback triggered\n", DRIVER_NAME);
    return true;
}


// Find virtio device by ID
static struct virtio_device_state *find_virtio_device(unsigned int device_id)
{
    int i;
    for (i = 0; i < num_virtio_devices; i++) {
        if (virtio_devices[i].device_id == device_id) {
            return &virtio_devices[i];
        }
    }
    return NULL;
}

// Create a simple network packet
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
    
    // Ethernet header
    eth = (struct ethhdr *)buffer;
    memset(eth->h_dest, 0xff, ETH_ALEN); // broadcast
    memset(eth->h_source, 0x00, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);
    
    // IP header
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
    ip->saddr = in_aton(src_ip);
    ip->daddr = in_aton(dest_ip);
    
    // UDP header
    udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr));
    udp->source = htons(src_port);
    udp->dest = htons(dest_port);
    udp->len = htons(sizeof(struct udphdr) + 10);
    udp->check = 0;
    
    // Payload
    payload = (char *)(buffer + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));
    strncpy(payload, "CTF_PACKET", 10);
    
    *length = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 10;
    return 0;
}

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
        case IOCTL_ALLOC_VQ_PAGE: {
            if (g_vq_virt_addr) { ret = -ENOMEM; break; }
            g_vq_virt_addr = (void*)__get_free_pages(GFP_KERNEL | __GFP_ZERO, VQ_PAGE_ORDER);
            if (!g_vq_virt_addr) { ret = -ENOMEM; break; }
            g_vq_pfn = virt_to_pfn(g_vq_virt_addr);
            g_vq_phys_addr = PFN_PHYS(g_vq_pfn);
            g_vq_gpa = g_vq_phys_addr;
            if (copy_to_user(user_arg, &g_vq_pfn, sizeof(g_vq_pfn))) ret = -EFAULT;
            else ret = 0;
            break;
        }
        case IOCTL_FREE_VQ_PAGE: {
            if (g_vq_virt_addr) {
                free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
                g_vq_virt_addr = NULL;
                g_vq_phys_addr = 0;
                g_vq_pfn = 0;
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
            if (data.index >= VQ_PAGE_SIZE / 16) { ret = -EINVAL; break; } // Assuming 16-byte descriptor size
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
                if (copy_to_user(user_arg, &hypercall_ret, sizeof(hypercall_ret))) ret = -EFAULT;
                else ret= 0;
            } else {
                ret= -EACCES;
            }
            break;
        }
        case IOCTL_READ_KERNEL_MEM: {
            struct kvm_kernel_mem_read r;
            if (copy_from_user(&r, user_arg, sizeof(r))) return -EFAULT;
            if (r.length > MAX_COPY_SIZE || !is_valid_kernel_addr(r.kernel_addr)) {
                return -EINVAL;
            }
            if (copy_to_user(r.user_buf, (const void*)r.kernel_addr, r.length)) return -EFAULT;
            ret = 0;
            break;
        }
        case IOCTL_WRITE_KERNEL_MEM: {
            struct kvm_kernel_mem_write w;
            void *kbuf;
            if (copy_from_user(&w, user_arg, sizeof(w))) return -EFAULT;
            if (w.length > MAX_COPY_SIZE || !is_valid_kernel_addr(w.kernel_addr)) {
                return -EINVAL;
            }
            kbuf = kmalloc(w.length, GFP_KERNEL);
            if (!kbuf) return -ENOMEM;
            if (copy_from_user(kbuf, w.user_buf, w.length)) {
                kfree(kbuf);
                return -EFAULT;
            }
            memcpy((void*)w.kernel_addr, kbuf, w.length);
            kfree(kbuf);
            ret = 0;
            break;
        }
        case IOCTL_PATCH_INSTRUCTIONS: {
            struct va_scan_data req;
            void *kernel_buf;
            if (copy_from_user(&req, user_arg, sizeof(req))) return -EFAULT;
            if (!my_set_memory_rw || !my_set_memory_ro) {
                pr_err("%s: Missing function pointers for set_memory operations\n", DRIVER_NAME);
                return -ENODEV;
            }

            if (!req.user_buffer) {
                return -EINVAL;
            }

            ret = my_set_memory_rw(req.va, 1);
            if (ret) {
                pr_err("%s: set_memory_rw failed: %ld\n", DRIVER_NAME, ret);
                return ret;
            }

            kernel_buf = kmalloc(req.size, GFP_KERNEL);
            if (!kernel_buf) {
                my_set_memory_ro(req.va, 1);
                return -ENOMEM;
            }
            if (copy_from_user(kernel_buf, req.user_buffer, req.size)) {
                ret = -EFAULT;
            } else {
                ret = 0;
            }
            kfree(kernel_buf);

            my_set_memory_ro(req.va, 1);

            break;
        }
        case IOCTL_READ_FLAG_ADDR: {
            if (copy_to_user(user_arg, &g_flag_addr, sizeof(g_flag_addr))) return -EFAULT;
            ret = 0;
            break;
        }
        case IOCTL_WRITE_FLAG_ADDR: {
            if (copy_from_user(&g_flag_addr, user_arg, sizeof(g_flag_addr))) return -EFAULT;
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

            if (copy_to_user(user_arg, &slide, sizeof(slide))) return -EFAULT;
            ret = 0;
            break;
        }
        case IOCTL_VIRT_TO_PHYS: {
            unsigned long virt_addr;
            unsigned long phys_addr;
            if (copy_from_user(&virt_addr, user_arg, sizeof(virt_addr))) return -EFAULT;
            phys_addr = virt_to_phys((void*)virt_addr);
            if (copy_to_user(user_arg, &phys_addr, sizeof(phys_addr))) return -EFAULT;
            ret = 0;
            break;
        }
        case IOCTL_SCAN_VA: {
            struct va_scan_data req;
            void *kernel_buf;
            if (copy_from_user(&req, user_arg, sizeof(req))) return -EFAULT;
            if (req.size > MAX_COPY_SIZE) return -EINVAL;
            kernel_buf = kmalloc(req.size, GFP_KERNEL);
            if (!kernel_buf) return -ENOMEM;
            memcpy(kernel_buf, (void*)req.va, req.size);
            if (copy_to_user(req.user_buffer, kernel_buf, req.size)) ret = -EFAULT;
            else ret = 0;
            kfree(kernel_buf);
            break;
        }
        case IOCTL_WRITE_VA: {
            struct va_write_data req;
            void *kernel_buf;
            if (copy_from_user(&req, user_arg, sizeof(req))) return -EFAULT;
            if (req.size > MAX_COPY_SIZE) return -EINVAL;
            kernel_buf = kmalloc(req.size, GFP_KERNEL);
            if (!kernel_buf) return -ENOMEM;
            if (copy_from_user(kernel_buf, req.user_buffer, req.size)) {
                kfree(kernel_buf);
                return -EFAULT;
            }
            memcpy((void*)req.va, kernel_buf, req.size);
            kfree(kernel_buf);
            ret = 0;
            break;
        }
        case IOCTL_HYPERCALL_ARGS: {
            struct hypercall_args args;
            unsigned long hypercall_ret;
            if (copy_from_user(&args, user_arg, sizeof(args))) return -EFAULT;
            if (allow_untrusted_hypercalls) {
                hypercall_ret = kvm_hypercall4(args.nr, args.arg0, args.arg1, args.arg2, args.arg3);
                if (copy_to_user(user_arg, &hypercall_ret, sizeof(hypercall_ret))) ret = -EFAULT;
                else ret = 0;
            } else {
                ret = -EACCES;
            }
            break;
        }
        case IOCTL_ATTACH_VQ: {
            struct attach_vq_data data;
            struct virtio_device_state *dev_state;
            
            if (copy_from_user(&data, user_arg, sizeof(data))) return -EFAULT;
            
            // Find or create device state
            dev_state = find_virtio_device(data.device_id);
            if (!dev_state) {
                if (num_virtio_devices >= MAX_VIRTIO_DEVICES) {
                    return -ENOSPC;
                }
                dev_state = &virtio_devices[num_virtio_devices++];
                dev_state->device_id = data.device_id;
            }
            
            dev_state->vq_pfn = data.vq_pfn;
            dev_state->queue_index = data.queue_index;
            dev_state->attached = true;
            
            pr_info("%s: Attached virtqueue: device_id=%u, vq_pfn=%lu, queue_index=%u\n",
                   DRIVER_NAME, data.device_id, data.vq_pfn, data.queue_index);
            ret = 0;
            break;
        }
        case IOCTL_TRIGGER_VQ: {
            struct attach_vq_data data;
            struct virtio_device_state *dev_state;
            unsigned long hypercall_ret;
            
            if (copy_from_user(&data, user_arg, sizeof(data))) return -EFAULT;
            
            dev_state = find_virtio_device(data.device_id);
            if (!dev_state || !dev_state->attached) {
                return -ENODEV;
            }
            
            // Trigger hypercall to notify the hypervisor
            hypercall_ret = kvm_hypercall2(KVM_HC_VIRTIO_NOTIFY, data.device_id, dev_state->queue_index);
            
            if (copy_to_user(user_arg, &hypercall_ret, sizeof(hypercall_ret))) ret = -EFAULT;
            else ret = 0;
            break;
        }
        case IOCTL_SCAN_PHYS: {
            struct mmio_data data;
            void __iomem *virt_addr;
            void *kernel_buf;
            
            if (copy_from_user(&data, user_arg, sizeof(data))) return -EFAULT;
            if (data.size > MAX_COPY_SIZE) return -EINVAL;
            
            virt_addr = ioremap(data.phys_addr, data.size);
            if (!virt_addr) return -ENOMEM;
            
            kernel_buf = kmalloc(data.size, GFP_KERNEL);
            if (!kernel_buf) {
                iounmap(virt_addr);
                return -ENOMEM;
            }
            
            memcpy_fromio(kernel_buf, virt_addr, data.size);
            
            if (copy_to_user(data.user_buffer, kernel_buf, data.size)) ret = -EFAULT;
            else ret = 0;
            
            kfree(kernel_buf);
            iounmap(virt_addr);
            break;
        }
        case IOCTL_FIRE_VQ_ALL: {
            int i;
            unsigned long hypercall_ret;
            
            for (i = 0; i < num_virtio_devices; i++) {
                if (virtio_devices[i].attached) {
                    hypercall_ret = kvm_hypercall2(KVM_HC_VIRTIO_NOTIFY, 
                                                 virtio_devices[i].device_id, 
                                                 virtio_devices[i].queue_index);
                    pr_info("%s: Fired virtqueue %d: device_id=%u, ret=%lu\n",
                           DRIVER_NAME, i, virtio_devices[i].device_id, hypercall_ret);
                }
            }
            ret = 0;
            break;
        }
        case IOCTL_SEND_NET_PACKET: {
            struct net_packet_data data;
            unsigned char packet_buffer[1514]; // Standard Ethernet MTU
            unsigned int packet_len = sizeof(packet_buffer);
            
            if (copy_from_user(&data, user_arg, sizeof(data))) return -EFAULT;
            if (data.packet_len > sizeof(packet_buffer)) return -EINVAL;
            
            if (copy_from_user(packet_buffer, data.packet_data, data.packet_len)) return -EFAULT;
            
            // For now, just log the packet
            pr_info("%s: Would send network packet: device_id=%u, len=%u\n",
                   DRIVER_NAME, data.device_id, data.packet_len);
            
            // Trigger virtqueue notification
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
            
            if (copy_from_user(&data, user_arg, sizeof(data))) return -EFAULT;
            
            // Create a sample packet
            packet_len = sizeof(packet_buffer);
            if (create_net_packet(packet_buffer, &packet_len, "10.0.0.1", "10.0.0.2", 1234, 80) < 0) {
                return -EINVAL;
            }
            
            if (copy_to_user(data.packet_data, packet_buffer, packet_len)) return -EFAULT;
            if (copy_to_user(&((struct net_packet_data __user *)user_arg)->packet_len, 
                           &packet_len, sizeof(packet_len))) return -EFAULT;
            
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

static int __init driver_init(void)
{
    int ret;
    unsigned long lookup_addr;

    pr_info("%s: Initializing\n", DRIVER_NAME);

    // Try to get kallsyms_lookup_name
    lookup_addr = kallsyms_lookup_name("kallsyms_lookup_name");
    if (lookup_addr) {
        my_kallsyms_lookup_name = (void *)lookup_addr;
        pr_info("%s: Found kallsyms_lookup_name at %p\n", DRIVER_NAME, my_kallsyms_lookup_name);
    } else {
        pr_warn("%s: kallsyms_lookup_name not found\n", DRIVER_NAME);
    }

    // Try to get set_memory_rw/ro
    lookup_addr = kallsyms_lookup_name("set_memory_rw");
    if (lookup_addr) {
        my_set_memory_rw = (set_memory_op_t)lookup_addr;
        pr_info("%s: Found set_memory_rw at %p\n", DRIVER_NAME, my_set_memory_rw);
    }

    lookup_addr = kallsyms_lookup_name("set_memory_ro");
    if (lookup_addr) {
        my_set_memory_ro = (set_memory_op_t)lookup_addr;
        pr_info("%s: Found set_memory_ro at %p\n", DRIVER_NAME, my_set_memory_ro);
    }

    // Allocate device number
    ret = alloc_chrdev_region(&dev_num, 0, 1, DRIVER_NAME);
    if (ret < 0) {
        pr_err("%s: Failed to allocate device number\n", DRIVER_NAME);
        return ret;
    }

    // Create device class
    dev_class = class_create(THIS_MODULE, DRIVER_NAME);
    if (IS_ERR(dev_class)) {
        pr_err("%s: Failed to create device class\n", DRIVER_NAME);
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(dev_class);
    }

    // Create device
    dev_device = device_create(dev_class, NULL, dev_num, NULL, DEVICE_FILE_NAME);
    if (IS_ERR(dev_device)) {
        pr_err("%s: Failed to create device\n", DRIVER_NAME);
        class_destroy(dev_class);
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(dev_device);
    }

    // Register character device
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

static void __exit driver_exit(void)
{
    int i;

    // Clean up virtqueues
    for (i = 0; i < num_virtio_devices; i++) {
        if (virtio_devices[i].vq) {
            vring_del_virtqueue(virtio_devices[i].vq);
        }
    }

    // Free VQ page if allocated
    if (g_vq_virt_addr) {
        free_pages((unsigned long)g_vq_virt_addr, VQ_PAGE_ORDER);
    }

    // Clean up device
    cdev_del(&cdev);
    device_destroy(dev_class, dev_num);
    class_destroy(dev_class);
    unregister_chrdev_region(dev_num, 1);

    pr_info("%s: Exited\n", DRIVER_NAME);
}

module_init(driver_init);
module_exit(driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CTF Player");
MODULE_DESCRIPTION("KVM Probe Driver for CTF Challenge");
MODULE_VERSION("1.0");