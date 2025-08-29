#ifndef SUBMISSION_METHODS_H
#define SUBMISSION_METHODS_H

#include "virtio_structs.h"

// Function declarations
void try_virtio_net_submission(struct virtq_desc *desc);
void try_virtio_block_submission(struct virtq_desc *desc);
void try_vfio_submission(struct virtq_desc *desc);
void try_direct_memory_submission(struct virtq_desc *desc);

#endif // SUBMISSION_METHODS_H

// ===== IMPLEMENTATION =====

#include "submission_methods.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <linux/vfio.h>
#include <errno.h>

void try_virtio_net_submission(struct virtq_desc *desc) {
    (void)desc; // Silence unused parameter warning
    printf("\n=== Attempting VirtIO-Net Descriptor Submission ===\n");
    
    int netdev_fd = open("/dev/net/tun", O_RDWR);
    if (netdev_fd >= 0) {
        printf("Opened /dev/net/tun (fd=%d)\n", netdev_fd);
        printf("  Could potentially submit descriptors via TAP interface\n");
        close(netdev_fd);
    } else {
        printf("Failed to open /dev/net/tun: %s\n", strerror(errno));
    }
    
    FILE *proc_net = fopen("/proc/net/dev", "r");
    if (proc_net) {
        char line[256];
        printf("\nNetwork interfaces (potential VirtIO targets):\n");
        
        while (fgets(line, sizeof(line), proc_net)) {
            if (strstr(line, "eth") || strstr(line, "ens") || strstr(line, "enp")) {
                char *iface = strtok(line, ":");
                if (iface) {
                    while (*iface == ' ') iface++;
                    printf("  %s (could be VirtIO-net)\n", iface);
                }
            }
        }
        fclose(proc_net);
    }
}

void try_virtio_block_submission(struct virtq_desc *desc) {
    (void)desc; // Silence unused parameter warning
    printf("\n=== Attempting VirtIO-Block Descriptor Submission ===\n");
    
    DIR *block_dir = opendir("/sys/block");
    if (block_dir) {
        struct dirent *entry;
        char dev_path[128]; // Increased buffer size to fix truncation warning
        
        while ((entry = readdir(block_dir)) != NULL) {
            if (strncmp(entry->d_name, "vd", 2) == 0) {
                printf("  Found VirtIO block device: /dev/%s\n", entry->d_name);
                
                snprintf(dev_path, sizeof(dev_path), "/dev/%s", entry->d_name);
                
                int blk_fd = open(dev_path, O_RDWR);
                if (blk_fd >= 0) {
                    printf("    Opened %s (fd=%d)\n", dev_path, blk_fd);
                    printf("    Could submit malicious I/O requests here\n");
                    close(blk_fd);
                } else {
                    printf("    Failed to open %s: %s\n", dev_path, strerror(errno));
                }
            }
        }
        closedir(block_dir);
    }
}

void try_vfio_submission(struct virtq_desc *desc) {
    (void)desc; // Silence unused parameter warning
    printf("\n=== Attempting VFIO-based Descriptor Submission ===\n");
    
    int vfio_fd = open("/dev/vfio/vfio", O_RDWR);
    if (vfio_fd >= 0) {
        printf("VFIO available (/dev/vfio/vfio)\n");
        
        int api_version = ioctl(vfio_fd, VFIO_GET_API_VERSION);
        if (api_version == VFIO_API_VERSION) {
            printf("  API Version: %d (compatible)\n", api_version);
            
            DIR *vfio_dir = opendir("/dev/vfio");
            if (vfio_dir) {
                struct dirent *entry;
                printf("  Available VFIO groups:\n");
                
                while ((entry = readdir(vfio_dir)) != NULL) {
                    if (entry->d_name[0] != '.' && strcmp(entry->d_name, "vfio") != 0) {
                        printf("    Group: %s\n", entry->d_name);
                    }
                }
                closedir(vfio_dir);
            }
        } else {
            printf("  VFIO API version mismatch: got %d, expected %d\n", 
                   api_version, VFIO_API_VERSION);
        }
        
        close(vfio_fd);
    } else {
        printf("VFIO not available: %s\n", strerror(errno));
        printf("  (Normal in most VMs without device passthrough)\n");
    }
}

void try_direct_memory_submission(struct virtq_desc *desc) {
    (void)desc; // Silence unused parameter warning
    printf("\n=== Attempting Direct Memory Manipulation ===\n");
    
    int mem_fd = open("/dev/mem", O_RDWR);
    if (mem_fd >= 0) {
        printf("Opened /dev/mem - direct physical memory access available!\n");
        printf("  WARNING: This could corrupt the system!\n");
        close(mem_fd);
    } else {
        printf("Cannot access /dev/mem: %s\n", strerror(errno));
    }
    
    int kmem_fd = open("/dev/kmem", O_RDWR);
    if (kmem_fd >= 0) {
        printf("Opened /dev/kmem - kernel memory access available!\n");
        close(kmem_fd);
    } else {
        printf("Cannot access /dev/kmem: %s\n", strerror(errno));
        printf("  (Expected on modern systems - /dev/kmem usually disabled)\n");
    }
}

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "submission_methods.h"

void submit_underflow_chain(struct virtqueue *vq, void *guest_hdr, size_t guest_hdr_len) {
    if (!vq || !guest_hdr) {
        printf("submit_underflow_chain: invalid arguments\n");
        return;
    }

    // Construct a fake descriptor chain
    struct virtq_desc desc[2];
    memset(desc, 0, sizeof(desc));

    // Descriptor 0 (header)
    desc[0].addr = (uint64_t)(uintptr_t)guest_hdr;
    desc[0].len = guest_hdr_len;
    desc[0].flags = 0x0003; // NEXT | WRITE
    desc[0].next = 1;

    // Descriptor 1 (oversized abuse buffer)
    desc[1].addr = (uint64_t)(uintptr_t)malloc(1024*1024);
    desc[1].len  = 1024*1024; // 1 MB oversized
    desc[1].flags = 0x0002;   // WRITE
    desc[1].next  = 0;

    printf("=== SUBMITTING UNDERFLOW CHAIN ===\n");
    printf("Descriptor 0: addr=%p len=%zu flags=0x%x next=%u\n",
           (void*)desc[0].addr, (size_t)desc[0].len, desc[0].flags, desc[0].next);
    printf("Descriptor 1: addr=%p len=%zu flags=0x%x next=%u\n",
           (void*)desc[1].addr, (size_t)desc[1].len, desc[1].flags, desc[1].next);

    // Normally you'd push to the virtqueue here.
    // For now, just log it.
    printf("Underflow chain prepared for virtqueue submission.\n");
}
