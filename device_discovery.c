#define _POSIX_C_SOURCE 200809L
#include "device_discovery.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <stdint.h>

// Function declarations
void find_virtio_devices(void);
void find_virtqueues(void);
void examine_virtio_pci(void);
void parse_virtqueue_addresses(void);  // Add this line

// ===== IMPLEMENTATION =====

void find_virtio_devices(void) {
    printf("\n=== VirtIO Device Discovery ===\n");
    
    DIR *virtio_dir = opendir("/sys/bus/virtio/devices");
    if (virtio_dir) {
        printf("Found VirtIO bus at /sys/bus/virtio/devices/\n");
        struct dirent *entry;
        while ((entry = readdir(virtio_dir)) != NULL) {
            if (entry->d_name[0] != '.') {
                printf("  Device: %s\n", entry->d_name);
                
                char path[256], type_str[64];
                snprintf(path, sizeof(path), "/sys/bus/virtio/devices/%s/device", entry->d_name);
                int fd = open(path, O_RDONLY);
                if (fd >= 0) {
                    if (read(fd, type_str, sizeof(type_str)-1) > 0) {
                        type_str[strcspn(type_str, "\n")] = 0;
                        printf("    Type: %s", type_str);
                        
                        int type = strtol(type_str, NULL, 0);
                        switch (type) {
                            case 1: printf(" (Network)"); break;
                            case 2: printf(" (Block)"); break;
                            case 3: printf(" (Console)"); break;
                            case 4: printf(" (Entropy)"); break;
                            case 5: printf(" (Memory Balloon)"); break;
                            case 9: printf(" (9P Transport)"); break;
                            case 16: printf(" (SCSI Host)"); break;
                            case 18: printf(" (Vsock)"); break;
                            default: printf(" (Unknown)"); break;
                        }
                        printf("\n");
                    }
                    close(fd);
                }
            }
        }
        closedir(virtio_dir);
    } else {
        printf("No VirtIO devices found in /sys/bus/virtio/devices/\n");
    }
}

void find_virtqueues(void) {
    printf("\n=== Virtqueue Discovery ===\n");
    
    FILE *interrupts = fopen("/proc/interrupts", "r");
    if (interrupts) {
        char line[512];
        printf("VirtIO interrupts from /proc/interrupts:\n");
        
        while (fgets(line, sizeof(line), interrupts)) {
            if (strstr(line, "virtio") || strstr(line, "vring")) {
                printf("  %s", line);
            }
        }
        fclose(interrupts);
    }
    
    FILE *vmalloc = fopen("/proc/vmallocinfo", "r");
    if (vmalloc) {
        char line[512];
        printf("\nVirtqueue memory regions from /proc/vmallocinfo:\n");
        
        while (fgets(line, sizeof(line), vmalloc)) {
            if (strstr(line, "virtio") || strstr(line, "vring")) {
                printf("  %s", line);
            }
        }
        fclose(vmalloc);
    }

    parse_virtqueue_addresses();
}

void examine_virtio_pci(void) {
    printf("\n=== VirtIO PCI Devices ===\n");
    
    FILE *lspci = popen("lspci | grep -i virtio", "r");
    if (lspci) {
        char line[256];
        printf("PCI VirtIO devices:\n");
        
        while (fgets(line, sizeof(line), lspci)) {
            printf("  %s", line);
        }
        pclose(lspci);
    }
    
    DIR *pci_dir = opendir("/sys/bus/pci/devices");
    if (pci_dir) {
        struct dirent *entry;
        while ((entry = readdir(pci_dir)) != NULL) {
            if (entry->d_name[0] != '.') {
                char vendor_path[256], device_path[256];
                char vendor_id[16], device_id[16];
                
                snprintf(vendor_path, sizeof(vendor_path), "/sys/bus/pci/devices/%s/vendor", entry->d_name);
                snprintf(device_path, sizeof(device_path), "/sys/bus/pci/devices/%s/device", entry->d_name);
                
                int vfd = open(vendor_path, O_RDONLY);
                int dfd = open(device_path, O_RDONLY);
                
                if (vfd >= 0 && dfd >= 0) {
                    if (read(vfd, vendor_id, sizeof(vendor_id)-1) > 0 &&
                        read(dfd, device_id, sizeof(device_id)-1) > 0) {
                        
                        if (strstr(vendor_id, "0x1af4")) {
                            vendor_id[strcspn(vendor_id, "\n")] = 0;
                            device_id[strcspn(device_id, "\n")] = 0;
                            printf("  Found VirtIO PCI device: %s (vendor: %s, device: %s)\n", 
                                   entry->d_name, vendor_id, device_id);
                        }
                    }
                }
                
                if (vfd >= 0) close(vfd);
                if (dfd >= 0) close(dfd);
            }
        }
        closedir(pci_dir);
    }
}

void parse_virtqueue_addresses(void) {
    printf("\n=== Virtqueue Physical Addresses ===\n");
    
    FILE *vq_addrs = fopen("/proc/virtqueue_addrs", "r");
    if (!vq_addrs) {
        printf("Could not open /proc/virtqueue_addrs\n");
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), vq_addrs)) {
        // Expected format: "virtqueue_name gpa:0xXXXXXXXX"
        char vq_name[64];
        uint64_t gpa;
        
        if (sscanf(line, "%63s gpa:%lx", vq_name, &gpa) == 2) {
            printf("  %-20s: GPA 0x%016lx\n", vq_name, gpa);
        }
    }

    fclose(vq_addrs);
}
