#ifndef DESCRIPTOR_TRACKING_H
#define DESCRIPTOR_TRACKING_H

#include <time.h>   /* struct timespec */
#include <stdint.h>

#include "virtio_structs.h"

struct descriptor_state {
    uint16_t desc_index;
    uint64_t addr;
    uint32_t len;
    uint16_t flags;

    struct timespec injection_time;
    struct timespec last_check_time;
    uint16_t initial_avail_idx;
    uint16_t initial_used_idx;
    uint16_t current_used_idx;

    int is_injected;
    int is_processed;
    int is_completed;
};

/* Function signatures updated to handle array of descriptors */
int track_descriptor_injection(uintptr_t virtqueue_addr, uint16_t desc_index, struct virtq_desc desc[]);
int check_descriptor_processing(uintptr_t virtqueue_addr, int timeout_ms);
void monitor_used_ring_changes(uintptr_t virtqueue_addr, int duration_ms);
void dump_descriptor_state(void);

#endif /* DESCRIPTOR_TRACKING_H */

