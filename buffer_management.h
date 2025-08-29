#define _POSIX_C_SOURCE 200809L
#ifndef BUFFER_MANAGEMENT_H
#define BUFFER_MANAGEMENT_H

#include <stddef.h>
#include "virtio_structs.h"

// Global buffer pointers
extern void *normal_buf;
extern void *abuse_buf;
extern void *guard_region;
extern size_t normal_len;
extern size_t abuse_len;

// Function declarations
int allocate_buffers(void);
void cleanup_buffers(void);
void create_descriptors(struct virtq_desc *normal_desc, struct virtq_desc *abuse_desc);

#endif // BUFFER_MANAGEMENT_H
