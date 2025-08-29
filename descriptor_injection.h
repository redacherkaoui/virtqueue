#ifndef DESCRIPTOR_INJECTION_H
#define DESCRIPTOR_INJECTION_H

#include <stdint.h>

void inject_descriptor_with_avail_update(uintptr_t virtqueue_guest_phys_addr, int desc_index);
void locate_virtqueue_in_guest_ram(void);
void find_virtqueue_via_proc_maps(void);

#endif