#ifndef VIRTIO_STRUCTS_H
#define VIRTIO_STRUCTS_H

#include <stdint.h>

// VirtIO descriptor structure
struct virtq_desc {
    uint64_t addr;   // Buffer physical address (QEMU will translate)
    uint32_t len;    // Buffer length
    uint16_t flags;  // Descriptor flags
    uint16_t next;   // Index of next descriptor (if chained)
};

// VirtIO available ring structure
struct virtq_avail {
    uint16_t flags;
    uint16_t idx;        // Next available descriptor index
    uint16_t ring[];     // Available descriptor indices
};

// VirtIO used ring structure  
struct virtq_used_elem {
    uint32_t id;         // Descriptor index
    uint32_t len;        // Bytes written
};

struct virtq_used {
    uint16_t flags;
    uint16_t idx;
    struct virtq_used_elem ring[];
};

// Common VirtIO descriptor flags
#define VIRTQ_DESC_F_NEXT     1  // Buffer continues in next descriptor
#define VIRTQ_DESC_F_WRITE    2  // Buffer is write-only (device writes, driver reads)
#define VIRTQ_DESC_F_INDIRECT 4  // Buffer contains list of descriptors

// VirtIO PCI configuration offsets
#define VIRTIO_PCI_QUEUE_NOTIFY  16  // Queue notification offset
#define VIRTIO_PCI_STATUS        18  // Device status register
#define VIRTIO_PCI_QUEUE_SEL     14  // Queue selection register
#define VIRTIO_PCI_QUEUE_NUM     12  // Queue size register

// VirtIO status bits
#define VIRTIO_STATUS_ACK        1
#define VIRTIO_STATUS_DRIVER     2
#define VIRTIO_STATUS_DRIVER_OK  4
#define VIRTIO_STATUS_FAILED     128

#endif // VIRTIO_STRUCTS_H