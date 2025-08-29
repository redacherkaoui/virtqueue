#ifndef DEVICE_DISCOVERY_H
#define DEVICE_DISCOVERY_H

// Function declarations
void find_virtio_devices(void);
void find_virtqueues(void);
void examine_virtio_pci(void);
void parse_virtqueue_addresses(void);

#endif // DEVICE_DISCOVERY_H