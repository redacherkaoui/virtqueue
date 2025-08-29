#ifndef QUEUE_KICKING_H
#define QUEUE_KICKING_H

#include <stdint.h>

void kick_via_pci_io(uint16_t pci_base, uint16_t queue_id);
void kick_queue_mmio(const char *pci_device, uint16_t queue_id);
void kick_via_sysfs(const char *pci_device, uint16_t queue_id);
void kick_via_network_trigger(void);
void kick_via_block_io(void);
void comprehensive_queue_kicking(void);

#endif