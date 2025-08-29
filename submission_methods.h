#ifndef SUBMISSION_METHODS_H
#define SUBMISSION_METHODS_H

#include "virtio_structs.h"

/* Existing submission methods */
void try_virtio_net_submission(struct virtq_desc *desc);
void try_virtio_block_submission(struct virtq_desc *desc);
void try_vfio_submission(struct virtq_desc *desc);
void try_direct_memory_submission(struct virtq_desc *desc);

/* New underflow chain submission method */
void submit_underflow_chain(void *vq, void *guest_hdr, size_t guest_hdr_len);

#endif // SUBMISSION_METHODS_H
