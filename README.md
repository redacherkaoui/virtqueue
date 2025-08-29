#  VirtIO Queue Corruption Exploit

This repository contains a working exploit targeting VirtIO queue management via chained descriptor injection. The exploit corrupts the `used` ring structure, triggers device desynchronization, and causes measurable system instability.

---

##  Exploit Summary

- **Target**: VirtIO-net / VirtIO-block devices
- **Method**: Malicious chained descriptors injected into valid virtqueue GPA
- **Trigger**: Queue kicked via PCI I/O, MMIO, and traffic
- **Impact**:
  - `used->idx` ballooned to `44975`
  - Repeated `0xAFAFAFAF` entries in `used` ring
  - +6540 KB memory usage increase
  - Segfaults in `libc.so.6` post-injection

---

## 🔍 Exploitation Flow

1. **Descriptor Chain Construction**
   - Head: 512 bytes, `NEXT | WRITE`
   - Tail: 1MB+, `WRITE`, oversized and misaligned

2. **Injection**
   - Descriptor chain injected into real virtqueue GPA
   - `avail->ring` updated, `avail->idx` incremented

3. **Queue Kick**
   - PCI I/O port write
   - MMIO register access
   - Network traffic trigger

4. **Post-Exploit Observation**
   - `used->flags: 0xAFAF`
   - `used->idx: 44975`
   - Repeated `id=len=2947526575` (`0xAFAFAFAF`)
   - No descriptor tracking match
   - Guard bytes intact (no DMA into abuse buffer)

---

## 🧠 Exploit Interpretation

This exploit demonstrates corruption of VirtIO’s internal queue bookkeeping. The device fails to validate descriptor chain boundaries, leading to overwrite of its own `used` ring structure. While host compromise is not confirmed, the exploit achieves:

- Device-side logic corruption
- Loss of descriptor tracking coherence
- System instability and memory footprint increase

---

## 📉 Limitations

- No confirmed host DMA faults
- No KASAN/UBSAN splats
- Exploit uses `/dev/mem` for direct GPA mapping (outside some threat models)

---

##  Suggested Hardening

- Enforce strict IOMMU boundaries
- Validate descriptor chain lengths in QEMU and kernel drivers
- Disable raw physical access (`CONFIG_STRICT_DEVMEM`)
- Add ring sanity checks for impossible `used->idx` values

---

##  Files

- `exploit.c`: Main exploit logic
- `descriptor_chain.c`: Descriptor construction
- `queue_kick.c`: PCI/MMIO/network triggers
- `feedback.c`: Exploit effectiveness scoring
- `virtqueue_logger.ko`: Optional kernel module for virtqueue state logging

---

## ⚠ Disclaimer

This exploit is released for research and educational purposes only. Use responsibly and only in controlled environments.

