/*
 * VirtQueue Logger - Kernel module to log virtqueue base addresses
 * Usage: insmod virtqueue_logger.ko
 *        cat /proc/virtqueue_addrs
 *        rmmod virtqueue_logger
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/virtio.h>
#include <linux/virtio_ring.h>
#include <linux/slab.h>
#include <linux/list.h>

#define PROC_NAME "virtqueue_addrs"

struct virtqueue_info {
    struct list_head list;
    struct virtqueue *vq;
    unsigned long desc_addr;
    unsigned long avail_addr;
    unsigned long used_addr;
    unsigned int queue_index;
    char device_name[32];
};

static LIST_HEAD(virtqueue_list);
static DEFINE_SPINLOCK(virtqueue_lock);
static struct proc_dir_entry *proc_entry;

// Hook into virtqueue creation
static struct virtqueue *(*orig_vring_new_virtqueue)(unsigned int index,
                                                     unsigned int num,
                                                     unsigned int vring_align,
                                                     struct virtio_device *vdev,
                                                     bool weak_barriers,
                                                     bool context,
                                                     void *pages,
                                                     bool (*notify)(struct virtqueue *),
                                                     void (*callback)(struct virtqueue *),
                                                     const char *name);

static struct virtqueue *hooked_vring_new_virtqueue(unsigned int index,
                                                    unsigned int num,
                                                    unsigned int vring_align,
                                                    struct virtio_device *vdev,
                                                    bool weak_barriers,
                                                    bool context,
                                                    void *pages,
                                                    bool (*notify)(struct virtqueue *),
                                                    void (*callback)(struct virtqueue *),
                                                    const char *name)
{
    struct virtqueue *vq;
    struct virtqueue_info *info;

    // Call original function
    vq = orig_vring_new_virtqueue(index, num, vring_align, vdev, weak_barriers,
                                 context, pages, notify, callback, name);

    if (!vq)
        return NULL;

    // Log virtqueue information
    info = kmalloc(sizeof(*info), GFP_KERNEL);
    if (!info)
        return vq; // Continue even if logging fails

    info->vq = vq;

    /*
     * ⚠️ In Linux 6.x, struct vring_virtqueue is no longer exported.
     * We can’t directly access vring internals here.
     * For now, just mark addresses as unavailable.
     */
    info->desc_addr = 0;
    info->avail_addr = 0;
    info->used_addr = 0;
    info->queue_index = index;

    if (name)
        strncpy(info->device_name, name, sizeof(info->device_name) - 1);
    else
        snprintf(info->device_name, sizeof(info->device_name), "queue%u", index);

    spin_lock(&virtqueue_lock);
    list_add_tail(&info->list, &virtqueue_list);
    spin_unlock(&virtqueue_lock);

    printk(KERN_INFO "VirtQueue Logger: %s (index %u)\n", info->device_name, index);
    printk(KERN_INFO "  desc_addr:  (unavailable)\n");
    printk(KERN_INFO "  avail_addr: (unavailable)\n");
    printk(KERN_INFO "  used_addr:  (unavailable)\n");

    return vq;
}

static int virtqueue_proc_show(struct seq_file *m, void *v)
{
    struct virtqueue_info *info;

    seq_printf(m, "VirtQueue Address Information\n");
    seq_printf(m, "=============================\n");
    seq_printf(m, "%-20s %-8s %-16s %-16s %-16s %-16s %-16s %-16s\n",
               "Device", "Queue", "Desc_Virt", "Desc_Phys",
               "Avail_Virt", "Avail_Phys", "Used_Virt", "Used_Phys");

    spin_lock(&virtqueue_lock);
    list_for_each_entry(info, &virtqueue_list, list) {
        seq_printf(m, "%-20s %-8u 0x%-14lx (n/a) 0x%-14lx (n/a) 0x%-14lx (n/a)\n",
                   info->device_name,
                   info->queue_index,
                   info->desc_addr,
                   info->avail_addr,
                   info->used_addr);
    }
    spin_unlock(&virtqueue_lock);

    return 0;
}

static int virtqueue_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, virtqueue_proc_show, NULL);
}

static const struct proc_ops virtqueue_proc_ops = {
    .proc_open = virtqueue_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init virtqueue_logger_init(void)
{
    printk(KERN_INFO "VirtQueue Logger: Module loaded\n");

    // Create /proc entry
    proc_entry = proc_create(PROC_NAME, 0444, NULL, &virtqueue_proc_ops);
    if (!proc_entry) {
        printk(KERN_ERR "VirtQueue Logger: Failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }

    // TODO: Hook vring_new_virtqueue with kprobes if deeper introspection is required
    printk(KERN_INFO "VirtQueue Logger: /proc/%s created\n", PROC_NAME);
    return 0;
}

static void __exit virtqueue_logger_exit(void)
{
    struct virtqueue_info *info, *tmp;

    // Remove /proc entry
    if (proc_entry)
        proc_remove(proc_entry);

    // Clean up virtqueue list
    spin_lock(&virtqueue_lock);
    list_for_each_entry_safe(info, tmp, &virtqueue_list, list) {
        list_del(&info->list);
        kfree(info);
    }
    spin_unlock(&virtqueue_lock);

    printk(KERN_INFO "VirtQueue Logger: Module unloaded\n");
}

module_init(virtqueue_logger_init);
module_exit(virtqueue_logger_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Security Researcher");
MODULE_DESCRIPTION("Log VirtIO virtqueue addresses for exploitation research");
MODULE_VERSION("1.1 (Linux 6.x safe)");

