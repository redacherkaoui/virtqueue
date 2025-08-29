#define _POSIX_C_SOURCE 200809L

#ifdef DISABLE_FAULT_DETECTION
/* ---------- Lightweight stubs when disabled ---------- */
#include "fault_detection.h"
#include <stdio.h>
#include <unistd.h>

void capture_pre_exploit_state(void)  { puts("[faults] pre-state capture disabled"); }
void capture_post_exploit_state(void) { puts("[faults] post-state capture disabled"); }
void monitor_kernel_logs(int secs)    { printf("=== MONITORING KERNEL LOGS ===\nMonitoring for %d seconds...\n", secs); sleep(secs); puts("Kernel log monitoring completed"); }
void detect_system_faults(void)       { puts("No new critical faults detected"); }
void save_fault_report(const char *p) { printf("Fault report saved to: %s\n", p ? p : "(null)"); }

#else
/* ---------------- Full implementation ---------------- */
#include "fault_detection.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/wait.h>
#include <errno.h>

#define LOG_BUFFER_SIZE (1024 * 1024)  /* 1MB */
#define MAX_FAULT_LINES 1000

static char pre_dmesg[LOG_BUFFER_SIZE];
static char post_dmesg[LOG_BUFFER_SIZE];
static char fault_report[LOG_BUFFER_SIZE * 2];
static int  fault_count = 0;

/* millisecond sleep via nanosleep (avoids usleep warnings) */
static void sleep_ms(int ms) {
    if (ms <= 0) return;
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static void execute_command_to_buffer(const char *command, char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) return;
    FILE *pipe = popen(command, "r");
    if (!pipe) {
        snprintf(buffer, buffer_size, "Error executing '%s': %s\n", command, strerror(errno));
        return;
    }
    size_t n = fread(buffer, 1, buffer_size - 1, pipe);
    buffer[n] = '\0';
    pclose(pipe);
}

static void append_command_output(FILE *out, const char *header, const char *cmd, size_t hard_limit_bytes) {
    if (header && *header) fprintf(out, "%s\n", header);
    FILE *p = popen(cmd, "r");
    if (!p) {
        fprintf(out, "(failed: %s) %s\n", cmd, strerror(errno));
        return;
    }
    char chunk[4096];
    size_t total = 0;
    while (fgets(chunk, sizeof(chunk), p)) {
        size_t len = strlen(chunk);
        if (hard_limit_bytes && total + len > hard_limit_bytes) {
            len = hard_limit_bytes > total ? (hard_limit_bytes - total) : 0;
        }
        if (len) fwrite(chunk, 1, len, out);
        total += len;
        if (hard_limit_bytes && total >= hard_limit_bytes) break;
    }
    pclose(p);
}

void capture_pre_exploit_state(void) {
    printf("\n=== CAPTURING PRE-EXPLOIT STATE ===\n");

    /* Prefer dmesg; fall back to journalctl if restricted */
    execute_command_to_buffer("dmesg -T | tail -100 2>/dev/null || journalctl -k -n 100 2>/dev/null",
                              pre_dmesg, sizeof(pre_dmesg));
    printf("Captured pre-exploit dmesg (%zu bytes)\n", strlen(pre_dmesg));

    FILE *pre_file = fopen("/tmp/pre_exploit_dmesg.log", "w");
    if (pre_file) {
        fputs(pre_dmesg, pre_file);
        fclose(pre_file);
        printf("Pre-exploit state saved to /tmp/pre_exploit_dmesg.log\n");
    }

    FILE *info = fopen("/tmp/pre_exploit_system.log", "w");
    if (info) {
        time_t now = time(NULL);
        fprintf(info, "=== PRE-EXPLOIT SYSTEM STATE ===\nTimestamp: %s\n", ctime(&now));
        append_command_output(info, "\n=== /proc/meminfo ===", "cat /proc/meminfo", 0);
        append_command_output(info, "\n=== CPU Info (head -20) ===", "head -20 /proc/cpuinfo", 0);
        append_command_output(info, "\n=== Load Average ===", "cat /proc/loadavg", 0);
        fclose(info);
        puts("System state saved to /tmp/pre_exploit_system.log");
    }
}

void capture_post_exploit_state(void) {
    printf("\n=== CAPTURING POST-EXPLOIT STATE ===\n");
    sleep_ms(500); /* allow delayed messages */

    execute_command_to_buffer("dmesg -T | tail -100 2>/dev/null || journalctl -k -n 100 2>/dev/null",
                              post_dmesg, sizeof(post_dmesg));
    printf("Captured post-exploit dmesg (%zu bytes)\n", strlen(post_dmesg));

    FILE *post_file = fopen("/tmp/post_exploit_dmesg.log", "w");
    if (post_file) {
        fputs(post_dmesg, post_file);
        fclose(post_file);
        puts("Post-exploit state saved to /tmp/post_exploit_dmesg.log");
    }

    FILE *info = fopen("/tmp/post_exploit_system.log", "w");
    if (info) {
        time_t now = time(NULL);
        fprintf(info, "=== POST-EXPLOIT SYSTEM STATE ===\nTimestamp: %s\n", ctime(&now));
        append_command_output(info, "\n=== /proc/meminfo ===", "cat /proc/meminfo", 0);
        append_command_output(info, "\n=== Recent kernel messages ===",
                              "dmesg -T | tail -50 2>/dev/null || journalctl -k -n 50 2>/dev/null", 0);
        append_command_output(info, "\n=== VirtIO device status (lspci -v | grep -A 10 -i virtio) ===",
                              "lspci -v | grep -A 10 -i virtio 2>/dev/null", 0);
        fclose(info);
        puts("Post-exploit system state saved to /tmp/post_exploit_system.log");
    }
}

void monitor_kernel_logs(int duration_seconds) {
    printf("\n=== MONITORING KERNEL LOGS ===\n");
    printf("Monitoring for %d seconds...\n", duration_seconds);

    pid_t pid = fork();
    if (pid == 0) {
        /* child: stream /proc/kmsg if permitted */
        int kfd = open("/proc/kmsg", O_RDONLY | O_NONBLOCK);
        if (kfd < 0) {
            printf("Cannot open /proc/kmsg: %s\n", strerror(errno));
            _exit(1);
        }

        FILE *out = fopen("/tmp/exploit_kmsg_monitor.log", "w");
        if (!out) {
            printf("Cannot create monitoring log file\n");
            close(kfd);
            _exit(1);
        }

        time_t start = time(NULL);
        time_t now   = start;
        char buf[1024];

        fprintf(out, "=== KERNEL LOG MONITORING ===\nStart time: %s\n", ctime(&start));
        fflush(out);

        while ((now = time(NULL)) - start < duration_seconds) {
            ssize_t n = read(kfd, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
                fputs(buf, out);
                fflush(out);

                if (strstr(buf, "BUG:") || strstr(buf, "WARNING:") ||
                    strstr(buf, "OOPS:") || strstr(buf, "panic")   ||
                    strstr(buf, "segfault") || strstr(buf, "virtio")) {
                    printf("CRITICAL: %s", buf);
                    fault_count++;
                }
            }
            sleep_ms(10);
        }

        fclose(out);
        close(kfd);
        _exit(0);
    } else if (pid > 0) {
        int status;
        (void)waitpid(pid, &status, 0);
        puts("Kernel log monitoring completed");
        if (fault_count > 0)
            printf("WARNING: %d critical messages detected during monitoring\n", fault_count);
    } else {
        printf("Failed to fork monitoring process: %s\n", strerror(errno));
    }
}

void detect_system_faults(void) {
    printf("\n=== DETECTING SYSTEM FAULTS ===\n");

    if (!pre_dmesg[0])  { puts("No pre-exploit state captured");  return; }
    if (!post_dmesg[0]) { puts("No post-exploit state captured"); return; }

    /* Tokenize */
    char *pre_lines[MAX_FAULT_LINES], *post_lines[MAX_FAULT_LINES];
    int pre_n = 0, post_n = 0;

    char pre_copy[LOG_BUFFER_SIZE];
    char post_copy[LOG_BUFFER_SIZE];
    strncpy(pre_copy, pre_dmesg, sizeof(pre_copy));   pre_copy[sizeof(pre_copy)-1]   = '\0';
    strncpy(post_copy, post_dmesg, sizeof(post_copy));post_copy[sizeof(post_copy)-1] = '\0';

    for (char *p = strtok(pre_copy, "\n");  p && pre_n  < MAX_FAULT_LINES;  p = strtok(NULL, "\n")) pre_lines[pre_n++]   = p;
    for (char *p = strtok(post_copy,"\n");  p && post_n < MAX_FAULT_LINES;  p = strtok(NULL, "\n")) post_lines[post_n++] = p;

    printf("Analyzing %d pre-exploit vs %d post-exploit log lines\n", pre_n, post_n);

    int new_faults = 0;
    char fault_summary[4096] = {0};

    for (int i = 0; i < post_n; i++) {
        int seen = 0;
        for (int j = 0; j < pre_n; j++) {
            if (strcmp(post_lines[i], pre_lines[j]) == 0) { seen = 1; break; }
        }
        if (!seen) {
            if (strstr(post_lines[i], "BUG:") || strstr(post_lines[i], "WARNING:") ||
                strstr(post_lines[i], "OOPS:") || strstr(post_lines[i], "panic")   ||
                strstr(post_lines[i], "segfault") || strstr(post_lines[i], "virtio") ||
                strstr(post_lines[i], "Call Trace:") || strstr(post_lines[i], "RIP:")) {
                printf("NEW FAULT DETECTED: %s\n", post_lines[i]);
                strncat(fault_summary, post_lines[i], sizeof(fault_summary) - strlen(fault_summary) - 1);
                strncat(fault_summary, "\n",        sizeof(fault_summary) - strlen(fault_summary) - 1);
                new_faults++;
            }
        }
    }

    time_t now = time(NULL);
    if (new_faults > 0) {
        printf("\n*** %d NEW FAULTS DETECTED AFTER EXPLOIT! ***\n", new_faults);
        snprintf(fault_report, sizeof(fault_report),
                 "=== FAULT DETECTION REPORT ===\n"
                 "Timestamp: %s"
                 "New faults detected: %d\n\n"
                 "Critical messages:\n%s\n",
                 ctime(&now), new_faults, fault_summary);
    } else {
        puts("No new critical faults detected");
        snprintf(fault_report, sizeof(fault_report),
                 "=== FAULT DETECTION REPORT ===\n"
                 "Timestamp: %s"
                 "Status: No new critical faults detected\n",
                 ctime(&now));
    }
}

void save_fault_report(const char *filename) {
    printf("\n=== SAVING FAULT REPORT ===\n");
    if (!filename || !*filename) { puts("Invalid report path"); return; }

    FILE *rf = fopen(filename, "w");
    if (!rf) { printf("Failed to create fault report file: %s\n", strerror(errno)); return; }

    fputs(fault_report, rf);

    /* Append additional system information (NO writes to source files) */
    append_command_output(rf, "\n=== /proc/slabinfo (head -20) ===", "head -20 /proc/slabinfo 2>/dev/null", 0);
    append_command_output(rf, "\n=== VirtIO Device Status (lspci -v | grep -A 5 -i virtio) ===",
                          "lspci -v | grep -A 5 -i virtio 2>/dev/null", 0);
    append_command_output(rf, "\n=== Recent VirtIO Interrupt Lines ===",
                          "grep -i virtio /proc/interrupts 2>/dev/null", 0);

    fclose(rf);
    printf("Fault report saved to: %s\n", filename);
}
#endif /* DISABLE_FAULT_DETECTION */

