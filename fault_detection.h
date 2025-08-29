#ifndef FAULT_DETECTION_H
#define FAULT_DETECTION_H

void capture_pre_exploit_state(void);
void capture_post_exploit_state(void);
void monitor_kernel_logs(int duration_seconds);
void detect_system_faults(void);
void save_fault_report(const char *filename);

#endif