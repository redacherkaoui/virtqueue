# VirtIO Advanced Security Research Tool Makefile

CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c99
LDFLAGS = -lrt

SOURCES = main.c buffer_management.c device_discovery.c submission_methods.c \
          descriptor_injection.c queue_kicking.c descriptor_tracking.c \
          fault_detection.c exploit_feedback.c

OBJECTS = $(SOURCES:.c=.o)

TARGET = virtio_exploit_advanced

MODULE_DIR = kernel_module
MODULE_NAME = virtqueue_logger

all: $(TARGET) kernel_module

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Build kernel module (optional)
kernel_module:
	@echo "Building kernel module (optional)..."
	@mkdir -p $(MODULE_DIR)
	@cp virtqueue_logger.c $(MODULE_DIR)/
	@echo "obj-m += $(MODULE_NAME).o" > $(MODULE_DIR)/Makefile
	@cd $(MODULE_DIR) && $(MAKE) -C /lib/modules/$(shell uname -r)/build M=$$(pwd) modules || echo "⚠️ Kernel module skipped (missing headers?)"

clean:
	rm -f $(OBJECTS) $(TARGET)
	rm -rf $(MODULE_DIR)

# Install binary + kernel module
install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/
	@if [ -f $(MODULE_DIR)/$(MODULE_NAME).ko ]; then \
		echo "Installing kernel module..."; \
		if lsmod | grep -q $(MODULE_NAME); then \
			echo "Module already loaded, unloading..."; \
			sudo rmmod $(MODULE_NAME) || true; \
		fi; \
		sudo mkdir -p /lib/modules/`uname -r`/extra; \
		sudo cp $(MODULE_DIR)/$(MODULE_NAME).ko /lib/modules/`uname -r`/extra/; \
		sudo depmod -a; \
		echo "Kernel module installed to /lib/modules/`uname -r`/extra/"; \
	else \
		echo "⚠️  Kernel module not built, skipping install"; \
	fi

uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)
	sudo rm -f /lib/modules/`uname -r`/extra/$(MODULE_NAME).ko
	sudo depmod -a 2>/dev/null || true

debug: CFLAGS += -g -DDEBUG
debug: clean $(TARGET)

analyze: $(SOURCES)
	cppcheck --enable=all $(SOURCES)

run: $(TARGET)
	sudo ./$(TARGET)

load_module:
	@if [ -f $(MODULE_DIR)/$(MODULE_NAME).ko ]; then \
		sudo insmod $(MODULE_DIR)/$(MODULE_NAME).ko; \
		echo "Kernel module loaded"; \
	else \
		echo "Kernel module not found - run 'make kernel_module' first"; \
	fi

unload_module:
	sudo rmmod $(MODULE_NAME) 2>/dev/null || echo "Module not loaded"

help:
	@echo "VirtIO Advanced Security Research Tool Build System"
	@echo "Available targets:"
	@echo "  all           - Build main executable and kernel module (default)"
	@echo "  kernel_module - Build only the kernel module (optional)"
	@echo "  clean         - Remove build artifacts"
	@echo "  debug         - Build with debug symbols"
	@echo "  install       - Install binary and kernel module (sudo required)"
	@echo "  uninstall     - Remove installed files (sudo required)"
	@echo "  analyze       - Run static analysis with cppcheck"
	@echo "  run           - Build and run with sudo"
	@echo "  load_module   - Load the virtqueue logger kernel module"
	@echo "  unload_module - Unload the virtqueue logger kernel module"
	@echo "  help          - Show this help message"

.PHONY: all clean install uninstall debug analyze run kernel_module load_module unload_module help
