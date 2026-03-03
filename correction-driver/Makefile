KDIR := /lib/modules/$(shell uname -r)/build
BUILD_DIR := $(CURDIR)/build
SRC_DIR := $(CURDIR)/src

all:
	mkdir -p $(BUILD_DIR)
	echo "obj-m := correction-driver.o" > $(BUILD_DIR)/Makefile
	ln -sf $(SRC_DIR)/correction-driver.c $(BUILD_DIR)/correction-driver.c
	$(MAKE) -C $(KDIR) M=$(BUILD_DIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(BUILD_DIR) clean || true
	rm -rf $(BUILD_DIR)