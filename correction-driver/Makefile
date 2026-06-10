obj-m := correction_driver.o

correction_driver-objs := src/correction-driver.o src/bio_helper.o src/transformation.o src/locker.o src/alignment.o src/transformation_part.o src/transformation_meta.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean