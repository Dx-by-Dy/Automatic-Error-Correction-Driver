obj-m := correction_driver.o

correction_driver-objs := src/corrdm.o src/bio_helper.o src/trn_rq.o src/locker.o src/trn_p_rq.o src/trn_mw_rq.o src/trn_mr_rq.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean