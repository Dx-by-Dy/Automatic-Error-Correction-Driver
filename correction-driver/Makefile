obj-m := correction_driver.o

correction_driver-objs := src/corrdm.o src/bio_helper.o src/trn_rq.o src/locker.o src/trn_p_rq.o src/trn_mw_rq.o src/trn_mr_rq.o

ifdef DM_DEBUG_ENABLED
    ccflags-y += -DDM_DEBUG_ENABLED
endif

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

debug: 
	$(MAKE) -C $(KDIR) M=$(PWD) modules DM_DEBUG_ENABLED=1

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean