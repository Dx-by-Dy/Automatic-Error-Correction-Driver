obj-m := correction_driver.o

correction_driver-objs := src/corrdm.o src/bio_helper.o src/locker.o src/trn_p_rq.o src/trn_mw_rq.o src/trn_mr_rq.o

ifdef DM_DEBUG_ENABLED
    ccflags-y += -DDM_DEBUG_ENABLED
endif

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

debug: 
	$(MAKE) -C $(KDIR) M=$(PWD) modules DM_DEBUG_ENABLED=1

# Compiler warnings at W=1, sparse and checkpatch. The project indents with 4 spaces and puts
# opening braces on their own line, so checkpatch's complaints about that are turned off.
CHECKPATCH_IGNORE := LEADING_SPACE,CODE_INDENT,OPEN_BRACE,SUSPECT_CODE_INDENT,SPDX_LICENSE_TAG

check: clean
	$(MAKE) -C $(KDIR) M=$(PWD) W=1 C=1 modules
	perl $(KDIR)/scripts/checkpatch.pl --no-tree --terse --show-types --ignore $(CHECKPATCH_IGNORE) \
		--file src/*.c src/*.h

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean