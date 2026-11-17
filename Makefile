obj-m := dm-dcorr.o

dm-dcorr-objs := src/dm-dcorr.o src/superblock.o src/bio_helper.o src/trn_p_rq.o src/trn_mw_rq.o src/trn_mr_rq.o src/cache.o src/metadata.o src/written.o

ifdef DM_DEBUG_ENABLED
    ccflags-y += -DDM_DEBUG_ENABLED
endif

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# The driver is built and checked only in the development VM, through deploy/vm.sh: a build on the host
# leaves objects in the tree and checks without the sparse the VM has. dcorrsetup and clean are allowed.
IN_VM := $(shell systemd-detect-virt --vm --quiet 2>/dev/null && echo yes)
ifneq ($(IN_VM),yes)
ifneq ($(filter all debug check,$(or $(MAKECMDGOALS),all)),)
$(error Not in the VM: run deploy/vm.sh check, or deploy/vm.sh test, which builds the driver there)
endif
endif

# dcorrsetup, in userspace. The layout comes from src/dcorr-format.h, shared with the driver.
TOOL := tools/dcorrsetup
TOOL_CFLAGS := -std=gnu11 -O2 -Wall -Wextra -Werror -Isrc

all: $(TOOL)
	$(MAKE) -C $(KDIR) M=$(PWD) modules

tools: $(TOOL)

$(TOOL): tools/dcorrsetup.c src/dcorr-format.h
	cc $(TOOL_CFLAGS) -o $@ tools/dcorrsetup.c

debug: $(TOOL)
	$(MAKE) -C $(KDIR) M=$(PWD) modules DM_DEBUG_ENABLED=1

# Compiler warnings at W=1, sparse and checkpatch. The project indents with 4 spaces and puts
# opening braces on their own line, so checkpatch's complaints about that are turned off.
CHECKPATCH_IGNORE := LEADING_SPACE,CODE_INDENT,OPEN_BRACE,SUSPECT_CODE_INDENT,SPDX_LICENSE_TAG

check: clean
	$(MAKE) -C $(KDIR) M=$(PWD) W=1 C=1 modules
	cc $(TOOL_CFLAGS) -Wpedantic -o $(TOOL) tools/dcorrsetup.c
	perl $(KDIR)/scripts/checkpatch.pl --no-tree --terse --show-types --ignore $(CHECKPATCH_IGNORE) \
		--file src/*.c src/*.h tools/*.c

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f $(TOOL)

.PHONY: all tools debug check clean