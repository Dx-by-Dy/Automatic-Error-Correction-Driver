obj-m += ramdisk.o

all:
	make -C /lib/modules/6.16.12-200.fc42.x86_64/build M=$(PWD) modules
    
clean:
	make -C /lib/modules/6.16.12-200.fc42.x86_64/build M=$(PWD) clean