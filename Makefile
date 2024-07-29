KDIR := /lib/modules/$(shell uname -r)/build

PWD := $(shell pwd)

MODULE := tcp_cesar

ifneq ($(MODULE),)
    obj-m := $(MODULE).o
endif

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	rm -rf *.ko *.mod.* .*.cmd *.o
