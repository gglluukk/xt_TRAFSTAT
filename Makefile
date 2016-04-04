EXTRA_CFLAGS := -O3 -march=native

ifneq ($(KERNELRELEASE),)
obj-m += xt_TRAFSTAT.o
else
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
CC := gcc -Wall

default:
	$(MAKE) -Wall -C $(KERNELDIR) M=$(PWD) modules
	$(CC) $(EXTRA_CFLAGS) -fPIC -s -shared -o libxt_TRAFSTAT.so libxt_TRAFSTAT.c

clean:
	@rm -rf *.o *.ko *.mod.c Module.symvers *.mod.gcno modules.order \
		*.so .*.cmd .tmp*

install: uninstall default 
	cp -f libxt_TRAFSTAT.so /usr/lib/xtables/
	cp -f xt_TRAFSTAT.ko \
		/lib/modules/$(shell uname -r)/kernel/net/netfilter/
	if ( ! modinfo xt_TRAFSTAT &> /dev/null ) ; then \
		depmod -a ; fi

uninstall: clean 
	@rmmod xt_TRAFSTAT &> /dev/null &
	@rm -f /usr/lib/xtables/libxt_TRAFSTAT.so &> /dev/null &
	@rm -f /lib/modules/$(shell uname -r)/extra/xt_TRAFSTAT.ko &
	@if ( lsmod | grep -i trafstat ) ; then \
		printf '\n\e[5;31;40mTRAFSTAT module still loaded\e[m\n\n'; fi
endif

