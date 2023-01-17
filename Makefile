EXTRA_CFLAGS := -O2

ifneq ($(KERNELRELEASE),)
obj-m += xt_TRAFSTAT.o
else
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
CC := gcc -Wall
XTABLES_PATH := ${XTABLES_PATH}
ifeq "${XTABLES_PATH}" ""
XTABLES_PATH := `dirname \`find /usr/ -name libipt_REJECT.so | head -1\``
endif

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
	$(CC) $(EXTRA_CFLAGS) -fPIC -s -shared -o libxt_TRAFSTAT.so \
                       libxt_TRAFSTAT.c
ifeq "${XTABLES_PATH}" ""
	@printf '\n\e[5;31;40mERROR: no path for Xtables libraries\e[m\n'
	@echo "export XTABLES_PATH= with proper location"
	@exit
endif

clean:
	rm -rf *.o *.ko *.mod *.mod.c Module.symvers *.mod.gcno modules.order \
		*.so .*.cmd .tmp* .cache.mk

install: uninstall default
	@cp -f libxt_TRAFSTAT.so /${XTABLES_PATH}
	@cp -f xt_TRAFSTAT.ko \
		/lib/modules/$(shell uname -r)/kernel/net/netfilter/
	@if ( ! modinfo xt_TRAFSTAT &> /dev/null ) ; then \
		depmod -a ; fi

uninstall: clean
	-@rmmod xt_TRAFSTAT &> /dev/null
	@rm -f ${XTABLES_PATH}/libxt_TRAFSTAT.so
	@rm -f /lib/modules/$(shell uname -r)/net/netfilter/xt_TRAFSTAT.ko
	@if ( lsmod | grep -i trafstat ) ; then \
		printf '\n\e[5;31;40mTRAFSTAT module still loaded\e[m\n\n'; fi
endif

