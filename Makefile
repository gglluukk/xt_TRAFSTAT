CC ?= gcc -Wall
EXTRA_CFLAGS ?= -O2
obj-m += xt_TRAFSTAT.o
KERNEL_VERSION ?= $(shell uname -r)
KERNEL_DIR ?= /lib/modules/$(KERNEL_VERSION)/build
MODULE_PATH ?= /lib/modules/$(KERNEL_VERSION)/kernel/net/netfilter
XTABLES_PATH ?= $(shell dirname $$(find /usr/ -name libipt_REJECT.so \
					 2>/dev/null | head -1) 2> /dev/null)

default:
	@if [ ! -f "$(XTABLES_PATH)/libipt_REJECT.so" ]; then \
		echo "ERROR: wrong path for xtables libraries"; \
		echo "make XTABLES_PATH= with proper location"; \
		exit 1; \
	fi
	@if ! $(MAKE) -C $(KERNEL_DIR) M=$(shell pwd)/ modules ; then \
		echo "ERROR: no kernel headers installed? Try:"; \
		echo "apt install linux-headers-$(KERNEL_VERSION)"; \
		exit 1; \
	fi
	$(CC) $(EXTRA_CFLAGS) -fPIC -s -shared -o libxt_TRAFSTAT.so \
		libxt_TRAFSTAT.c

clean:
	rm -rf *.o *.ko *.mod *.mod.c Module.symvers *.mod.gcno modules.order \
		*.so .*.cmd .tmp* .cache.mk

install: default
	@cp -f libxt_TRAFSTAT.so ${XTABLES_PATH}/
	@cp -f xt_TRAFSTAT.ko ${MODULE_PATH}/
	@echo "Rebuilding module dependencies..."
	@depmod -a $(KERNEL_VERSION)

uninstall:
	@if lsmod | grep -q '^xt_TRAFSTAT'; then \
		echo -n "Unload module xt_TRAFSTAT: "; \
		if ! rmmod xt_TRAFSTAT 2>/dev/null; then \
			echo "FAILED"; \
			iptables-save 2>/dev/null | \
				grep --color=auto TRAFSTAT; \
			lsmod | grep --color=auto xt_TRAFSTAT; \
		else \
			echo "OK"; \
		fi \
	fi
	@echo "Removing helper and module:"
	rm -f ${XTABLES_PATH}/libxt_TRAFSTAT.so
	rm -f ${MODULE_PATH}/xt_TRAFSTAT.ko

.PHONY: default clean install uninstall
