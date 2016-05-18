RTE_SDK    ?= $(HOME)/src/dpdk
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

APP = csit-pktgen

SRCS-y := main.c

CFLAGS += -O3 -g -std=gnu11
CFLAGS += $(WERROR_FLAGS)

include $(RTE_SDK)/mk/rte.extapp.mk
