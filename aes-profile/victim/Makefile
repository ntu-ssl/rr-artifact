DEFINITION :=

ifdef N_profile
	DEFINITION += -DN_profile=$(N_profile)
endif

ifdef NOCACHE
	DEFINITION += -DNOCACHE=$(NOCACHE)
endif


all:
	gcc victim.c -o victim -L/root/rr-artifact/openssl-1.1.0l -lcrypto -I/root/rr-artifact/openssl-1.1.0l/include $(DEFINITION)
