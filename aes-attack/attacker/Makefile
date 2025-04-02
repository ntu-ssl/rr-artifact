USRDIR := ../../host-utils
USRSRCS := $(wildcard $(USRDIR)/*.c)
OBJS := $(USRSRCS:.c=.o)

DEFINITION := -mcmodel=medium

ifdef NOCACHE
	DEFINITION += -DNOCACHE=$(NOCACHE)
endif

ifdef SAMPLE_N
	DEFINITION += -DSAMPLE_N=$(SAMPLE_N)
endif

attacker: $(OBJS) attacker.o
	gcc $^ -o $@

%.o: %.c
	gcc -c $< -o $@ $(DEFINITION)

clean:
	rm -f $(OBJS) attacker.o attacker

