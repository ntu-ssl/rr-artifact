USRDIR := ../../host-utils
USRSRCS := $(wildcard $(USRDIR)/*.c)
OBJS := $(USRSRCS:.c=.o)

DEFINITION :=

ifdef SNP
	DEFINITION += -DSNP=$(SNP)
endif

attacker: $(OBJS) attacker.o
	gcc $^ -o $@

%.o: %.c
	gcc -c $< -o $@

attacker.o: attacker.c
	gcc -c $< -o $@ $(DEFINITION)

clean:
	rm -f $(OBJS) attacker.o attacker

