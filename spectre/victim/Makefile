CFLAGS += -std=gnu99 -O0

PROGRAM = victim
SOURCE  = victim.c
     
all: $(PROGRAM)

DEFINITION :=

ifdef SECRET
DEFINITION += -DSECRET=\"$(SECRET)\"
endif
     
$(PROGRAM): $(SOURCE) ; $(CC) $(CFLAGS) $(DEFINITION) -o $(PROGRAM) $(SOURCE)
     
clean: ; rm -f $(PROGRAM)
