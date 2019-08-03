CC=gcc

OBJS = VulnAgent.o
TARGETS = VulnAgent
FILENAME = VulnAgent.c
CFLAGS = -I. `net-snmp-config --cflags`
BUILDLIBS = `net-snmp-config --libs`
BUILDAGENTLIBS = `net-snmp-config --agent-libs`

all: $(TARGETS)

BUG: $(OBJS)
  $(CC) $(CFLAGS) -o $(TARGETS) $(FILENAME) $(BUILDLIBS) $(BUILDAGENTLIBS)
clean:
  rm $(OBJS) $(TARGETS)