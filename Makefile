CC = mips-openwrt-linux-gcc

OBJECTS = agent.o common.o
INC_PATH = /home/teddy/trunk/staging_dir/target-mips_34kc_uClibc-0.9.33.2/usr/include/
LB_PATH = /home/teddy/trunk/staging_dir/target-mips_34kc_uClibc-0.9.33.2/usr/lib/
CFLAGS = -Wall -g
LDFLAGS = -lpcap

vap_agent: $(OBJECTS)
	$(CC) -o vap-agent -L$(LB_PATH) -I$(INC_PATH) $(OBJECTS) $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -I$(INC_PATH) -c $*.c

clean:
	rm $(OBJECTS) vap-agent
