CC = gcc
CFLAGS = -Wall -Wextra -O2 -g -pthread
TARGET = netstack
OBJS = main.o net_common.o ethernet.o arp.o ipv4.o icmp.o udp.o tcp.o tftp.o http.o dns.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean