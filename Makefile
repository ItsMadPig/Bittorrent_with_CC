
CC = gcc
CFLAGS = -g -Wall -DDEBUG
LDFAGS = -lm

OBJS = peer.o list.o bt_parse.o debug.o input_buffer.o chunk.o sha.o packet.o spiffy.o ctr_send_recv.o process_udp.o 

BINS = peer list_test

.c.o:
	$(CC) $(CFLAGS) -c $<


all:$(BINS) 

peer: $(OBJS) $(MK_CHUNKS_OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS)

list_test: list.c debug.c
	$(CC) $(CFLAGS) -D_TEST_LIST_ $^ -o $@

ctr_send_recv_test.o: ctr_send_recv.c
	$(CC) $(CFLAGS) -c $^ -D_TEST_CTR_ -o $@

ctr_send_recv_test: ctr_send_recv_test.o debug.o list.o process_udp.o bt_parse.o spiffy.o packet.o chunk.o sha.o
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f $(OBJS) $(BINS)
