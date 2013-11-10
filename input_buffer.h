#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define USERBUF_SIZE 8191
#define LINE_BUF 1024

struct line_t {
    char *line_buf;
    struct line_t *next;
};

struct line_queue_t{
    struct line_t *head;
    int count;
};

struct packet_queue_t {
    char *packet;
    char *next;
};

struct user_iobuf {
    char *buf;
    unsigned int cur;
    
    struct line_queue_t *line_queue; // actually, only one line in the queue
};


struct user_iobuf *create_userbuf();
void process_user_input(int fd, struct user_iobuf *userbuf);
void enqueue_line(struct line_queue_t *line_queue, char *buf);
struct line_t *dequeue_line(struct line_queue_t *line_queue);	

void print_queue(struct line_queue_t *line_queue);
	

