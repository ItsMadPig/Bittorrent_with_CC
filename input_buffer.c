#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "input_buffer.h"
#include "debug.h"


struct user_iobuf *create_userbuf() {
    struct user_iobuf *b;
    b = (struct user_iobuf *)calloc(1, sizeof(struct user_iobuf));
    if (!b) {
	DEBUG_PERROR("input_bffer: create_userbuf, user_iobuf");
	return NULL;
    }

    b->buf = (char *)calloc(USERBUF_SIZE + 1, sizeof(char));
    if (!b->buf) {
	free(b);
	DEBUG_PERROR("input_buffer: create_userbuf, buf");
	return NULL;
    }

    b->cur = 0;
    
    b->line_queue = (struct line_queue_t *)calloc(1, sizeof(struct line_queue_t));
    b->line_queue->head = NULL;
    b->line_queue->count = 0;

    //bzero(b->buf, USERBUF_SIZE+1);
    return b;
}

void process_user_input(int fd, struct user_iobuf *userbuf)
{

    assert(userbuf != NULL);

    int nread;
    char *ret;

    nread = read(fd, userbuf->buf + userbuf->cur, 
		 (USERBUF_SIZE - userbuf->cur));

    if (nread == -1) {
	DEBUG_PERROR("Error! process_user_input, read");
	exit(-1);
    }

    userbuf->cur += nread;
    if (userbuf->cur >= USERBUF_SIZE) {
	DEBUG_PERROR("Error! process_user_input, userbuf->cur >= USERBUF_SIZE");
	exit(-1);
    }

    while ((ret = strchr(userbuf->buf, '\n')) != NULL) {
	*ret = '\0';
	DPRINTF(DEBUG_PROCESS_GET, "process_user_input: userbuf->buf:%s\n", userbuf->buf);
	enqueue_line(userbuf->line_queue, userbuf->buf);
	    
	/* Shift the remaining contents of the buffer forward */
	memmove(userbuf->buf, ret + 1, USERBUF_SIZE - (ret - userbuf->buf));
	userbuf->cur -= (ret - userbuf->buf + 1);
	DPRINTF(DEBUG_PROCESS_GET, "process_user_input: buf left:%s\n", userbuf->buf);
    }

    // test line_queue
    if (debug & DEBUG_PROCESS_GET) {
	print_queue(userbuf->line_queue);
    }
}


void enqueue_line(struct line_queue_t *line_queue, char *buf) {
    struct line_t **p;

    if (line_queue->head == NULL) {
	p = &(line_queue->head);
    } else {
	p = &(line_queue->head->next);
	while (*p != NULL)
	    p = &((*p)->next);
    }

    *p = (struct line_t*)calloc(1, sizeof(struct line_t));
    (*p)->line_buf = (char *)calloc(LINE_BUF, sizeof(char));
    (*p)->next = NULL;

    strcpy((*p)->line_buf, buf);
    
    line_queue->count++;
}

struct line_t *dequeue_line(struct line_queue_t *line_queue) {
    assert(line_queue != NULL);

    struct line_t *p = NULL;

    if (line_queue->head == NULL)
	p = NULL;
    else {
	p = line_queue->head;
	line_queue->head = p->next;
    }

    line_queue->count--;

    return p;
}

void print_queue(struct line_queue_t* line_queue){
    int i;
    struct line_t *p;

    printf("print_queue: count:%d\t", line_queue->count);
    
    p = line_queue->head;
    for (i = 0; i < line_queue->count; i++) {
	printf("line:%s\n", p->line_buf);
	p = p->next;
    }

}



#ifdef _TEST_INPUT_BUFFER_

int main(){
    struct user_iobuf *userbuf;
    
    userbuf = create_userbuf();
    process_user_input(STDIN_FILENO, userbuf);    
    
    return 0;
}

#endif
