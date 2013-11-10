/*
 * peer.c
 *
 * Authors: Ed Bardsley <ebardsle+441@andrew.cmu.edu>,
 *          Dave Andersen
 * Class: 15-441 (Spring 2005)
 *
 * Skeleton for 15-441 Project 2.
 *
 */

#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "list.h"
#include "debug.h"
#include "spiffy.h"
#include "bt_parse.h"
#include "input_buffer.h"
#include "packet.h"
#include "process_udp.h"
#include "ctr_send_recv.h"

time_t global_time;

void peer_run(bt_config_t *config);

int main(int argc, char **argv) {
    bt_config_t config;

    bt_init(&config, argc, argv); 

    DPRINTF(DEBUG_INIT, "peer.c main beginning\n");
    
    time(&global_time);

#ifdef TESTING
    config.identity = 1; // your group number here
    strcpy(config.chunk_file, "chunkfile");
    strcpy(config.has_chunk_file, "haschunks");
#endif

    bt_parse_command_line(&config);

#ifdef DEBUG
    printf("debug:%x\n", debug);
    if (debug & DEBUG_INIT) {
	bt_dump_config(&config);
    }
#endif
  
    peer_run(&config);

    return 0;
}


struct list_t *exclude_self(bt_peer_t *all_nodes, short self_id) {
    struct list_t *peer_list = NULL;
    bt_peer_t *p;
    int found = 0;
    
    init_list(&peer_list);

    p = all_nodes;
    while (p != NULL) {
	if (p->id != self_id)
	    enlist(peer_list, p);
	else 
	    found = 1;

	p = p->next;
    }
    
    if (!found) 
	DPRINTF(DEBUG_PEER, "Warning! exlucde_self, id:%d, not in the peer list\n", self_id);
    
    return peer_list;
}


void id_hash_printer(void *data) {
    assert(data != NULL);
    struct id_hash_t *p = NULL;

    p = (struct id_hash_t *)data;

    printf("id_hash: %d, %s\n", p->id, p->hash_string);
}

// parse has_chunk_file, get a list of id and hash_string
void parse_haschunkfile(bt_config_t *config) {

    FILE *fp;
    int buf_size = 1024;
    char buf[buf_size];
    int id;
    char *hash_string;
    struct id_hash_t *id_hash;
    
    if ((fp = fopen(config->has_chunk_file, "r")) == NULL) {
	DPRINTF(DEBUG_PEER, "Error! add_info, open");
	exit(-1);
    }
    
    memset(buf, 0, buf_size);
    while (fgets(buf, buf_size, fp) != NULL) {
	if (feof(fp))
	    break;

	//DPRINTF(DEBUG_PEER, "add_info, fgets:%s", buf);
	
	hash_string = (char *)calloc(HASH_STR_LEN+1, sizeof(char));
	sscanf(buf, "%d %s", &id, hash_string);
	
	id_hash = (struct id_hash_t *)calloc(1, sizeof(struct id_hash_t));
	id_hash->id = id;
	id_hash->hash_string = hash_string;

	enlist(config->id_hash_list, id_hash);

	memset(buf, 0, buf_size);
    }
    if (debug & DEBUG_PEER) {
	printf("\nparse_hashchunkfile: config->id_hash_list:\n");
	dump_list(config->id_hash_list, id_hash_printer, "\n");
	printf("\n");
    }
    

}





struct GET_request_t *handle_GET_request(char *chunkfile, char *outputfile, struct list_t *peer_list) {
    assert(chunkfile != NULL);
    assert(outputfile != NULL);
    assert(peer_list != NULL);

    struct GET_request_t *GET_request = NULL;
    struct list_t  *WHOHAS_info_list = NULL;

    DPRINTF(DEBUG_PEER, "handle_GET_request:\n");
    DPRINTF(DEBUG_PEER, "chunkfile:%s, outputfile:%s\n\n", chunkfile, outputfile);

    init_GET_request(&GET_request);

    if (parse_chunkfile(GET_request, chunkfile) != 0)
	return NULL;

    // a list of WHOHAS pakcet_info
    WHOHAS_info_list = make_WHOHAS_packet_info(GET_request, peer_list);

    if (debug & DEBUG_PEER) {
	printf("WHOHAS_info_list:\n");
	//dump_packet_info_list(WHOHAS_info_list);
	dump_list(WHOHAS_info_list, info_printer, "\n");
    }

    GET_request->outbound_info_list = WHOHAS_info_list; // no need to enlist

    assert(outputfile != NULL);
    GET_request->output_file = (char *)calloc(strlen(outputfile), sizeof(char)) + 1;
    memcpy(GET_request->output_file, outputfile, strlen(outputfile));
    
    return GET_request;
}

struct GET_request_t *handle_line(struct line_queue_t *line_queue, struct list_t *peer_list) {

    struct GET_request_t *GET_request;
    char chunkf[128], outf[128];
    struct line_t *line_p;

    if (line_queue->count == 0) {
	DPRINTF(DEBUG_PACKET, "handle_line: line_queue->count is 0\n");
	return NULL;
    }

    // count == 1
    if (line_queue->count > 1) {
	DPRINTF(DEBUG_PACKET, "Warning! handle_line: line_queue->count is %d, >1, only first GET request will be handled\n", line_queue->count);
    }

    line_p= dequeue_line(line_queue);
    if (line_p == NULL) {
	DPRINTF(DEBUG_PROCESS_GET, "hanlde_lie: handle_line, dequeue_line returns NULL\n");
	return NULL;
    }

    DPRINTF(DEBUG_PROCESS_GET, "handle_line:\n%s\n", line_p->line_buf);

    if (strlen(line_p->line_buf) != 0) {
	if (sscanf(line_p->line_buf, "GET %120s %120s", chunkf, outf) == 2) {

	    GET_request = handle_GET_request(chunkf, outf, peer_list);

	} else {
	    DPRINTF(DEBUG_PEER, "Error! wrong input format\n");
	    return NULL;
	}

	free(line_p);

	bzero(chunkf, sizeof(chunkf));
	bzero(outf, sizeof(outf));
	return GET_request;
    }

    return NULL;
}


void peer_run(bt_config_t *config) {
    int sock;
    //int max_fd;
    int nfds;
    struct sockaddr_in myaddr;
    fd_set master_readfds, master_writefds;
    fd_set readfds, writefds;
    struct user_iobuf *userbuf = NULL;
    struct GET_request_t *GET_request = NULL;
    struct list_t *reply_list = NULL;
    struct packet_info_t *recv_info = NULL;
    

    //cp2:
    //struct peer_to_slot_t *peer_to_slot = NULL;
    struct list_t *peer_list = NULL;
    struct list_t *GET_list = NULL;
    
    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
	perror("peer_run could not create socket");
	exit(-1);
    }
  
    bzero(&myaddr, sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    myaddr.sin_port = htons(config->myport);
    
    if (bind(sock, (struct sockaddr *) &myaddr, sizeof(myaddr)) == -1) {
	perror("peer_run could not bind socket");
	exit(-1);
    }
  
    spiffy_init(config->identity, (struct sockaddr *)&myaddr, sizeof(myaddr));

    FD_ZERO(&master_readfds);
    FD_ZERO(&master_writefds);

    FD_SET(STDIN_FILENO, &master_readfds);
    FD_SET(sock, &master_readfds);

    //    max_fd = sock;
    //if (STDIN_FILENO > sock)
    //max_fd = STDIN_FILENO;

    // all sorts of preparation
    parse_haschunkfile(config);
    init_ctr();

    peer_list = exclude_self(config->peers, config->identity);
    DPRINTF(DEBUG_PEER, "peer_list:");
    dump_list(peer_list, peer_printer, " ");
    
    userbuf = create_userbuf();

    while (1) {

	readfds = master_readfds;
	writefds = master_writefds;
    
	nfds = select(sock+1, &readfds, &writefds, NULL, NULL);
    
	if (nfds > 0) {

	    // read user input, "GET chunkfile newfile"
	    if (FD_ISSET(STDIN_FILENO, &readfds)) {
		// read user input, there might be several GETs, and there might several inputs
		DPRINTF(DEBUG_PEER, "stdin, read\n");
		process_user_input(STDIN_FILENO, userbuf); 

		// handle the GET requests already read, set sock in master_writefds 
		// there is only one GET request
		if ((GET_request = handle_line(userbuf->line_queue, peer_list)) != NULL) {
		    
		    //ctr_enlist(GET_request->outbound_info_list);
		    outbound_list_cat(GET_request->outbound_info_list);

		    FD_SET(sock, &master_writefds); 

		} else {
		    DPRINTF(DEBUG_PACKET, "peer: nothing to handle\n");
		}

		//check_out_size();
	    }

	    // all five kinds of packets
	    if (FD_ISSET(sock, &readfds)) { 

		DPRINTF(DEBUG_PEER, "sock, read\n");
		DPRINTF(DEBUG_PEER, "try general_recv:\n");

		if ((recv_info = general_recv(sock, config)) != NULL) {
		    
		    reply_list = process_inbound_udp(recv_info, sock, config, GET_request);
		    // if reply_info == NULL, no need to reply
		    if (reply_list != NULL && reply_list->length != 0) {
			DPRINTF(DEBUG_PEER, "Peer: reply_list is not null or empty, ");
			if (general_list_cat(reply_list) != 0)
			    DEBUG_PERROR("Error! peer: general_list_cat\n");
		    } 
		    // null reply_info might be the result of IHAVE, DATA packet, still need to write
		    FD_SET(sock, &master_writefds);

		}

		// check if GET_request has slot finished download
		GET_list = check_GET_req(&GET_request, peer_list);
		outbound_list_cat(GET_list);

		// dup ack is checked when receiving ack
		// check timeout, enlist resend packet inside
		check_timeout(sock);
		//DPRINTF(DEBUG_PEER, "peer: timeout happened\n");
		
	    }

	    // all five kinds of packet
	    if (FD_ISSET(sock, &writefds)) {

		//DPRINTF(DEBUG_PEER, "sock, write\n");

		// check if GET_request has available peers to download chunks
		GET_list = check_GET_req(&GET_request, peer_list);
		outbound_list_cat(GET_list);
		
		if (general_send(sock) == 0) { 
		    DPRINTF(DEBUG_PEER, "no more packet to send, fd_clr sock from writefds\n");
		    FD_CLR(sock, &master_writefds);
		}
		
	    }
	}

    }
}
