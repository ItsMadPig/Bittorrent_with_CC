#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include "bt_parse.h"
#include "list.h"
#include "packet.h"
#include "debug.h"
#include "ctr_send_recv.h"


struct list_t* make_WHOHAS_packet_info(struct GET_request_t * GET_request, struct list_t *peer_list){

    //struct packet_info_t *packet_info_list, *packet_info;
    struct packet_info_t *packet_info;
    struct list_t *packet_info_list = NULL;
    int list_size, i, packet_len;
    int slot_begin, slot_end; // indices of first and off-1 slots    
    int slot_count;

    slot_count = GET_request->slot_list->length;
    if ( slot_count % MAX_HASH != 0)
	list_size = slot_count / MAX_HASH + 1; 
    else
	list_size = slot_count / MAX_HASH; 
    
    init_list(&packet_info_list);
	    
    // make a list_size list of packet_info
    for (i = 0; i < list_size; i++) {
	slot_begin = i * MAX_HASH;
	slot_end = (i+1) * MAX_HASH; // does not include slot_end
	if (slot_end > slot_count)
	    slot_end = slot_count;

	// first figure out size of the packet_info
	packet_len = (slot_end - slot_begin) * HASH_LEN + BYTE_LEN + HEADER_LEN;

	// save headers and chunk_t into struct packet_info
	packet_info = (struct packet_info_t *)calloc(1, sizeof(struct packet_info_t));
	
	packet_info->magic = (uint16)MAGIC;
	packet_info->version = (uint8)VERSION;
	packet_info->type = (uint8)WHOHAS;
	packet_info->header_len = (uint16)HEADER_LEN;
	packet_info->packet_len = (uint16)packet_len;
	packet_info->seq_num = (uint32)0;
	packet_info->ack_num = (uint32)0;
	packet_info->hash_count = (uint8)(slot_end - slot_begin);
	// include slot end
	packet_info->hash_chunk = array2chunk(GET_request, slot_begin, slot_end); 
	packet_info->peer_list = peer_list;

	enlist(packet_info_list, packet_info);
    }

    return packet_info_list;
}

/* make block of bytes which can be transmited  */
uint8 *info2packet(struct packet_info_t *packet_info){
    
    uint8 *packet, *packet_head;
    int chunksize = 0;

    packet_head = (uint8 *)calloc(packet_info->packet_len, sizeof(uint8));
    packet = packet_head;
 
    uint16 magic = htons(packet_info->magic);
    memcpy(packet, &magic, 2);
    packet += 2;
    
    memcpy(packet, &(packet_info->version), 1);
    packet += 1;

    memcpy(packet, &(packet_info->type), 1);
    packet += 1;

    uint16 header_len = htons(packet_info->header_len);
    memcpy(packet, &header_len, 2);
    packet += 2;

    uint16 packet_len = htons(packet_info->packet_len);
    memcpy(packet, &packet_len, 2);
    packet += 2;

    uint32 seq_num = htonl(packet_info->seq_num);
    memcpy(packet, &seq_num, 4);
    packet += 4;

    uint32 ack_num = htonl(packet_info->ack_num);
    memcpy(packet, &ack_num, 4);
    packet += 4;

    switch (packet_info->type) {
    case WHOHAS:
    case IHAVE:
	memcpy(packet, &(packet_info->hash_count), 1);
	packet += 1;
	memset(packet, 0, 3);
	packet += 3;	
	
	chunksize = packet_info->hash_count * HASH_LEN;
	memcpy(packet, packet_info->hash_chunk, chunksize);
	break;

    case GET:
	chunksize = packet_info->packet_len - packet_info->header_len;
	memcpy(packet, packet_info->hash_chunk, chunksize);
	break;
    case DATA:
	chunksize = packet_info->packet_len - packet_info->header_len;
	memcpy(packet, packet_info->data_chunk, chunksize);
	break;
    case ACK:
    case DENIED:
	// do nothing
	break;
    default:
	DPRINTF(DEBUG_PACKET, "info2packet: Warning! wrong packet type\n");
	break;
    }

    
    
    return packet_head;
}

/* parse chunk file, get hash_id, hash in string form and hex form  */
int parse_chunkfile(struct GET_request_t *GET_request, char *chunkfile) {
    assert(GET_request != NULL);
    assert(chunkfile != NULL);

    FILE *fp = NULL;
    char *p = NULL;
    char *p1 = NULL;
    struct slot_t *slot = NULL;
    char *buf_p = NULL;
    int buf_len = 1024;
    char id_buf[8];
    //int count;

    if ((fp= fopen(chunkfile, "r")) == NULL) {
	DEBUG_PERROR("Error! parse_chunkfile, fopen");
	return -1;
    }

    //count = 0;
    buf_p = (char *)calloc(buf_len, sizeof(char));
    while ((p = fgets(buf_p, buf_len, fp)) != NULL) {

	if (feof(fp)) 
	    break;

	DPRINTF(DEBUG_PACKET, "parse_chunkfile: p:%s", p);

	if (strchr(p, '\n') == NULL) {
	    DPRINTF(DEBUG_PACKET, "ERROR! parse_chunfile, fgets: line length of chunfile is greater than buf_len:%d\n", buf_len);
	    return -1;
	}
	
	if ((p1 = strchr(p, ' ')) == NULL) {
	    DPRINTF(DEBUG_PACKET, "ERROR! parse_chunkfile, fgets: chunk file is of wrong fomat\n");
	    return -1;
	}

	slot = NULL;
	init_slot(&slot);
	enlist(GET_request->slot_list, slot);
	//slot_p = (struct slot_t *)calloc(1, sizeof(struct slot_t));
	//GET_request->slot_array[GET_request->slot_count-1] = slot_p;
	
	strncpy(id_buf, p, p1-p);
	slot->hash_id = atoi(id_buf);
	DPRINTF(DEBUG_PACKET, "slot->hash_id:%d\n", slot->hash_id);
	
	p = p1 + 1;
	p1 = strchr(p, '\n'); // should not be null
	if (p1 - p != HASH_STR_LEN) {
	    DPRINTF(DEBUG_PACKET, "ERROR! parse_chunkfile: p1-p != HASH_STR_LEN\n");
	    return -1;
	}
	strncpy(slot->hash_str, p, HASH_STR_LEN);
	slot->hash_str[HASH_STR_LEN] = '\0';
	DPRINTF(DEBUG_PACKET, "slot->hash-str:%s\n", slot->hash_str);

	str2hex(slot->hash_str, slot->hash_hex);
	if (debug & DEBUG_PACKET) {
	    printf("slot->hash_hex:");
	    dump_hex(slot->hash_hex); 
	    printf("\n");
	}
	
	free(buf_p);
	buf_p = (char *)calloc(buf_len, sizeof(char));
    }
    
    return 0;
}

void init_GET_request(struct GET_request_t **p) {
    *p = (struct GET_request_t *)calloc(1, sizeof(struct GET_request_t));

    init_list(&((*p)->slot_list));
    init_list(&((*p)->id_hash_list));
    init_list(&((*p)->peer_slot_list));

    (*p)->output_file = NULL;
}

/* parse packet, save fields into  packet_info_t */
struct packet_info_t *packet2info(uint8 *packet) {

    uint8_t *p;
    struct packet_info_t *packet_info;
    int chunk_size;
    //int tmp = 0;
    
    //tmp = sizeof(struct packet_info_t);
    p = packet;
    
    packet_info = (struct packet_info_t *)calloc(1, sizeof(struct packet_info_t));
    //packet_info = (struct packet_info_t *)calloc(1, tmp);

    uint16 magic = *(uint16 *)p;
    packet_info->magic = ntohs(magic);
    p += 2;

    packet_info->version = *(uint8 *)p;
    p += 1;

    packet_info->type = *(uint8 *)p;
    p += 1;

    uint16 header_len = *(uint16 *)p;
    packet_info->header_len = ntohs(header_len);
    p += 2;
    
    uint16 packet_len =  *(uint16 *)p;
    packet_info->packet_len = ntohs(packet_len);
    p += 2;

    uint32 seq_num = *(uint32 *)p;
    packet_info->seq_num = ntohl(seq_num);
    p += 4;
    
    uint32 ack_num = *(uint32 *)p;
    packet_info->ack_num = ntohl(ack_num);
    p += 4;    

    printf("packet_len:%d, header_len:%d\n", packet_info->packet_len, packet_info->header_len);
    chunk_size = packet_info->packet_len - packet_info->header_len;
    
    switch (packet_info->type) {
    case WHOHAS:
    case IHAVE:
	// hash_count
	packet_info->hash_count = *(uint8 *)p;
	p += 4;
	chunk_size -= 4;
	// hash_chunk
	packet_info->hash_chunk = (uint8 *)calloc(chunk_size, sizeof(uint8));
	memcpy((packet_info->hash_chunk), p, chunk_size);	
	break;
    case GET:
	//packet_info->hash_count = 0; // actually not used
	packet_info->hash_chunk = (uint8 *)calloc(HASH_LEN, sizeof(uint8));
	memcpy((packet_info->hash_chunk), p, HASH_LEN); // only one hash
	break;
    case DATA:
	//packet_info->hash_count = 0; // actually no such field 
	packet_info->data_chunk = (uint8 *)calloc(chunk_size, sizeof(uint8));
	
	memcpy((packet_info->data_chunk), p, chunk_size); // only one hash
	break;
    case ACK:
    case DENIED:
	// no hash/data_chunk
	break;
    default:
	fprintf(stderr, "Error! packet2info, type does no match\n");
	break;
    }

    return packet_info;
}

/*
void dump_packet_info_list(struct packet_info_t *packet_info) {

    int i;
    struct packet_info_t *p;

    i = 0;
    p = packet_info;
    while (p != NULL) {
	printf("packet_info_list[%d]:\n", i++);

	dump_packet_info(p);
	p = p->next;
    }
}
*/

//void dump_packet_info(struct packet_info_t *p) {
void info_printer(void *data) {
    int j;
    struct packet_info_t *p = NULL;

    assert(data != NULL);

    p = (struct packet_info_t *)data;
    
    printf("magic:%d ", p->magic);
    printf("version:%d ", p->version);
    printf("type:%d ", p->type);
    printf("header_len:%d ", p->header_len);
    printf("packet_len:%d ", p->packet_len);
    printf("seq_num:%d ", p->seq_num);
    printf("ack_num:%d ", p->ack_num);
    printf("hash_count:%d(not necessarily exist)\n", p->hash_count);
    
    printf("hash/data_chunk:(not necessarily exist)\n");
    switch (p->type) {
    case WHOHAS:
    case IHAVE:
	for (j = 0; j < p->hash_count; j++) 
	    dump_hex(p->hash_chunk + HASH_LEN * j);
	break;
    case GET:
	dump_hex(p->hash_chunk);
	break;
    case DATA:
	dump_hex(p->data_chunk);
	printf("and more ...\n");
	break;
    case ACK:
    case DENIED:
	printf("no hash/data chunk\n");
	break;
    default:
	printf("Wrong type\n");
	break;
    }
    
    // print peer list
    printf("peer_list:\n");
    dump_list(p->peer_list, peer_printer, "\n");
}


void dump_hex(uint8 *hex) {

    int i;
    unsigned int k;

    for (i = 0; i < HASH_LEN; i++) {
	k = *hex;
	printf("%2x ", k);
	hex += 1;
    }
    printf("\n");

}

/*convert 40 bytes of string into 20 bytes of hex numbers*/
void str2hex(char *str, uint8 *hex) {
    int i;
    unsigned int k;
    uint8 uint8_k;
    char buf[3];

    for (i = 0; i < HASH_LEN; i++) {
	memset(buf, 0, 3);
	strncpy(buf, str + 2*i, 2);
	sscanf(buf, "%x", &k);
	uint8_k = (uint8)k;
	memcpy(hex + i, &uint8_k, sizeof(uint8));
    }

}

/* concatenate hash_hex between begin and end into a continuous block  */
uint8 *array2chunk(struct GET_request_t *GET_request, int slot_begin, int slot_end) {
    uint8 *chunk, *p;
    int chunk_size, i, j;
    int slot_count;
    struct slot_t *slot = NULL;

    slot_count = slot_end - slot_begin + 1;
    chunk_size = slot_count * HASH_LEN;
    chunk = (uint8 *)calloc(chunk_size, sizeof(uint8));
    p = chunk;

    j = 0;
    for (i = slot_begin; i < slot_end; i++, j++) {
	slot = list_ind(GET_request->slot_list, i);
	memcpy(p + j*HASH_LEN, slot->hash_hex, HASH_LEN);
	//memcpy(p + j*HASH_LEN, GET_request->slot_array[i]->hash_hex, HASH_LEN);
    }

    return chunk;
}

/*
void enlist_packet_info(struct packet_info_t **packet_info_list, struct packet_info_t *packet_info) {
    struct packet_info_t *p;

    if (*packet_info_list == NULL)
	*packet_info_list = packet_info; 
    else {
	p = *packet_info_list;
	while (p->next != NULL)
	    p = p->next;
	p->next = packet_info;
    }

}
*/

/*
struct packet_info_t *delist_packet_info(struct packet_info_t **list) {
    struct packet_info_t *p;

    if (*list == NULL)
	return NULL;

    p = *list;
    *list = (*list)->next;

    return p;
}
*/

/*
void dump_info_list(struct packet_info_t *list) {
    struct packet_info_t *p;
    
    if (list == NULL) {
	printf("null\n");
    } else {
	p = list;
	while (p != NULL) {
	    dump_packet_info(p);
	    p = p->next;
	}
    }
}
*/

void enlist_id_hash(struct id_hash_t **id_hash_list, struct id_hash_t *id_hash) {
    struct id_hash_t *p;

    if (*id_hash_list == NULL)
	*id_hash_list = id_hash; 
    else {
	p = *id_hash_list;
	while (p->next != NULL)
	    p = p->next;
	p->next = id_hash;
    }
}

struct id_hash_t *delist_id_hash(struct id_hash_t **list) {
    struct id_hash_t *p;
    
    if (*list == NULL)
	return NULL;
    
    p = *list;
    *list = (*list)->next;

    return p;
}

void dump_id_hash_list(struct id_hash_t *list) {
    struct id_hash_t *p;
    
    if (list == NULL) {
	printf("null\n");
    } else {
	p = list;
	while (p != NULL) {
	    printf("%d %s\n", p->id, p->hash_string);
	    p = p->next;
	}
    }
}

/*
struct slot_t *get_slot(struct list_t *peer_slot_list, bt_peer_t *peer) {
    
    struct list_item_t *iterator = NULL;
    struct peer_slot_t *peer_slot = NULL;
    
    iterator = get_iterator(peer_slot_list);
    while (has_next(iterator)) {
	peer_slot = next(iterator);
	if (peer_slot->peer_id = peer->id)
	    ????
    }

}
*/

void init_packet_info(struct packet_info_t **p) {
    (*p) = (struct packet_info_t *)calloc(1, sizeof(struct packet_info_t));

    (*p)->hash_chunk = NULL;
    (*p)->data_chunk = NULL;
    init_list(&((*p)->peer_list));
}


void init_slot(struct slot_t **p) {
    (*p) = (struct slot_t *)calloc(1, sizeof(struct slot_t));

    init_list(&((*p)->peer_list));
    (*p)->selected_peer = NULL;
    //init_list(&((*p)->DATA_list));
    init_flow_wnd(&((*p)->flow_wnd));
    
    (*p)->status = RAW;
    (*p)->received_data = NULL;

    (*p)->trial_num = 0;
    time(&((*p)->old_time));
}

/* Check several thing for each slot: is the slot ready for downloading, or is the downloading done */
struct list_t *check_GET_req(struct GET_request_t **GET_request_dp, struct list_t *peer_list) {
    
    struct list_item_t *iterator = NULL;

    struct slot_t *slot = NULL;
    struct list_t *list = NULL;
    struct list_t *ret_list = NULL;
    int done_count = 0;
    int ind = 0;
    int fd;
    int slot_ind;
    struct GET_request_t *GET_request = NULL;
    
    time_t cur_time;

    assert(GET_request_dp != NULL);

    GET_request = *GET_request_dp;

    if (GET_request == NULL){
	//DPRINTF(DEBUG_PACKET, "check_GET_req: GET req is null, no need to check\n");
	return NULL;
    }

    init_list(&list);

    iterator = get_iterator(GET_request->slot_list);
    while (has_next(iterator)) {
	slot = next(&iterator);
	DPRINTF(DEBUG_PACKET, "check_GET_req: slot_%d, ", ind);
	
	switch (slot->status) {
	case RAW:
	    DPRINTF(DEBUG_PACKET, "RAW\n");

	    time(&cur_time);
	    //printf("????diftime:%f\n", difftime(cur_time, slot->old_time));
	    if (difftime(cur_time, slot->old_time) > RESTART_TIME) {
		DPRINTF(DEBUG_PACKET, "slot stays in RAW status over RESTART_TIME=%d, goto RESTART\n", RESTART_TIME);		
		slot->status = RESTART;
		break;
	    }
	    
	    break; 

	case START:
	    DPRINTF(DEBUG_PACKET, "START\n");	    
	    
	    // received IHAVE packet(s)
	    assert(slot->peer_list->length != 0);
	    assert(slot->selected_peer == NULL);
	    assert(slot->flow_wnd != NULL);
	    
	    if (select_peer(slot, GET_request->peer_slot_list) != NULL) {
		slot->status = DOWNLOADING; // change status	

		assert(slot->selected_peer != NULL);
		ret_list = make_GET_info(slot->hash_hex, slot->selected_peer);
		cat_list(&list, &ret_list);
		
		break;
	    }
	    // no available peer, restart????
	    // right now, do nothing, hope some peer become available next time this slot is checked
	    // solution: go to restart
	    time(&cur_time);
	    if (difftime(cur_time, slot->old_time) > RESTART_TIME){
		DPRINTF(DEBUG_PACKET, "slot statys in START status over RESTART_TIME=%d, goto RESTART\n", RESTART_TIME);
		slot->status = RESTART;
		break;
	    }
	    	    
	    break;

	case DOWNLOADING:
	    DPRINTF(DEBUG_PACKET, "DOWNLOADING\n");
	    
	    assert(slot->selected_peer != NULL);
	    
	    int ret;
	    ret = is_fully_received(slot->flow_wnd, slot->hash_hex, &(slot->received_data));

	    if (ret == -1) {
		// last_read != list_size
		break;
	    } else if (ret == 0) {
		// differetn hash
		DPRINTF(DEBUG_PACKET, "check_GET_req: fully received, but hash does not match, RESTART this slot\n");
		slot->status = RESTART;
		break;
	    } else {
		// fully received, and same hash
		assert(ret == 1);

		DPRINTF(DEBUG_PACKET, "check_GET_req: is_fully_received, same hash, data is saved in the slot, change status to DONE\n");

		slot->status = DONE;

		remove_peer(GET_request->peer_slot_list, slot->selected_peer->id);

	    } 
		

	    break;

	case DONE:
	    DPRINTF(DEBUG_PACKET, "DONE\n");
	    ++done_count;
	    if (done_count == GET_request->slot_list->length) {

		assert(GET_request->output_file);
		DPRINTF(DEBUG_PACKET, "check_GET_req: ALL downloading done! Save to file %s\n", GET_request->output_file);
		
		// save data to file
		fd = open(GET_request->output_file, O_RDWR | O_CREAT | O_TRUNC, 0644);
		if (fd == -1) {
		    DEBUG_PERROR("Error! check_GET_req, open");
		    return NULL;
		}
		
		for (slot_ind = 0; slot_ind < GET_request->slot_list->length; slot_ind++) {
		    lseek(fd, slot_ind * CHUNK_SIZE, SEEK_SET);

		    slot = list_ind(GET_request->slot_list, slot_ind);

		    assert(slot != NULL);
		    assert(slot->received_data != NULL);
		    if (write(fd, slot->received_data, CHUNK_SIZE) != CHUNK_SIZE) {
			DEBUG_PERROR("Error! check_GET_req: write");
			return NULL;
		    }
		}
		close(fd);

		// re-init GET_request
		init_GET_request(GET_request_dp);
	    }
	    break;

	case RESTART:
	    
	    // reset old_time,  send WHOAHS, delete current wnd, remove peer_slot, goto RAW
	    DPRINTF(DEBUG_PACKET, "RESTART\n");

	    //
	    time(&(slot->old_time));
	    //slot->trial_num += 1;
	    
	    //
	    if (slot->selected_peer != NULL)
		remove_peer(GET_request->peer_slot_list, slot->selected_peer->id);

	    //
	    slot->selected_peer = NULL;

	    slot->peer_list = NULL;
	    init_list(&(slot->peer_list));

	    slot->received_data = NULL;

	    slot->flow_wnd = NULL;
	    init_flow_wnd(&(slot->flow_wnd));

	    slot->status = RAW;// send WHOHAS, wait for IHAVE to change status to START
		
	    //
	    ret_list = make_single_WHOHAS_info(slot->hash_hex, peer_list);
	    
	    cat_list(&list, &ret_list);


	    break;

	}
	++ind;
    }


    DPRINTF(DEBUG_PACKET, "check_GET_req: GET req check done\n");
    return list;
}


void remove_peer(struct list_t *peer_slot_list, int id){
    assert(peer_slot_list != NULL);
    assert(id >= 0);
    
    struct list_item_t *ite = NULL;
    struct list_item_t *old_ite = NULL;
    struct peer_slot_t *peer_slot = NULL;
    int removed = 0;

    // delist the peer_slot from peer_slot_list
    ite = get_iterator(peer_slot_list);
    while (has_next(ite)) {
	old_ite = ite;
	peer_slot = next(&ite);
		    
	if (peer_slot->peer_id == id) {
	    delist_item(peer_slot_list, old_ite);
	    DPRINTF(DEBUG_PACKET, "check_GET_req: peer_slot_list removes item with peer_id=%d\n", id);

	    removed = 1;
	}
    }

    assert(removed == 1);
}

struct list_t *make_single_WHOHAS_info(uint8 *hash, struct list_t *peer_list) {
    struct packet_info_t *info = NULL;
    struct list_t *info_list = NULL;
    int packet_len;

    assert(hash != NULL);
    assert(peer_list != NULL);

    init_packet_info(&info);
    init_list(&info_list);
    packet_len = HEADER_LEN + BYTE_LEN + HASH_LEN;

    info->magic = (uint16)MAGIC;
    info->version = (uint8)VERSION;
    info->type = (uint8)WHOHAS;
    info->header_len = (uint16)HEADER_LEN;
    info->packet_len = (uint16)packet_len;
    info->seq_num = (uint32)0;
    info->ack_num = (uint32)0;
    
    info->hash_count = 1;
    //info->hash_chunk = hash;
    info->hash_chunk = (uint8*)calloc(HASH_LEN, sizeof(uint8));
    memcpy(info->hash_chunk, hash, HASH_LEN);

    info->peer_list = peer_list;
    //cat_list(&(info->peer_list), &peer_list);
    
    enlist(info_list, info);

    return info_list;

}

struct list_t *make_GET_info(uint8* hash, bt_peer_t *peer) {
    struct packet_info_t *info = NULL;
    struct list_t *info_list = NULL;
    int packet_len;
    
    init_packet_info(&info);
    init_list(&info_list);
    packet_len = HEADER_LEN + HASH_LEN;

    info->magic = (uint16)MAGIC;
    info->version = (uint8)VERSION;
    info->type = (uint8)GET;
    info->header_len = (uint16)HEADER_LEN;
    info->packet_len = (uint16)packet_len;
    info->seq_num = (uint32)0;
    info->ack_num = (uint32)0;
    
    info->hash_count = 0;// actually, not used

    info->hash_chunk = (uint8 *)calloc(HASH_LEN, sizeof(uint8));
    memcpy(info->hash_chunk, hash, HASH_LEN);
    //dump_hex(info->hash_chunk);

    enlist(info->peer_list, peer);
    
    enlist(info_list, info);

    return info_list;
}

bt_peer_t *select_peer(struct slot_t *slot, struct list_t *peer_slot_list) {
    
    struct list_item_t *iterator = NULL;
    bt_peer_t *peer = NULL;
    struct peer_slot_t *peer_slot = NULL;
    
    assert(peer_slot_list != NULL); // it could be empty
    assert(slot->peer_list->length != 0); // it cannot be empty

    DPRINTF(DEBUG_PACKET, "select_peer:\n");
    iterator = get_iterator(slot->peer_list);
    while (has_next(iterator)) {
	peer = next(&iterator);

	if (in_peer_slot_list(peer->id, peer_slot_list)) {
	    DPRINTF(DEBUG_PACKET, "select_peer:peer_%d already in peer_slot_list\n", peer->id);
	    continue; // check next peer
	} else {
	    DPRINTF(DEBUG_PACKET, "select_peer:peer_%d not in peer_slot_list, selected\n", peer->id);
	    
	    // select
	    slot->selected_peer = peer;

	    // enlist peer_slot
	    init_peer_slot(&peer_slot);
	    peer_slot->peer_id = peer->id;
	    peer_slot->slot = slot;
	    enlist(peer_slot_list, peer_slot);

	    return peer; 
	}
    }
    
    // all peers are in peer_slot_list
    DPRINTF(DEBUG_PACKET, "select_peer: all slot->peers are in peer_slot_list, no peer selected\n");
    return NULL;
}

/* check if a peer_id is in the peer_slot_list  
 * return 1 if in, 0 if not
 */
int in_peer_slot_list(int peer_id, struct list_t *peer_slot_list) {
    
    struct list_item_t *iterator = NULL;
    struct peer_slot_t *ps = NULL;

    iterator = get_iterator(peer_slot_list);
    while (has_next(iterator)) {
	ps = next(&iterator);
	if (peer_id == ps->peer_id)
	    return 1;
    }
    return 0;
}

void init_peer_slot(struct peer_slot_t **ps){
    *ps = (struct peer_slot_t *)calloc(1, sizeof(struct peer_slot_t));

    (*ps)->peer_id = -1;
    (*ps)->slot = NULL;
}

/* make a series of DATA packet, enlist them individually
 * data can only be of size CHUNK_SIZE
 * Always retun NULL, since all packet has been enlisted to send inside function
 */
struct list_t *make_DATA_info(uint8 *data, struct list_t *peer_list) {

    assert(data != NULL);
    assert(peer_list != NULL);

    struct list_t *info_list = NULL;
    struct packet_info_t *info = NULL;
    int list_size, i;
    size_t data_begin, data_end, data_len;

    init_list(&info_list);

    list_size = get_list_size();
    DPRINTF(DEBUG_PACKET, "make_DATA_info: list_size:%d\n", list_size);

    for (i = 0; i < list_size; i++){
	info = NULL;
	init_packet_info(&info);

	// data region
	data_begin = MAX_DATA * i;
	data_end = MAX_DATA * (i+1);
	if (data_end > CHUNK_SIZE) 
	    data_end = CHUNK_SIZE;
	data_len = data_end - data_begin;

	// basic infomation
	info->magic = (uint16)MAGIC;
	info->version = (uint8)VERSION;
	info->type = (uint8)DATA;
	info->header_len = (uint16)HEADER_LEN;
	info->packet_len = (uint16)(HEADER_LEN + data_len);
	info->seq_num = (uint32)(i+1);
	//info->seq_num = (uint32)2;
	info->ack_num = (uint32)0; // not used

	info->data_chunk = (uint8 *)calloc(data_len, sizeof(uint8));
	memcpy(info->data_chunk, data + data_begin, data_len);
	DPRINTF(DEBUG_PACKET, "first 8 bytes of data_chunk:");
	dump_hex(info->data_chunk);

	// additional information: dest. peer_list
	info->peer_list = peer_list;

	// enlist for send
	enlist(info_list, info);
    }

    return info_list;
}

int get_list_size() {
    int list_size;
    
    // turn into list of packets
    list_size = CHUNK_SIZE / MAX_DATA;
    if (MAX_DATA * list_size < CHUNK_SIZE)
	++list_size;
    assert(MAX_DATA * list_size >= CHUNK_SIZE);
    
    return list_size;
}

/* ack_num = 0, is ok, it means that the 0th packet has not been received yet  */
struct list_t *make_ACK_info(int ack_num, struct list_t *peer_list) {
    assert(ack_num >= 0);

    struct packet_info_t *info = NULL;
    struct list_t *list = NULL;

    init_packet_info(&info);
    init_list(&list);
    
    info->magic = (uint16)MAGIC;
    info->version = (uint8)VERSION;
    info->type = (uint8)ACK;
    info->header_len = (uint16)HEADER_LEN;
    info->packet_len = (uint16)HEADER_LEN;
    info->seq_num = (uint32)0; // no used
    info->ack_num = (uint32)ack_num;

    //
    info->peer_list = peer_list;

    //
    enlist(list, info);

    return list;
}

/* Fetch data from file based on hash_id
 * If file cannot open or id wrong, return NULL
 */
uint8 *fetch_data(char *chunk_file, int hash_id) {
    assert(chunk_file != NULL);
    assert(hash_id >= 0);

    uint8 *buf = NULL;
    char path_buf[BT_FILENAME_LEN];
    char *path_p = NULL;
    char *tmp = NULL;
    int fd;
    FILE* fp;
    size_t offset;
    int size;
    printf("fetch_data:chunk_file:%s, hash_id:%d\n", chunk_file, hash_id);

    memset(path_buf, 0, BT_FILENAME_LEN);
    buf = (uint8 *)calloc(CHUNK_SIZE, sizeof(uint8));

    // figure data_chunk file
    if((fp = fopen(chunk_file, "r")) == NULL) {
	DPRINTF(DEBUG_PACKET, "Error! fetch_data, open chunk_file:%s", chunk_file);
	return NULL;
    }

    if (fgets(path_buf, BT_FILENAME_LEN-1, fp) == NULL) {
	DEBUG_PERROR("Error! fetch_data, fgets\n");
	return NULL;
    }
    
    if ((path_p = strstr(path_buf, "./")) == NULL) {
	DEBUG_PERROR("Error! fetch_data, strchr\n");
	return NULL;
    }
    tmp = strchr(path_p, '\n');
    *tmp = '\0';
    path_p += 2;
    
    DPRINTF(DEBUG_PACKET, "fetch_data: data_file:%s\n", path_p);

    // read data_file 
    if ((fd = open(path_p, O_RDONLY, 0)) == -1) {
	DPRINTF(DEBUG_PACKET, "Error! fetch_data, open data_file %s\n", path_p);
	DEBUG_PERROR("");
	return NULL;
    }
    
    // go to right position and read
    offset = hash_id * CHUNK_SIZE;
    if (lseek(fd, offset, SEEK_SET) == -1) {
	DEBUG_PERROR("Error! fetch_data, lseek");
	return NULL;
    }
    
    if ((size = read(fd, buf, CHUNK_SIZE)) == -1) {
	DEBUG_PERROR("Error! fetch_data, read");
	return NULL;
    }
    DPRINTF(DEBUG_PACKET, "fetch_data: %d bytes of data is fetched, CHUNK_SIZE is %d\n", size, CHUNK_SIZE);

    return buf;
}

/* Find id by comparing hashes
 * Return a non-negative id if found, return -1 if an id is not found
 */
int hash2id(uint8 *hash, struct list_t *id_hash_list) {
    assert(id_hash_list != NULL);

    struct list_item_t *ite = NULL;
    struct id_hash_t *id_hash = NULL;
    uint8 hash_hex[HASH_LEN];

    DPRINTF(DEBUG_PACKET, "hash2id: looking for id of hash:");
    dump_hex(hash);
    
    ite = get_iterator(id_hash_list);
    while (has_next(ite)) {
	id_hash = next(&ite);
	
	str2hex(id_hash->hash_string, hash_hex);

	DPRINTF(DEBUG_PACKET, "hash2id: compare to:");
	dump_hex(hash_hex);
	
	if (memcmp(hash, hash_hex, HASH_LEN) == 0) {
	    DPRINTF(DEBUG_PACKET, "hash2id: matching hash found, id is %d\n", id_hash->id);
	    return id_hash->id;
	}
    }
    DPRINTF(DEBUG_PACKET, "hash2id: matching hash not found\n");

    return -1;
}



#ifdef _TEST_PACKET_
int main(){

    printf("sizeof(uint8):%ld\n", sizeof(uint8));
    printf("sizeof(uint16):%ld\n", sizeof(uint16));
    printf("sizeof(uint32):%ld\n", sizeof(uint32));

    struct GET_request_t * GET_request;
    struct packet_info_t *WHOHAS_packet_info, *packet_info;
    uint8 *packet;

    GET_request = (struct GET_request_t *)calloc(1, sizeof(struct GET_request_t));
    init_GET_request(&GET_request);

    parse_chunkfile(GET_request, "A.chunks");

    WHOHAS_packet_info = make_WHOHAS_packet_info(GET_request, NULL);
    dump_packet_info(WHOHAS_packet_info);
    
    packet = info2packet(WHOHAS_packet_info);
    packet_info = packet2info(packet);
    dump_packet_info(packet_info);

    // test make_DATA_info
    int sock;
    bt_peer_t peer;
    struct list_t *peer_list = NULL;

    peer.id = 1;
    memset(&peer.addr, sizeof(peer.addr));
    peer.addr.sin_family = AF_INET;
    peer.addr.sin_addr.s_addr = htonl(INADDR_ANY);
    peer.addr.sin_port = htons(7890);
    
    if (bind(sock, (struct sockaddr *) &(peer.addr), sizeof(peer.addr)) == -1) {
	perror("could not bind socket");
	exit(-1);
    }

    init_list(&peer_list);
    make_DATA_info("B.haschunks", 2, peer_list);

    return 0;
}
#endif
