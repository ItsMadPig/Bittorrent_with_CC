

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "list.h"
#include "debug.h"
#include "process_udp.h"
#include "packet.h"
#include "spiffy.h"
#include "ctr_send_recv.h"

/* Delist a packet_info, convert it into packet and send it out 
 * Return -1 on type error, 0 on sending no packets, 1 on sending a packet
 */
int process_outbound_udp(int sock, struct list_t *list) {
    
    struct packet_info_t *packet_info = NULL;
    
    assert(list != NULL);
    if ((packet_info = delist(list)) != NULL) {
	if(debug & DEBUG_PROCESS_UDP) {
	    printf("\nprocess_outbound_udp: process packet_info:\n");
	    info_printer(packet_info);
	}

	// check type and process
	switch(packet_info->type) {
	case WHOHAS:
	    DPRINTF(DEBUG_PROCESS_UDP, "switch case WHOHAS\n");
	    break;
	case IHAVE:
	    DPRINTF(DEBUG_PROCESS_UDP, "switch case IHAVE\n");
	    break;
	case ACK:
	    DPRINTF(DEBUG_PROCESS_UDP, "switch case ACK\n");
	    break;
	case GET:
	    DPRINTF(DEBUG_PROCESS_UDP, "switch case GET\n");
	    break;
	case DATA:	    
	    DPRINTF(DEBUG_PROCESS_UDP, "switch case DATA\n");
	default:
	    DPRINTF(DEBUG_PROCESS_UDP, "Error! process_outbound_udp, type does not match\n");
	    return -1; // invalid type
	    break;
	}

	return send_info(sock, packet_info);
    }

    //DPRINTF(DEBUG_PROCESS_UDP, "process_outbound_udp: empty outbound_list\n");
    return 0;
}


/* Return 1 on sending packet to at least one peer, 0 on failing packet to any peer, -1 on peer_list is empty  */
int send_info(int sock, struct packet_info_t *packet_info){

    assert(packet_info->peer_list != NULL);
    assert(packet_info->peer_list->length != 0);

    uint8 *packet = NULL;
    struct list_item_t *iterator = NULL;
    bt_peer_t *peer = NULL;
    int count;

    packet = info2packet(packet_info);    

    if (packet_info->type == DATA) {
	time(&(packet_info->time));
	DPRINTF(DEBUG_PROCESS_UDP, "send_info: send DATA_packet, set its time\n");
    }
    
    // send to the peers in the peer_list of the packet_info
    iterator = get_iterator(packet_info->peer_list);
    if (iterator == NULL) {
	DPRINTF(DEBUG_PROCESS_UDP, "Warning! send_info, info->peer_list is null\n");
	return -1;
    }

    count = 0;
    while (has_next(iterator)) {
	peer = next(&iterator);
	assert(peer != NULL);
	DPRINTF(DEBUG_PROCESS_UDP, "send_info: send to peer %d\n", peer->id);
	send_packet(peer, packet, packet_info->packet_len, sock);
	peer = peer->next;
	count++;
    }
    
    if (count == 0)
	return 0;
    return 1;
}


/* Return 1 on sending, -1 on error  */
int send_packet(bt_peer_t *peer, uint8 *packet, int packet_len, int sock) {
      //while the whole data isn't sent completely
    if (spiffy_sendto(sock, packet, packet_len, 0, (struct sockaddr *)&(peer->addr), sizeof(struct sockaddr_in)) < 0){
        DEBUG_PERROR("Error! send_packet error\n");
	return -1;
    }

    return 1;
}

/* Process inbound packet based on packet type
 * Return reply packet, return NULL if no need to reply
 */
struct list_t  *process_inbound_udp(struct packet_info_t *info, int sock, bt_config_t *config, struct GET_request_t *GET_request) {

    assert(info != NULL);
    assert(config != NULL);
    
    struct list_t *ret_list = NULL;
    //assert(GET_request != NULL);// cannot assume this
    
    switch (info->type) {
    case WHOHAS:
	ret_list = process_inbound_WHOHAS(info, config);
	break;
    case IHAVE:
	ret_list = process_inbound_IHAVE(info, GET_request);
	break;
    case GET:
	ret_list = process_inbound_GET(info, config);
	break;
    case ACK:
	ret_list = process_inbound_ACK(info, sock);
	break;
    case DENIED:
	printf("process_inbound_udp: DENIED, not implemted yet\n");
	ret_list = NULL;
	break;
    case DATA:
	ret_list = process_inbound_DATA(info, GET_request);
	break;
    default:
	DPRINTF(DEBUG_CTR, "general_recv: wrong type\n");
	ret_list = NULL;
	break;
    }

    return ret_list;
}


struct list_t *process_inbound_GET(struct packet_info_t *info, bt_config_t *config) {

    int id = -1;
    uint8 *data = NULL;
    struct list_t *info_list = NULL;

    assert(info != NULL);
    assert(config != NULL);

    if((id = hash2id(info->hash_chunk, config->id_hash_list)) == -1){
	DPRINTF(DEBUG_PROCESS_UDP, "process_inbound_GET: Error! cannot find matching hash, no DATA packet is made\n");
	return NULL;
    }

    data = fetch_data(config->chunk_file, id);
    if (data == NULL) {
	DPRINTF(DEBUG_PROCESS_UDP, "Warning! fetched no data, no DATA_packet is made\n");
	return NULL;
    }
    
    info_list = make_DATA_info(data, info->peer_list);

    //data_wnd_list_cat(info_list);

    return info_list;
}


/* Parse WHOHAS pacekt and make IHAVE packet info
 * Return pointer to IHAVE pacekt info on success, return NULL if IAHVE packet info is empty
 */
struct list_t *process_inbound_WHOHAS(struct packet_info_t *packet_info, bt_config_t *config) {

    uint8 *target_hash = NULL;
    uint8 *chunk_p = NULL;
    struct packet_info_t *IHAVE_packet_info = NULL;
    struct list_t *ret_list = NULL;
    uint8 chunk_data[MAX_PACKET_LEN];
    int count = 0;
    int i;
    int chunk_size;

    IHAVE_packet_info = (struct packet_info_t *)calloc(1, sizeof(struct packet_info_t));

    // earch for matching hash
    count = 0;
    chunk_p = chunk_data;

    for (i = 0; i < packet_info->hash_count; i++) {
	target_hash = packet_info->hash_chunk + i * HASH_LEN;
	DPRINTF(DEBUG_PROCESS_UDP, "process_inbound_WHOHAS: search target hash%d\n",i);

	if (search_hash(target_hash, config->id_hash_list) == 1) {
	    DPRINTF(DEBUG_PROCESS_UDP, "process_inbound_WHOAHS: target hash found\n");
	    memcpy(chunk_p, target_hash, HASH_LEN);
	    chunk_p += HASH_LEN;
	    count++;
	}
    }

    // no need to send IHAVE back
    if (count == 0) {
	DPRINTF(DEBUG_PROCESS_UDP, "process_inbound_WHOHAS: 0 matching hash found, do not send IAHVE packet back\n");
	free(IHAVE_packet_info);
	return NULL;
    }
    
    // fill packet_info 
    IHAVE_packet_info->hash_count = (uint8)count;

    chunk_size = chunk_p - chunk_data;
    IHAVE_packet_info->hash_chunk = (uint8 *)calloc(chunk_size, sizeof(uint8));
    memcpy(IHAVE_packet_info->hash_chunk, chunk_data, chunk_size);

    IHAVE_packet_info->magic = (uint16)15441;
    IHAVE_packet_info->version = (uint8)1;
    IHAVE_packet_info->type = (uint8)IHAVE;
    IHAVE_packet_info->header_len = HEADER_LEN;
    IHAVE_packet_info->packet_len = HEADER_LEN + BYTE_LEN + IHAVE_packet_info->hash_count * HASH_LEN;

    IHAVE_packet_info->peer_list = packet_info->peer_list;
    

    if (debug & DEBUG_PROCESS_UDP) {
	printf("process_udp: make IAHVE_packet_info:\n");
	info_printer(IHAVE_packet_info);
    }

    // enlist IHAVE_packet_info to the outbound_list
    //outbound_list_en(IHAVE_packet_info);

    init_list(&ret_list);
    enlist(ret_list, IHAVE_packet_info);

    return ret_list;
}

/* Always return NULL, since there is no need to reply */
struct list_t *process_inbound_IHAVE(struct packet_info_t *info, struct GET_request_t *GET_request) {
    assert(info != NULL);
    assert(GET_request != NULL);

    compare_hash(GET_request->slot_list, info);

    return NULL;
}

void compare_hash(struct list_t *slot_list, struct packet_info_t *info) {
    
    struct list_item_t *iterator = NULL;
    struct slot_t *slot = NULL;
    uint8 *slot_hash = NULL;
    uint8 *info_hash = NULL;
    int i, count;
    
    count = 0;
    iterator = get_iterator(slot_list);
    while (has_next(iterator)) {
	slot = next(&iterator);
	slot_hash = slot->hash_hex;

	DPRINTF(DEBUG_PROCESS_UDP, "compare_hash: slot_%d:", count);
	dump_hex(slot->hash_hex);
	
	for (i = 0; i < info->hash_count; i++) {
	    info_hash = info->hash_chunk + (i * HASH_LEN);
	    
	    DPRINTF(DEBUG_PROCESS_UDP, "compare_hash: info_hash_%d:", i);
	    dump_hex(info_hash);
	    if (memcmp(slot_hash, info_hash, HASH_LEN) == 0) {

		cat_list(&(slot->peer_list), &(info->peer_list));
		DPRINTF(DEBUG_PROCESS_UDP, "compare_hash: matching hash found, enlist peer to slot_%d\n", count);
		
		// change slot status only if it's RAW
		if (slot->status == RAW) {
		    slot->status = START;
		    DPRINTF(DEBUG_PROCESS_UDP, "compare_hash: change slot status from RAW to START\n");
		}

		break;
	    }
	}
	
	if (i == info->hash_count)
	    DPRINTF(DEBUG_PROCESS_UDP, "compare_hash: no matching hash\n");
	++count;
    }
    
}

/* Save inbound DATA packet, and generate ACK packet
 * Return the generated ACK if slot found, return NULL if slot not found
 */
struct list_t *process_inbound_DATA(struct packet_info_t *info, struct GET_request_t *GET_req) {
    assert(info != NULL);

    struct list_t *list = NULL;
    int expec_num = 0;
    expec_num = enlist_DATA_info(info, GET_req);

    list = make_ACK_info(expec_num-1, info->peer_list);

    return list;
}



int search_hash(uint8 *target_hash, struct list_t *id_hash_list) {
    assert(target_hash != NULL);
    assert(id_hash_list != NULL);

    uint8 *has_hash = NULL;
    struct list_item_t *ite = NULL;
    struct id_hash_t *id_hash = NULL;
    int match;

    match = 0;
    has_hash = (uint8 *)calloc(HASH_LEN, sizeof(uint8));
    
    //id_hash = id_hash_list;
    ite = get_iterator(id_hash_list);
    while (has_next(ite)) {
	id_hash = next(&ite);

	str2hex(id_hash->hash_string, has_hash);

	if (debug & DEBUG_PROCESS_UDP) {
	    printf("search_hash: has_hash   ");
	    dump_hex(has_hash);
	}
	
	if (memcmp(target_hash, has_hash, HASH_LEN) == 0) {
	    match = 1;
	    break;
	}
	
    }

    //free(has_hash);
    return match;
}


/* First, change wnd size based on mode
 * Second, check dup acks, change wnd and return data_packet to resend
 */
struct list_t* process_inbound_ACK(struct packet_info_t *info, int sock){
    assert(info != NULL);

    return do_inbound_ACK(info, sock);
}


// adjust wnd based on wnd->last_ack and and wnd->size
// you should update these two before calling this func
int adjust_data_wnd(struct data_wnd_t *wnd) {
    assert(wnd != NULL);

    // update last_avai
    wnd->last_packet_avai = wnd->last_packet_acked + wnd->size;
    if (wnd->last_packet_avai > wnd->packet_list->length)
	wnd->last_packet_avai = wnd->packet_list->length;
	
    // update last_sent 
    if (wnd->last_packet_sent > wnd->last_packet_avai)
	wnd->last_packet_sent = wnd->last_packet_avai;
    
    // double check
    assert(wnd->last_packet_acked <= wnd->last_packet_sent);
    assert(wnd->last_packet_sent <= wnd->last_packet_avai);
    assert(wnd->last_packet_avai <= wnd->packet_list->length);

    // 
    time_t cur_time; 
    time(&cur_time);

    char *id_str = (char*)calloc(32, sizeof(char));

    sprintf(id_str, "%d_%d", wnd->connection_peer_id, wnd->flow_id);
    record_wnd_size(id_str, difftime(cur_time, global_time), wnd->last_packet_avai - wnd->last_packet_acked);

    return 0;
}



void record_wnd_size(char *id, time_t time, int size) {
    int record_size = 1024;
    FILE *fp = NULL;
    char record[record_size];
    
    if ((fp = fopen("problem2-peer.txt", "a")) == NULL) {
	perror("Error! record_wnd_size, fopen");
	exit(-1);
    }
    
    memset(record, 0, record_size);
    sprintf(record, "%s\t%10ld\t%5d\n", id, time, size);

    fputs(record, fp);

    fclose(fp);
}




/*
#ifdef _TEST_PROCESS_UDP_
#include "input_buffer.h"

int main(){

    struct user_iobuf *userbuf;
    struct GET_request_t *GET_request;
    int sock = 2;
    
    process_user_input(0, userbuf);
    GET_request = handle_line(userbuf->line_queue);
    process_outbound_udp(sock, GET_request);
    
    return 0;
}

#endif
*/
