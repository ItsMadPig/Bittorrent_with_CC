#ifndef _PACKET_H_
#define _PACKET_H_

#include <sys/socket.h>
#include <netinet/in.h>
#include "bt_parse.h"

#define uint8 unsigned char
#define uint16 unsigned short
#define uint32 unsigned int

#define WHOHAS 0
#define IHAVE 1
#define GET 2
#define DATA 3
#define ACK 4
#define DENIED 5

#define VERSION 1
#define MAGIC 15441

#define MAX_PACKET_LEN 1500
//#define MAX_PACKET_LEN 40
#define MAX_HASH ((MAX_PACKET_LEN - HEADER_LEN) / HASH_LEN )
#define MAX_SLOT_COUNT 1024
#define HASH_LEN 20
#define HEADER_LEN 16
#define BYTE_LEN 4
#define HASH_STR_LEN 40
#define MAX_DATA (MAX_PACKET_LEN - HEADER_LEN)

#define CHUNK_SIZE (512*1024)

#define INIT_ARRAY_SIZE 128

#define RAW 0x00
#define START 0x01
#define DOWNLOADING 0x02
#define DONE 0x04
#define RESTART 0x08

#define MAX_TRIAL 10

struct addr_t {
    struct sockaddr_in *sock_addr;
    socklen_t addr_len;    
    
    struct addr_t *next;
};

struct packet_info_t {
    uint16 magic;
    uint8 version;
    uint8 type;
    uint16 header_len;
    uint16 packet_len;
    uint32 seq_num;
    uint32 ack_num;

    // not necessarily to be used
    uint8 hash_count;
    uint8 *hash_chunk;
    uint8 *data_chunk;
    
    // two usage: if it's outbound packet, peer_list is destinations
    // if it's inbound udp, peer_list is replaced by source peer
    struct list_t *peer_list;

    // time is set when the pakcet is sent out, i.e. in process_outbound_udp, switch-case DATA
    // time is checked every time peer received some packet
    time_t time; 

};

struct slot_t {

    int hash_id;
    char hash_str[HASH_STR_LEN+1];
    uint8 hash_hex[HASH_LEN];

    unsigned char status;
    
    struct list_t *peer_list; // var length of peers, which graually grows by analyzing IHAVE_packet received, and the analysis is done in GET_req_t
    bt_peer_t *selected_peer; // select peer, slot to peer
    
    //struct list_t *DATA_list;
    struct flow_wnd_t *flow_wnd;
    uint8 *received_data;

    int trial_num;
    time_t old_time;
    
};

struct peer_slot_t {
    int peer_id;
    struct slot_t *slot;
};


struct id_hash_t {
    int id;
    char* hash_string;
    
    struct id_hash_t *next;
};

struct GET_request_t {

    struct list_t *slot_list;

    struct list_t *id_hash_list; // chunk_file id_hash, it's what this GET_req wanna fetch, pay attention to its diff from config->id_hash_list

    struct list_t *peer_slot_list; // for demultiplexing, and prevent simutaneous download from a peer

    struct list_t *outbound_info_list;

    char *output_file;
    
};


struct list_t* make_WHOHAS_packet_info(struct GET_request_t *GET_request, struct list_t *peer_list);
int parse_chunkfile(struct GET_request_t * GET_request, char *chunkfile);
uint8 *info2packet(struct packet_info_t *packet_info);
struct packet_info_t *packet2info(uint8 *packet);
void str2hex(char *str, uint8 *hex);
uint8 *array2chunk(struct GET_request_t *GET_request, int slot_begin, int slot_end);

//void dump_packet_info_list(struct packet_info_t *packet_info);
//void dump_packet_info(struct packet_info_t *p);
void info_printer(void *packet_info);
void dump_hex(uint8 *hex);

void init_GET_request(struct GET_request_t **p);
void enlist_packet_info(struct packet_info_t **packet_info_list, struct packet_info_t *packet_info);
struct packet_info_t *delist_packet_info(struct packet_info_t **list);
//void dump_info_list(struct packet_info_t *list);


void enlist_id_hash(struct id_hash_t **id_hash_list, struct id_hash_t *id_hash);
struct id_hash_t *delist_id_hash(struct id_hash_t **list);
void dump_id_hash_list(struct id_hash_t *list);

struct slot_t *get_slot(struct list_t *peer_to_slot, bt_peer_t *peer);
void init_slot(struct slot_t **p);
void init_packet_info(struct packet_info_t **p);

struct list_t *make_GET_info(uint8* hash, bt_peer_t *peer);
bt_peer_t *select_peer(struct slot_t *slot, struct list_t *peer_slot_list);
int in_peer_slot_list(int peer_id, struct list_t *peer_slot_list);
struct list_t *make_single_WHOHAS_info(uint8 *hash, struct list_t *peer_list);
void init_peer_slot(struct peer_slot_t **ps);
struct list_t *make_DATA_info(uint8 *data, struct list_t *peer_list);

uint8 *fetch_data(char *chunk_file, int hash_id);
int hash2id(uint8 *hash, struct list_t *id_hash_list);
struct list_t *make_ACK_info(int ack_num, struct list_t *peer_list);

struct list_t *check_GET_req(struct GET_request_t **GET_request, struct list_t *peer_list);

int get_list_size();

void remove_peer(struct list_t *peer_slot_list, int id);

#endif
