#ifndef _CTR_SEND_RECV_H_
#define _CTR_SEND_RECV_H_

#define INIT_WND_SIZE 1
#define INIT_SSTHRESH 64
#define SLOW_START 0x01
#define CONG_AVOID 0x10

#define RTT 3
#define TIMEOUT 3
#define RESTART_TIME (2*(RTT))

#include "list.h"
#include "packet.h"

struct data_wnd_t {
    
    int connection_peer_id;

    struct list_t *packet_list; // all outbound packet here
    
    int last_packet_acked;
    int last_packet_sent;
    int last_packet_avai;

    int size;
    int ssthresh;
    int mode;

    struct list_t *ACK_list;
    
    time_t time; // updated each time this wnd receives an ack

    int flow_id; // actually, wnd id

};

struct flow_wnd_t {
    
    struct list_t *packet_list;
   
    int last_packet_read;
    int next_packet_expec;
    int last_packet_recv; 

    int size; // recv - expec

    uint8 hash[HASH_LEN];
};

void init_ctr();
void init_data_wnd(struct data_wnd_t **wnd);
void init_flow_wnd(struct flow_wnd_t **wnd);

int new_flow_wnd(); // call init_flow_wnd to add a new flow_wnd

int general_send(int sock);
struct packet_info_t *general_recv(int sock, bt_config_t *config);

int outbound_list_send(int sock);
int data_wnd_list_send(int sock);
int data_wnd_send(int sock, struct data_wnd_t *wnd);
//int ctr_enlist(struct list_t *out_list);

struct data_wnd *search_data_wnd(int id);


// basic "enlist" functions: outbound_list_en, outbound_list_cat, enlsit_data_wnd

// *reply on enlist
int outbound_list_en(void *data); 

// *rely on cat_list
int outbound_list_cat(struct list_t *out_list); 

// *rely on enlist
int enlist_data_wnd (struct data_wnd_t *wnd, struct packet_info_t *info);

// rely on general_enlist
int general_list_cat(struct list_t *info_list);

// rely on outbound_list_en, data_wnd_list_en
int general_enlist(struct packet_info_t *info);

// rely on data_wnd_list_en
int data_wnd_list_cat(struct list_t *info_list);

// rely on enlist_data_wnd
int data_wnd_list_en(struct packet_info_t *info);

int check_out_size();


struct list_t* do_inbound_ACK(struct packet_info_t *info, int sock);

/* flow control below  */
int enlist_DATA_info(struct packet_info_t *info, struct GET_request_t *GET_req);
void update_flow_wnd(struct flow_wnd_t *wnd);

//int is_fully_received();
int is_fully_received(struct flow_wnd_t *wnd, uint8 *slot_hash, uint8 **received_chunk);

int check_timeout(int sock);
int check_cong_wnd_timeout (struct data_wnd_t *wnd, int sock);
int packet_loss(struct data_wnd_t *wnd);

#endif
