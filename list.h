#ifndef _LIST_H_
#define _LIST_H_

struct list_t {
    
    int length;
    
    struct list_item_t *head;
    struct list_item_t *end;

};

struct list_item_t {
    struct list_item_t *next;
    struct list_item_t *prev;
    
    void *data;
};

typedef void(*item_printer)(void *data);

/* add data to the end of the list*/
struct list_t *init_list(struct list_t **list);
struct list_t *enlist(struct list_t *list, void *data);
void *delist(struct list_t *list);
int dump_list(struct list_t *list, item_printer printer, char *delim);
struct list_t *cat_list(struct list_t **p, struct list_t **q);
struct list_item_t *get_iterator(struct list_t *list);
int has_next(struct list_item_t *iterator);
void *next(struct list_item_t **iterator);
void *list_ind(struct list_t *list, int ind);
void free_list(struct list_t *list);
int delist_item(struct list_t *list, struct list_item_t *item);
struct list_item_t *list_ind_ite(struct list_t *list, int ind);

#endif
