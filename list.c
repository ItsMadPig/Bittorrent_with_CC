#include <stdlib.h>
#include <assert.h>
#include "debug.h"
#include "list.h"

/* Return pointer to list, return NULL on error  */
struct list_t *enlist(struct list_t *list, void *data) {
    struct list_item_t *t = NULL;
    assert(list != NULL);
    assert(data != NULL);

    t = (struct list_item_t *)calloc(1, sizeof(struct list_item_t));
    if (t == NULL) {
	//DPRINTF(DEBUG_LIST, "Warning! enlist, calloc return null\n");
	return NULL;
    }
    
    t->data = data;
    t->next = NULL;
    t->prev = NULL;
    
    if (list->length == 0) {
	assert(list->head == NULL);
	assert(list->end == NULL);

	list->end = t;
	list->head = list->end;
	list->length = 1;

    } else {
	assert(list->head != NULL);
	assert(list->end != NULL);

	list->end->next = t;
	t->prev = list->end;

	list->end = list->end->next;

	(list->length)++;

	assert(list->end != list->head);
    }
    return list;
}

/* delis first item  */
void *delist(struct list_t *list) {
    void *data = NULL;

    assert(list != NULL);
    if (list->length == 0) {
	//DPRINTF(DEBUG_LIST, "Warning! trying to delist an empty list\n");
	return NULL;
    }
    
    assert(list->head != NULL);
    assert(list->end != NULL);

    data = list->head->data;

    list->length -= 1;
    if (list->length == 0) {
	list->head = NULL;
	list->end = NULL;
    } else {
	list->head = list->head->next;
	list->head->prev = NULL;
    }

    return data;
}

int delist_item(struct list_t *list, struct list_item_t *item) {
    assert(list != NULL);
    assert(item != NULL);

    struct list_item_t *prev = NULL;
    struct list_item_t *next = NULL;

    if (list->length == 1) {
	assert(list->head == item);
	list->head = NULL;
	list->end = NULL;
	list->length = 0;
	return 0;
    }

    prev = item->prev;
    next = item->next;
    
    if (prev == NULL) {
	// item is head, and next exists
	assert(next != NULL);
	list->head = next;
	next->prev = NULL;
	list->length -= 1;
	return 0;
    }

    if (next == NULL) {
	// item is end, and prev exists
	assert(prev != NULL);
	list->end = prev;
	prev->next = NULL;
	list->length -= 1;
	return 0;
    }
    
    assert(prev != NULL);
    assert(next != NULL);
    prev->next = next;
    next->prev = prev;
    list->length -= 1;
    
    return 0;
}

struct list_t *init_list(struct list_t **list) {
    *list = (struct list_t *)calloc(1, sizeof(struct list_t));
    
    if (*list == NULL) {
	//DPRINTF(DEBUG_LIST, "Warning! init_list, calloc returns null\n");
	return NULL;
    }

    (*list)->head = NULL;
    (*list)->end = NULL;
    (*list)->length = 0;

    return *list;
}

/* Return list pointer on success, no way to fail  */
struct list_t *cat_list(struct list_t **p, struct list_t **q) {

    assert(p != NULL);
    assert(q != NULL);

    if ((*p)->length == 0) {
	//printf("cat_list: p is empty\n");
	return *p = *q;
    }
    if ((*q)->length == 0) {
	//printf("cat_list: q is empty\n");
	return *p;
    }

    (*p)->end->next = (*q)->head;
    (*q)->head->prev = (*p)->end;
    (*p)->end = (*q)->end;

    (*p)->length += (*q)->length;
    
    return (*p);
}

int dump_list(struct list_t *list, void(*printer)(void *data), char *delim) {
    struct list_item_t *item = NULL;
    
    assert(list != NULL);
    
    if (list->length == 0 || list->head == NULL) 
	printf("empty list");

    item = list->head;
    while ( item != NULL) {
	printer(item->data);
	printf("%s", delim);
	item = item->next;
    }
    printf("\n");

    return 0;
}

struct list_item_t *get_iterator(struct list_t *list) {
    assert(list != NULL);
    return list->head;
}

int has_next(struct list_item_t *iterator) {
    
    if (iterator == NULL)
    	return 0;
    //assert(iterator != NULL);
    return 1;
}

void *next(struct list_item_t **iterator) {
    assert(iterator != NULL);
    assert(*iterator != NULL);

    void *data = NULL;

    data = (*iterator)->data;
    *iterator = (*iterator)->next;

    return data;
}

/* Return the ind_th element of the list, ind starts from 0 */
void *list_ind(struct list_t *list, int ind) {
    struct list_item_t *iterator = NULL;
    int count;

    assert(list != NULL);
    assert(ind >= 0);
    assert(ind < list->length);
     
    count = -1;
    iterator = get_iterator(list);
    while(has_next(iterator)) {
	++count;

	if (count == ind) 
	    return next(&iterator);
	else
	    iterator = iterator->next;
    }

    return NULL;
}

struct list_item_t *list_ind_ite(struct list_t *list, int ind) {
    
    struct list_item_t *iterator = NULL;
    int count;

    assert(list != NULL);
    assert(ind >= 0);
    assert(ind < list->length);
     
    count = -1;
    iterator = get_iterator(list);
    while(has_next(iterator)) {
	++count;

	if (count == ind) 
	    return iterator;
	else
	    iterator = iterator->next;
    }

    return NULL;

}

void free_list(struct list_t *list) {
    struct list_item_t *ite = NULL;
    struct list_item_t *p = NULL;
    
    ite = get_iterator(list);
    while (has_next(ite)) {
	p = ite;
	ite = ite->next;
	free(p);
    }
}

#ifdef _TEST_LIST_

void int_printer(void *data) {
    printf("%d", *(int*)data);
}

int main(){
    int i,j,k;
    struct list_t *list = NULL;
    
    i = 42;
    j = 0;
    k = -1;

    init_list(&list);
    dump_list(list, int_printer, " ");

    enlist(list, &i);
    dump_list(list, int_printer, " ");
    enlist(list, &j);
    dump_list(list, int_printer, " ");
    enlist(list, &k);
    dump_list(list, int_printer, " ");

    int *m;
    m = list_ind(list, 2);
    printf("list_in(list, 2):%d\n", *m);
    
    m = list_ind(list, 1);
    printf("list_in(list, 1):%d\n", *m);

    m = list_ind(list, 0);
    printf("list_in(list, 0):%d\n", *m);

    //m = list_ind(list, -1);

    delist(list);
    dump_list(list, int_printer, " ");
    delist(list);
    dump_list(list, int_printer, " ");
    //delist(list);
    //dump_list(list, int_printer, " ");

    //printf("list->length:%d\n", list->length);
    //delist(list);

    free_list(list);
    printf("list_freed\n");
    
    return 0;
}

#endif
