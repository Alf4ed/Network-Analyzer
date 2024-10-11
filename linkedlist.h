#ifndef CS241_LINKEDLIST_H
#define CS241_LINKEDLIST_H

struct linked_list *create_linked_list(void);
void add_item(struct linked_list *list, u_int value);
void free_elements(struct linked_list *list);
u_int *list_to_array(struct linked_list *list);
#endif