#include <stdlib.h>
#include "linkedlist.h"
#include <stdio.h>

struct element {
    struct element *next;
    u_int data;
};

struct linked_list {
    struct element *head;
    int size;
};

struct linked_list *create_linked_list(void) {
    struct linked_list *list = (struct linked_list *) malloc(sizeof(struct linked_list));
    list->head = NULL;
    list->size = 0;
    return(list);
}

void add_item(struct linked_list *list, u_int value) {
    struct element *new_element = (struct element *) malloc(sizeof(struct element));
    new_element->data = value;
    new_element->next = list->head;
    list->head = new_element;
    list->size++;
}

void free_elements(struct linked_list *list) {
    void *current_element = list->head;

    while(current_element != NULL) {
        void *temp = current_element;
        current_element = ((struct element *) current_element)->next;
        free(temp);
    }
}

u_int *list_to_array(struct linked_list *list) {
    u_int *array = malloc(list->size*sizeof(int));
    struct element *current_element = list->head;
    for(int i=0; i<list->size; i++) {
        array[i] = current_element->data;
        current_element = current_element->next;
    }
    return array;
}