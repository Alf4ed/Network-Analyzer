#include <stdio.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include "queue.h"

struct queue *create_queue(void) {
  struct queue *q = (struct queue *) malloc(sizeof(struct queue));
  q->head = NULL;
  q->tail = NULL;
  return(q);
}

int isempty(struct queue *q){
  return(q->head == NULL);
}

void enqueue(struct queue *q, struct pcap_pkthdr *header, const u_char *packet, int verbose){
  struct node *new_node = (struct node *) malloc(sizeof(struct node));
  new_node->header = header;
  new_node->packet = packet;
  new_node->verbose = verbose;
  new_node->next = NULL;
  if(isempty(q)){
    q->head = new_node;
    q->tail = new_node;
  }
  else{
    q->tail->next = new_node;
    q->tail = new_node;
  }
}

void dequeue(struct queue *q){
  struct node *head_node;
  if(!isempty(q)) {
    head_node = q->head;
    q->head = q->head->next;

    if(q->head == NULL) {
        q->tail = NULL;
    }
    free(head_node);
  }
}

void destroy_queue(struct queue *q){
  while(!isempty(q)){
    dequeue(q);
  }
  free(q);
}