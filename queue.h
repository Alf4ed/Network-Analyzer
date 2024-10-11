struct node {
  struct pcap_pkthdr *header;
  const u_char *packet;
  int verbose;
  struct node *next;
};

struct queue {
  struct node *head;
  struct node *tail;
};

struct queue *create_queue(void);
int isempty(struct queue *q);
void enqueue(struct queue *q, struct pcap_pkthdr *header, const u_char *packet, int verbose);
void dequeue(struct queue *q);
void destroy_queue(struct queue *q);