#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>

void dispatch(struct pcap_pkthdr *header, 
              const unsigned char *packet,
              int verbose);

void *run_thread(void * arg);
void create_threads();
void kill_threads();
void add_work(struct pcap_pkthdr *header, const unsigned char *packet, int verbose);

#endif