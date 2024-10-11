#include "analysis.h"
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "linkedlist.h"
#include <string.h>
#include <pthread.h>

extern int total_syn;
extern int total_arp;
extern int total_google;
extern int total_facebook;
extern struct linked_list *ip_list;

// Mutex lock required for the shared total variables
extern pthread_mutex_t totals_mutex;

void format_ip(u_int ip) {
  u_int formatted[4];
  formatted[0] = (ip >> 0) & 0xFF;
  formatted[1] = (ip >> 8) & 0xFF;
  formatted[2] = (ip >> 16) & 0xFF;
  formatted[3] = (ip >> 24) & 0xFF;
  printf("%d.%d.%d.%d",formatted[3],formatted[2],formatted[1],formatted[0]);
}

void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) {

  // Pointers to the sub-packets
  const unsigned char *ip_packet;
  const unsigned char *tcp_packet;
  const unsigned char *payload;

  // Pointers to the packet headers
  struct ether_header *eth_header;
  struct iphdr *ip_header;
  struct tcphdr *tcp_header;

  eth_header = (struct ether_header *) packet;

  // Check if the packet uses the IP protocol
  if(ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    ip_packet = packet+ETH_HLEN;
    ip_header = (struct iphdr *) ip_packet;
    u_char protocol = ip_header->protocol;

    // Check if the packet uses the TCP protocol
    if(protocol == IPPROTO_TCP) {
      tcp_packet = ip_packet + (ip_header->ihl)*4;
      tcp_header = (struct tcphdr *) tcp_packet;

      // Checks the syn flag is set to 1
      if(tcp_header->syn == 1) {
        // Checks all other flags are set to 0
        if(tcp_header->urg == 0 && tcp_header->ack == 0 && tcp_header->psh == 0 && tcp_header->rst == 0 && tcp_header->fin == 0) {
          pthread_mutex_lock(&totals_mutex);
          total_syn++;
          u_int value = ntohl(ip_header->saddr);
          add_item(ip_list,value);
          pthread_mutex_unlock(&totals_mutex);
        }
      }
      // Check if TCP using port 80
      if(ntohs(tcp_header->th_dport) == 80) {
        payload = tcp_packet + (tcp_header->th_off)*4;
        int payload_length = header->caplen - ETH_HLEN - (ip_header->ihl)*4 - (tcp_header->th_off)*4;

        // Copying the payload into a NULL terminated buffer
        char buffer[payload_length+1];
        for(int i=0;i<payload_length;i++) {
          buffer[i] = *(payload+i);
        }
        buffer[payload_length] = '\0';

        // Searching for the blacklisted domains within the HTTP header
        int bad_url = 0;
        char *blacklisted = strstr(buffer,"www.google.co.uk");
        if(blacklisted != NULL) {
          bad_url = 1;
          pthread_mutex_lock(&totals_mutex);
          total_google++;
          pthread_mutex_unlock(&totals_mutex);
        }
        else {
          blacklisted = strstr(buffer,"www.facebook.com");
          if(blacklisted != NULL) {
            bad_url = 1;
            pthread_mutex_lock(&totals_mutex);
            total_facebook++;
            pthread_mutex_unlock(&totals_mutex);
          }
        }
        if(bad_url) {
          printf("========================================\n");
          printf("Blacklisted URL violation detected\n");
          printf("Source IP address: ");
          format_ip(ntohl(ip_header->saddr));
          printf("\nDestination IP address: ");
          format_ip(ntohl(ip_header->daddr));
          printf("\n========================================\n");
        }
      }
    }
  }
  // Check if the packet uses the ARP protocol
  if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
    pthread_mutex_lock(&totals_mutex);
    total_arp++;
    pthread_mutex_unlock(&totals_mutex);
  }
}