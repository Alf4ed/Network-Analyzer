#include "sniff.h"
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <signal.h>
#include <netinet/if_ether.h>
#include "dispatch.h"
#include "linkedlist.h"
#include <pthread.h>

int total_syn = 0;
int total_arp = 0;
int total_google = 0;
int total_facebook = 0;
struct linked_list *ip_list;
pcap_t *pcap_handle;

// mutex lock required for the shared total variables
pthread_mutex_t totals_mutex = PTHREAD_MUTEX_INITIALIZER;

// When a signal interrupt is recieved, handle it and break out of pcap_loop
// Only async-signal-safe functions are called
void signal_handler(int signum) {
  if(signum == SIGINT) {
    pcap_breakloop(pcap_handle);
  }
}

// Function called from within pcap_loop
void callback_function(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  int verbose = (int) (*args);
  // If verbose is set to 1, dump raw packet to terminal
  if(verbose) {
    dump(packet, header->len);
  }
  struct pcap_pkthdr *new_header = (struct pcap_pkthdr *) malloc(sizeof(struct pcap_pkthdr));
  *new_header = *((struct pcap_pkthdr *) header);
  add_work(new_header, packet, verbose);
}

// Returns a positive value if a>b, negative value if a<b, otherwise 0
int compare(const void *a, const void *b) {
  if((*((u_int *) a)) - (*((u_int *) b)) < 0) {
    return -1;
  }
  if((*((u_int *) a)) - (*((u_int *) b)) > 0) {
    return 1;
  }
  return 0;
}

// Cleans up resources and outputs the result of the sniffer program
void summary() {
  kill_threads();
  pthread_mutex_lock(&totals_mutex);
  // Convert linked list to array in order to find number of distinct IPs
  u_int *array = list_to_array(ip_list);
  qsort(array,total_syn,sizeof(int),compare);
  // Find number of unique IPs in the array
  int unique = 0;
  if(total_syn != 0) {
    unique = 1;
    for(int i=0; i<total_syn-1; i++) {
      if(array[i] != array[i+1]) {
        unique++;
      }
    }
  }
  // Output the information about the different network attacks
  printf("\nIntrusion Detection Report:\n");
  printf("%d SYN packets detected from %d different IPs (syn attack)\n",total_syn,unique);
  printf("%d ARP responses (cache poisoning)\n",total_arp);
  printf("%d URL Blacklist violations (%d google and %d facebook)\n",total_google+total_facebook,total_google,total_facebook);
  pthread_mutex_unlock(&totals_mutex);
  // Free the array and the linked list/linked list elements
  free(array);
  free_elements(ip_list);
  free(ip_list);
  // Terminate the program
  exit(0);
}

// Application main sniffing loop
void sniff(char *interface, int verbose) {
  // Initialise the linked list that stores ip addresses
  ip_list = create_linked_list();
  // Create the threads in the threadpool
  create_threads();
  char errbuf[PCAP_ERRBUF_SIZE];
  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
  // capturing session. check the man page of pcap_open_live()
  pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }
  // Catching and handling a signal
  signal(SIGINT,signal_handler);
  // Verbose can be either 0 or 1, therefore can cast int to char without loss of precision
  u_char arg = (u_char) verbose;
  pcap_loop(pcap_handle,-1,callback_function,&arg);
  // Closing the packet-capture handler and associated resources
  pcap_close(pcap_handle);
  // Display the output and free memory
  summary();
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}
