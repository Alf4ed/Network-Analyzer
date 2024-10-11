#include "dispatch.h"
#include <pcap.h>
#include "analysis.h"
#include "queue.h"
#include <pthread.h>
#include <stdlib.h>

#define NUMTHREADS 10

int close_threads = 0;
pthread_t tid[NUMTHREADS];

/* Queue where the main server thread adds work and from where the worker threads pull work*/
struct queue *work_queue;
/* mutex lock required for the shared queue*/
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
  analyse(header, packet, verbose);
}

/*Function to be executed by each worker thread*/
void *run_thread(void *arg) {
  while(1) {
    pthread_mutex_lock(&queue_mutex);
    while(isempty(work_queue)) {
      if(close_threads == 1) {
        pthread_mutex_unlock(&queue_mutex);
        return NULL;
      }
      pthread_cond_wait(&queue_cond,&queue_mutex);
    }

    struct pcap_pkthdr *header = work_queue->head->header;
    const u_char *packet = (work_queue->head->packet);
    int verbose = (work_queue->head->verbose);

    dequeue(work_queue);
    pthread_mutex_unlock(&queue_mutex);

    dispatch(header,packet,verbose);

    free(header);
  }
  return NULL;
}

void add_work(struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {
  pthread_mutex_lock(&queue_mutex);
  enqueue(work_queue,header,packet,verbose);
  pthread_cond_broadcast(&queue_cond);
  pthread_mutex_unlock(&queue_mutex);
}

void kill_threads() {
  pthread_mutex_lock(&queue_mutex);
  close_threads = 1;
  pthread_cond_broadcast(&queue_cond);
  pthread_mutex_unlock(&queue_mutex);

  for(int i=0; i<NUMTHREADS; i++) {
    pthread_join(tid[i],NULL);
  }

  destroy_queue(work_queue);
}

void create_threads() {
  work_queue = create_queue();

  for(int i=0; i<NUMTHREADS; i++) {
    pthread_create(&tid[i], NULL, run_thread, NULL);
  }
}