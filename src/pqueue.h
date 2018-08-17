
#if !defined(MEDUSA_PQUEUE_H)
#define MEDUSA_PQUEUE_H

struct pqueue_head;

struct pqueue_head * pqueue_create (
        unsigned int size, unsigned int step,
        int (*compare) (void *a, void *b),
        void (*setpos) (void *entry, unsigned int position),
        unsigned int (*getpos) (void *entry));
void pqueue_destroy (struct pqueue_head *head);

unsigned int pqueue_count (struct pqueue_head *head);

int pqueue_add (struct pqueue_head *head, void *entry);
int pqueue_mod (struct pqueue_head *head, void *entry, int compare);
int pqueue_del (struct pqueue_head *head, void *entry);
int pqueue_verify (struct pqueue_head *head);

void * pqueue_pop (struct pqueue_head *head);
void * pqueue_peek (struct pqueue_head *head);

#endif
