
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct pqueue_head {
        void **entries;
        unsigned int count;
        unsigned int size;
        unsigned int step;
        int (*compare) (void *a, void *b);
        void (*position) (void *entry, unsigned int position);
};

static inline void pqueue_uninit (struct pqueue_head *head)
{
        if (head == NULL) {
                return;
        }
        if (head->entries != NULL) {
                free(head->entries);
        }
}

static inline int pqueue_init (
                struct pqueue_head *head,
                unsigned int size, unsigned int step,
                int (*compare) (void *a, void *b),
                void (*position) (void *entry, unsigned int position))
{
        memset(head, 0, sizeof(struct pqueue_head));
        head->size = size;
        head->step = step ? step : 1;
        head->compare = compare;
        head->position = position;
        if (head->size > 0) {
                head->entries = (void **) malloc(sizeof(void *) * head->size);
                if (head->entries == NULL) {
                        goto bail;
                }
        }
        return 0;
bail:   return -1;
}

static inline int pqueue_add (struct pqueue_head *head, void *entry)
{
        unsigned int i;
        unsigned int j;
        if (head->count + 1 >= head->size) {
                void **tmp;
                tmp = (void **) realloc(head->entries, sizeof(void **) * (head->size + head->step + (head->size ? 0 : 1)));
                if (tmp == NULL) {
                        tmp = (void **) malloc(sizeof(void *) * (head->size + head->step + (head->size ? 0 : 1)));
                        if (tmp == NULL) {
                                goto bail;
                        }
                        if (head->count > 0) {
                                memcpy(tmp, head->entries, sizeof(void **) * (head->count + (head->size ? 0 : 1)));
                        }
                        free(head->entries);
                }
                head->entries = tmp;
                head->size = head->size + head->step + (head->size ? 0 : 1);
        }
        i = head->count + 1;
        j = i / 2;
        while ((i > 1) && (head->compare(head->entries[j], entry) > 0)) {
                head->entries[i] = head->entries[j];
                head->position(head->entries[i], i);
                i = j;
                j = j / 2;
        }
        head->entries[i] = entry;
        head->position(head->entries[i], i);
        head->count++;
        return 0;
bail:   return -1;
}

static inline void pqueue_heapify (struct pqueue_head *head, unsigned int i)
{
        void *entry;

        unsigned int l;
        unsigned int r;
        unsigned int k;

        while (1) {
                l = i * 2;
                r = i * 2 + 1;
                k = i;

                if (head->count >= l &&
                    head->compare(head->entries[l], head->entries[k]) < 0) {
                        k = l;
                }
                if (head->count >= r &&
                    head->compare(head->entries[r], head->entries[k]) < 0) {
                        k = r;
                }
                if (k == i) {
                        break;
                }

                entry = head->entries[k];

                head->entries[k] = head->entries[i];
                head->position(head->entries[k], k);

                head->entries[i] = entry;
                head->position(head->entries[i], i);

                i = k;
        }
}

static inline int pqueue_del (struct pqueue_head *head, unsigned int position)
{
        unsigned int i;
        if (position > head->count + 1) {
                return -1;
        }
        head->entries[position] = head->entries[head->count];
        head->position(head->entries[position], position);
        head->count--;
        for (i = head->count / 2; i > 0; i--) {
                pqueue_heapify(head, i);
        }
        return 0;
}

static inline void * pqueue_peek (struct pqueue_head *head)
{
        void *entry;
        if (!head->count) {
                return NULL;
        }
        entry = head->entries[1];
        return entry;
}

static inline void * pqueue_pop (struct pqueue_head *head)
{
        void *entry;
        unsigned int i;
        unsigned int j;
        unsigned int k;
        if (!head->count) {
                return NULL;
        }
        entry = head->entries[1];
        head->entries[1] = head->entries[head->count];
        head->position(head->entries[1], 1);
        head->count--;
#if 0
        pqueue_heapify(head, 1);
#else
        i = 1;
        while (i != head->count + 1) {
                k = head->count + 1;
                j = i * 2;
                if ((j <= head->count) && (head->compare(head->entries[j], head->entries[k]) < 0)) {
                        k = j;
                }
                if ((j + 1 <= head->count) && (head->compare(head->entries[j + 1], head->entries[k]) < 0)) {
                        k = j + 1;
                }
                head->entries[i] = head->entries[k];
                head->position(head->entries[i], i);
                i = k;
        }
#endif
        return entry;
}
