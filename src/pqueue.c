
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "pqueue.h"

#if !defined(MAX)
#define MAX(a, b)               (((a) > (b)) ? (a) : (b))
#endif

#define pqueue_left(i)          (2 * (i))
#define pqueue_right(i)         ((2 * (i)) + 1)
#define pqueue_parent(i)        ((i) / 2)

struct pqueue_head {
        void **entries;
        unsigned int count;
        unsigned int size;
        unsigned int step;
        int (*cmp) (void *a, void *b);
        void (*setpos) (void *entry, unsigned int position);
        unsigned int (*getpos) (void *entry);
};

struct pqueue_head * pqueue_create (
        unsigned int size, unsigned int step,
        int (*cmp) (void *a, void *b),
        void (*setpos) (void *entry, unsigned int position),
        unsigned int (*getpos) (void *entry))
{
        struct pqueue_head *head;
        head = malloc(sizeof(struct pqueue_head));
        if (head == NULL) {
                goto bail;
        }
        memset(head, 0, sizeof(struct pqueue_head));
        head->size = size;
        head->step = step ? step : 1;
        head->cmp = cmp;
        head->setpos = setpos;
        head->getpos = getpos;
        head->count = 1;
        if (head->size > 0) {
                head->entries = (void **) malloc(sizeof(void *) * head->size);
                if (head->entries == NULL) {
                        goto bail;
                }
        }
        return head;
bail:   if (head != NULL) {
                pqueue_destroy(head);
        }
        return NULL;
}

void pqueue_destroy (struct pqueue_head *head)
{
        if (head == NULL) {
                return;
        }
        if (head->entries != NULL) {
                free(head->entries);
        }
        free(head);
}

unsigned int pqueue_count (struct pqueue_head *head)
{
        return head->count -1;
}

void pqueue_heapify (struct pqueue_head *head, unsigned int i)
{
        void *entry;

        unsigned int l;
        unsigned int r;
        unsigned int k;

        while (1) {
                l = i * 2;
                r = i * 2 + 1;
                k = i;

                if (head->count > l &&
                    head->cmp(head->entries[l], head->entries[k]) < 0) {
                        k = l;
                }
                if (head->count > r &&
                    head->cmp(head->entries[r], head->entries[k]) < 0) {
                        k = r;
                }
                if (k == i) {
                        break;
                }

                entry = head->entries[k];

                head->entries[k] = head->entries[i];
                head->setpos(head->entries[k], k);

                head->entries[i] = entry;
                head->setpos(head->entries[i], i);

                i = k;
        }
}

static inline void pqueue_shift_up (struct pqueue_head *head, unsigned int i)
{
        void *e;
        unsigned int p;
        e = head->entries[i];
        p = pqueue_parent(i);
        while ((i > 1) && (head->cmp(head->entries[p], e) > 0)) {
                head->entries[i] = head->entries[p];
                head->setpos(head->entries[i], i);
                i = p;
                p = pqueue_parent(i);
        }
        head->entries[i] = e;
        head->setpos(e, i);
}

static inline void pqueue_shift_down (struct pqueue_head *head, unsigned int i)
{
        void *e;
        unsigned int c;
        e = head->entries[i];
        while (1) {
                c = pqueue_left(i);
                if (c >= head->count) {
                        break;
                }
                if ((c + 1 < head->count) &&
                    (head->cmp(head->entries[c], head->entries[c + 1]) > 0)) {
                        c += 1;
                }
                if (!(head->cmp(e, head->entries[c]) > 0)) {
                        break;
                }
                head->entries[i] = head->entries[c];
                head->setpos(head->entries[i], i);
                i = c;
        }
        head->entries[i] = e;
        head->setpos(e, i);
}

int pqueue_add (struct pqueue_head *head, void *entry)
{
        unsigned int i;
        if (head->count + 1 >= head->size) {
                void **tmp;
                unsigned int size;
                size = MAX(head->count + 1, head->size + head->step);
                tmp = (void **) realloc(head->entries, sizeof(void **) * size);
                if (tmp == NULL) {
                        tmp = (void **) malloc(sizeof(void *) * size);
                        if (tmp == NULL) {
                                goto bail;
                        }
                        if (head->count > 0) {
                                memcpy(tmp, head->entries, sizeof(void **) * size);
                        }
                        free(head->entries);
                }
                head->entries = tmp;
                head->size = size;
        }
        i = head->count++;
        head->entries[i] = entry;
        head->setpos(entry, i);
        pqueue_shift_up(head, i);
        return 0;
bail:   return -1;
}

int pqueue_mod (struct pqueue_head *head, void *entry)
{
        unsigned int i;
        unsigned int p;
        i = head->getpos(entry);
        p = pqueue_parent(i);
        if (p > 1 && head->cmp(head->entries[p], head->entries[i]) > 0) {
                pqueue_shift_up(head, i);
        } else {
#if 0
                for (i = head->count / 2; i > 0; i--) {
                        pqueue_heapify(head, i);
                }
#else
                pqueue_shift_down(head, i);
#endif
        }
        return 0;
}

int pqueue_del (struct pqueue_head *head, void *entry)
{
        unsigned int i;
        i = head->getpos(entry);
        head->entries[i] = head->entries[--head->count];
        if (head->cmp(entry, head->entries[i]) > 0) {
                pqueue_shift_up(head, i);
        } else {
                pqueue_shift_down(head, i);
        }
        head->setpos(entry, -1);
        return 0;
}

void * pqueue_pop (struct pqueue_head *head)
{
        void *e;
        if (head->count == 1) {
                return NULL;
        }
        e = head->entries[1];
        head->entries[1] = head->entries[--head->count];
        pqueue_shift_down(head, 1);
        head->setpos(e, -1);
        return e;
}

void * pqueue_peek (struct pqueue_head *head)
{
        void *e;
        if (head->count == 1) {
                return NULL;
        }
        e = head->entries[1];
        return e;
}
