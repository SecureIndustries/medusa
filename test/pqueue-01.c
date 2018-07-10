
#include <stdlib.h>
#include <time.h>

#include "../src/pqueue.h"

struct entry {
        int add;
        int del;
        int pri;
        int pos;
};

static int entry_compare (void *a, void *b)
{
        struct entry *ea = (struct entry *) a;
        struct entry *eb = (struct entry *) b;
        if (ea->pri < eb->pri) {
                return -1;
        }
        if (ea->pri > eb->pri) {
                return 1;
        }
        return 0;
}

static void entry_position (void *a, unsigned int p)
{
        struct entry *ea = (struct entry *) a;
        ea->pos = p;
}

int main (int argc, char *argv[])
{
        int i;
        int count;
        struct entry *entries;

        int p;
        struct entry *entry;
        struct pqueue_head pqueue;

        long int seed;

        (void) argc;
        (void) argv;

        seed = time(NULL);
        srand(seed);

        fprintf(stderr, "seed: %ld\n", seed);

        count = rand() % 10000;
        entries = malloc(sizeof(struct entry) * count);
        if (entries == NULL) {
                return -1;
        }
        for (i = 0; i < count; i++) {
                entries[i].add = 0;
                entries[i].del = 0;
                entries[i].pri = i;
                entries[i].pos = -1;
        }

        pqueue_init(&pqueue, 0, rand() % 64, entry_compare, entry_position);

        fprintf(stderr, "add\n");
        while (pqueue.count != (unsigned int) count) {
                i = rand() % count;
                if (entries[i].add == 0) {
                        pqueue_add(&pqueue, &entries[i]);
                        entries[i].add = 1;
                        fprintf(stderr, "  %d = %d\n", i, entries[i].pri);
                }
        }

        fprintf(stderr, "del\n");
        while (pqueue.count > (unsigned int) count / 2) {
                i = rand() % count;
                if (entries[i].del == 0) {
                        pqueue_del(&pqueue, entries[i].pos);
                        entries[i].del = 1;
                        fprintf(stderr, "  %d @ %d\n", entries[i].pri, entries[i].pos);
                }
        }

        fprintf(stderr, "pop\n");
        for (p = -1; pqueue.count > 0; ) {
                entry = pqueue_pop(&pqueue);
                if (entry == NULL) {
                        return -1;
                }
                fprintf(stderr, "  %d @ %d\n", entry->pri, entry->pos);
                if (entry->pri <= p) {
                        fprintf(stderr, "  %d <= %d\n", entry->pri, p);
                        return -1;
                }
                p = entry->pri;
        }

        entry = pqueue_pop(&pqueue);
        if (entry != NULL) {
                return -1;
        }

        pqueue_uninit(&pqueue);
        free(entries);

        fprintf(stderr, "finish\n");
}
