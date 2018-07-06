
#include <sys/queue.h>

/*
 * Tail queue missing functions.
 */

#if !defined(TAILQ_FOREACH_SAFE)
#define TAILQ_FOREACH_SAFE(var, head, field, next)                        \
        for ((var) = ((head)->tqh_first);                                 \
             (var) && ((next) = ((var)->field.tqe_next), 1);              \
             (var) = (next))
#endif

#if !defined(TAILQ_FOREACH_REVERSE_SAFE)
#define TAILQ_FOREACH_REVERSE_SAFE(var, head, headname, field, tvar)      \
        for ((var) = TAILQ_LAST((head), headname);                        \
             (var) && ((tvar) = TAILQ_PREV((var), headname, field), 1);   \
             (var) = (tvar))
#endif

#if !defined(TAILQ_FIRST)
#define TAILQ_FIRST(head)                ((head)->tqh_first)
#endif

#if !defined(TAILQ_LAST)
#define TAILQ_LAST(head, headname)       (*(((struct headname *)((head)->tqh_last))->tqh_last))
#endif

#if !defined(TAILQ_NEXT)
#define TAILQ_NEXT(elm, field)           ((elm)->field.tqe_next)
#endif

#if !defined(TAILQ_PREV)
#define TAILQ_PREV(elm, headname, field) (*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))
#endif
