/* lar_list.h: Lan address resolution structure list defintions.
 *
 * Author:
 * Jay Schulist         <jschlst@samba.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * None of the authors or maintainers or their employers admit
 * liability nor provide warranty for any of this software.
 * This material is provided "as is" and at no charge.
 */

#ifndef _LAR_LIST_H
#define _LAR_LIST_H

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

#define list_head_init(name) { &(name), &(name) }

#define list_head(name) \
        struct list_head name = list_head_init(name)

#define list_init_head(ptr) do { \
        (ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

#define list_entry(ptr, type, member) \
        ((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

#define list_for_each(pos, head) \
        for (pos = (head)->next, (void)pos->next; pos != (head); \
                pos = pos->next, (void)pos->next)

#define list_for_each_safe(pos, n, head) \
        for (pos = (head)->next, n = pos->next; pos != (head); \
                pos = n, n = pos->next)

/* Return pointer to first true entry, if any, or NULL.  A macro
   required to allow inlining of cmpfn. */
#define list_find(head, cmpfn, type, args...)        \
({                                                      \
        const struct list_head *__i = (head);             \
                                                        \
        do {                                            \
                __i = __i->next;                        \
                if (__i == (head)) {                    \
                        __i = NULL;                     \
                        break;                          \
                }                                       \
        } while (!cmpfn((const type)__i , ## args));    \
        (type)__i;                                      \
})

extern void list_del(struct list_head *entry);
extern void list_add(struct list_head *new, struct list_head *prev,
        struct list_head *next);
extern void list_add_tail(struct list_head *new, struct list_head *head);

#endif	/* _LAR_LIST_H */
