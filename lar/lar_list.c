/* lar_list.c: Lan address resolution structure list functions.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>

#include "lar_list.h"

void list_add(struct list_head *new, struct list_head *prev,
        struct list_head *next)
{                       
        next->prev = new;   
        new->next  = next;
        new->prev  = prev;      
        prev->next = new;       
}                                       
                                        
void list_add_tail(struct list_head *new, struct list_head *head)
{                               
        list_add(new, head->prev, head);
}                       

void __list_del(struct list_head *prev, struct list_head *next)
{                       
        next->prev = prev;
        prev->next = next;
}

void list_del(struct list_head *entry)
{
        __list_del(entry->prev, entry->next);
}
