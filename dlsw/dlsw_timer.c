/* dlsw_timer.h: Data link switching timers.
 *
 * Written by Jay Schulist <jschlst@samba.org>
 * Copyright (c) 2001 by Jay Schulist <jschlst@samba.org>
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
#include <signal.h>
#include <sys/time.h>

/* our stuff. */
#include "dlsw_timer.h"

typedef struct timer_s {
	struct timer_s *next;
	int one_shot;
	unsigned long value;
	unsigned long reload_value;
	timerproc_t callback;
	void *data;
} timerdata_t;
typedef timerdata_t *timerdataptr_t;

static void timer_handler(int junk);
static int timer_insert(timerdataptr_t tptr);

static struct itimerval timer;
static timerdataptr_t timer_chain;

static int timer_start_system(timerdataptr_t tptr)
{
	timerclear(&(timer.it_interval));
	timer.it_value.tv_sec  = tptr->value / 1000;
	timer.it_value.tv_usec = (tptr->value % 1000) * 1000;
	if ((long )signal(SIGALRM, timer_handler) == -1L) {
  		fprintf(stderr, "Cannot set ALARM signal\n");
  		return 1;
  	}
	if (setitimer(ITIMER_REAL, &(timer), NULL)) {
  		perror("Cannot set ITIMER\n");
  		return 1;
  	}
	return 0;
}

static void timer_handler(int junk)
{
	timerdataptr_t tptr;

	if (timer_chain == NULL) 
		return;
	timer_chain->value = 0;
	while (((tptr = timer_chain) != NULL) && (tptr->value == 0)) {
  		timer_chain = tptr->next;
  		tptr->next  = NULL;
  		if (tptr->callback != NULL) 
			(tptr->callback)(tptr->data);
  		if (tptr->one_shot == 0) {
    			tptr->value = tptr->reload_value;
    			timer_insert(tptr);
    			if (tptr == timer_chain) 
				break;
    		}
   		else
    			free(tptr);
  	}
	if (timer_chain != NULL) 
		timer_start_system(timer_chain);
	return;
}

static int timer_delete(timerdataptr_t tptr)
{
	unsigned long cur_value;
	timerdataptr_t prev, next, next_period;
	int change;

	if (timer_chain == NULL) 
		return 1;
	prev        = NULL;
	next        = timer_chain;
	next_period = timer_chain->next;
	change      = ((tptr == timer_chain) && (next_period != NULL)
               		&& (next_period->value != 0));
	if (change) 
		next_period->value += tptr->value;
	while ((next != NULL) && (next != tptr)) {
  		prev = next;
  		next = next->next;
  	}
	if (next == NULL) 
		return 1;
	if (prev == NULL)
  		timer_chain = tptr->next;
 	else
  		prev->next = tptr->next;
	if (timer_chain == NULL) {
  		if ((long)signal(SIGALRM, SIG_DFL) == -1L) 
			return 1;
  		timerclear(&(timer.it_value));
  	} else {
  		if (change == 0) {
    			free(tptr);
    			return 0;
    		}
  		getitimer(ITIMER_REAL, &(timer));
  		cur_value = (timer.it_value.tv_sec * 1000)
              		+ (timer.it_value.tv_usec / 1000);
  		cur_value = next_period->value - cur_value;
  		timer.it_value.tv_sec  = cur_value / 1000;
  		timer.it_value.tv_usec = (cur_value % 1000) * 1000;
  	}
	timerclear(&(timer.it_interval));
	if (setitimer(ITIMER_REAL, &(timer), NULL)) 
		return 1;
	free(tptr);
	return 0;
}

static int timer_insert(timerdataptr_t tptr)
{
	unsigned long cur_value;
	timerdataptr_t prev, next;

	if (timer_chain == NULL)
  		timer_chain = tptr;
 	else {
  		getitimer(ITIMER_REAL, &(timer));
  		cur_value = (timer.it_value.tv_sec * 1000)
              		+ (timer.it_value.tv_usec / 1000);
  		prev      = timer_chain;
  		next      = timer_chain->next;
  		while ((next != NULL) && ((cur_value + next->value) < tptr->value)) {
    			cur_value += next->value;
    			prev = next;
    			next = next->next;
    		}
  		tptr->value -= cur_value;
  		if (prev == NULL)
    			timer_chain = tptr;
   		else
    			prev->next = tptr;
  		if (next != NULL) {
    			next->value -= tptr->value;
    			tptr->next = next;
    		}
  	}
	return 0;
}

void *timer_start(short one_shot, unsigned long value, 
	timerproc_t proc, void *data)
{
	timerdataptr_t tptr;
	if ((tptr = (timerdataptr_t)calloc(1, sizeof(timerdata_t))) == NULL)
  		return NULL;
	tptr->one_shot     = one_shot;
	tptr->value        =
	tptr->reload_value = value;
	tptr->callback     = proc;
	tptr->data         = data;
	if (timer_chain == NULL) {
  		if (timer_start_system(tptr)) {
    			free(tptr);
    			return NULL;
    		}
	}
	if (timer_insert(tptr)) {
  		free(tptr);
  		return NULL;
  	}
	return tptr;
}

int timer_stop(void *timeout)
{
	timerdataptr_t tptr;
	if ((tptr = (timerdataptr_t)timeout) == NULL) {
		printf("timer is NULL!\n");
		return 1;
	}
	return timer_delete(tptr);
}
