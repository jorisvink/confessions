/*
 * Copyright (c) 2023-2025 Joris Vink <joris@sanctorum.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>

#include <stdio.h>
#include <string.h>

#include "confession.h"

/*
 * Initialise the given ring queue with the number of elements.
 * The number of elements must be a power of 2 and must maximum
 * be 4096.
 */
void
confessions_ring_init(struct confessions_ring *ring, size_t elm)
{
	PRECOND(ring != NULL);

	memset(ring, 0, sizeof(*ring));

	ring->elm = elm;
	ring->mask = elm - 1;
}

/*
 * Dequeue an item from the given ring queue. If no items were
 * available to be dequeued, NULL is returned to the caller.
 */
void *
confessions_ring_dequeue(struct confessions_ring *ring)
{
	uintptr_t	uptr;
	u_int32_t	slot, head, tail, next;

	PRECOND(ring != NULL);

dequeue_again:
	head = confessions_atomic_read(&ring->consumer.head);
	tail = confessions_atomic_read(&ring->producer.tail);

	if ((tail - head) == 0)
		return (NULL);

	next = head + 1;
	if (!confessions_atomic_cas(&ring->consumer.head, &head, &next))
		goto dequeue_again;

	slot = head & ring->mask;
	uptr = confessions_atomic_read(&ring->data[slot]);

	while (!confessions_atomic_cas_simple(&ring->consumer.tail, head, next))
		confessions_cpu_pause();

	return ((void *)uptr);
}

/*
 * Queue the given item into the given ring queue. If no available
 * slots were available, this function will return -1.
 */
int
confessions_ring_queue(struct confessions_ring *ring, void *ptr)
{
	u_int32_t	slot, head, tail, next;

	PRECOND(ring != NULL);
	PRECOND(ptr != NULL);

queue_again:
	head = confessions_atomic_read(&ring->producer.head);
	tail = confessions_atomic_read(&ring->consumer.tail);

	if ((ring->elm + (tail - head)) == 0)
		return (-1);

	next = head + 1;
	if (!confessions_atomic_cas(&ring->producer.head, &head, &next))
		goto queue_again;

	slot = head & ring->mask;
	confessions_atomic_write(&ring->data[slot], (uintptr_t)ptr);

	while (!confessions_atomic_cas_simple(&ring->producer.tail, head, next))
		confessions_cpu_pause();

	return (0);
}
