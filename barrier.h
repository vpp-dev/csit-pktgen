
typedef struct {
	volatile int *barrier;
	volatile int *num_waiting;
	int num_workers;
	uint64_t t1;
	uint64_t t2;
} worker_barrier_t;

static worker_barrier_t *
worker_barrier_init(int num_workers)
{
	worker_barrier_t * b = aligned_alloc(64, 64);
	b->barrier = aligned_alloc(64, 64);
	b->num_waiting = aligned_alloc(64, 64);
	*b->barrier = 0;
	*b->num_waiting = 0;
	b->num_workers = num_workers;
	return b;
}

static inline void
worker_barrier_check(worker_barrier_t *b)
{
	if (*b->barrier) {
		__sync_fetch_and_add(b->num_waiting,  1);
		while (*b->barrier)
			;
		__sync_fetch_and_add(b->num_waiting,  -1);
	}
}

static void
worker_barrier_sync(worker_barrier_t *b)
{
	*b->barrier = 1;
	b->t1 = rte_rdtsc_precise();
	while (*b->num_waiting < b->num_workers)
		;
}

static void
worker_barrier_release(worker_barrier_t *b)
{
	*b->barrier = 0;
	while (*b->num_waiting > 0)
		;
	b->t2 = rte_rdtsc_precise();
}

static uint64_t
worker_barrier_last_duration(worker_barrier_t *b)
{
	return (b->t2 > b->t1) ? (b->t2 - b->t1) : 0;
}


