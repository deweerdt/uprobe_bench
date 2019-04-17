#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <stdio.h>
#include <assert.h>

volatile int never = 0;
void __attribute__((noinline)) g(int i)
{
	if (never) {
		fprintf(stderr, "%s:%d %d\n", __func__, __LINE__, i);
	}
}

void *f(void *a)
{
	unsigned long i = 0, prev_i = 0;
	struct timespec ts;
	int ret;
	unsigned prev_sec = 0;
	while (1) {
		ret = clock_gettime(CLOCK_MONOTONIC, &ts);
		assert(ret == 0);
		if (ts.tv_sec != prev_sec) {
			if (prev_sec != 0) {
				fprintf(stderr, "%" PRIu64 "\n", i - prev_i);
			}
			prev_i = i;
			prev_sec = ts.tv_sec;
		}
		i++;
		if ((i % 100) == 0) {
			g(i);
		}
	}
}

int main(int argc, char **argv)
{
	unsigned nr_threads = 2;
	if (argc >= 2) {
		nr_threads = strtoul(argv[1], NULL, 10);
	}
	pthread_t t[nr_threads];
	int ret; 
	unsigned i;
	for (i = 0; i < nr_threads; i++) {
		ret = pthread_create(&t[i], NULL, f, NULL);
		assert(ret == 0);
	}
	for (i = 0; i < nr_threads; i++) {
		pthread_join(t[i], NULL);
	}

	return 0;
}
