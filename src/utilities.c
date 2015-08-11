#include <stdlib.h>
#include <stdio.h>

// NOTE: In future, it would be nice to avoid using malloc/free directly.

void *memory_alloc(size_t size) {
	void *result = malloc(size);
	if (!result) {
		fprintf(stderr, "'malloc' failed - insufficient storage space available.\n");
		exit(1);
	}
	return result;
}

void memory_free(void *memory) {
	return free(memory);
}
