#include <stdlib.h>

// TODO: Don't use malloc/free directly. Plus, check allocation errors.

void *memory_alloc(size_t size) {
	return malloc(size);
}

void memory_free(void *memory) {
	return free(memory);
}
