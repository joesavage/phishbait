#ifndef UTILITIES_H
#define UTILITIES_H

#define DEBUG 1

#if DEBUG
#include <assert.h>
#define ASSERT(cond) assert(cond)
#else
#define ASSERT(cond)
#endif

#define READ_BUFFER_SIZE 4095

void *memory_alloc(size_t size);
void memory_free(void *memory);

#endif
