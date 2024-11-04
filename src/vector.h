#ifndef VECTOR_H
#define VECTOR_H

#include <stdlib.h>

typedef struct {
    void **data;    // Array of void* pointers
    size_t size;    // Number of elements in the vector
    size_t capacity; // Capacity of the vector
} Vector;

void vector_init(Vector *vector, size_t initial_capacity);
void vector_resize(Vector *vector, size_t new_capacity);
void vector_add(Vector *vector, void *element);
void *vector_get(Vector *vector, size_t index);
void vector_remove(Vector *vector, size_t index);
void vector_free(Vector *vector);

#endif