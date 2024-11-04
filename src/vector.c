#include <stdlib.h>

typedef struct {
    void **data;    // Array of void* pointers
    size_t size;    // Number of elements in the vector
    size_t capacity; // Capacity of the vector
} Vector;

// Initialize the vector with a starting capacity
void vector_init(Vector *vector, size_t initial_capacity) {
    vector->data = malloc(initial_capacity * sizeof(void *));
    vector->size = 0;
    vector->capacity = initial_capacity;
}

// Resize the vector to the specified new capacity
void vector_resize(Vector *vector, size_t new_capacity) {
    void **new_data = realloc(vector->data, new_capacity * sizeof(void *));
    if (new_data) {
        vector->data = new_data;
        vector->capacity = new_capacity;
    }
}

// Add an element to the vector
void vector_add(Vector *vector, void *element) {
    if (vector->size == vector->capacity) {
        // Double the capacity if full
        vector_resize(vector, vector->capacity * 2);
    }
    vector->data[vector->size++] = element;
}

// Get an element at a given index
void *vector_get(Vector *vector, size_t index) {
    if (index < vector->size) {
        return vector->data[index];
    }
    return NULL; // Index out of bounds
}

// Remove an element at a given index
void vector_remove(Vector *vector, size_t index) {
    if (index < vector->size) {
        for (size_t i = index; i < vector->size - 1; i++) {
            vector->data[i] = vector->data[i + 1];
        }
        vector->size--;
    }
}

// Free the vector memory
void vector_free(Vector *vector) {
    free(vector->data);
    vector->data = NULL;
    vector->size = 0;
    vector->capacity = 0;
}
