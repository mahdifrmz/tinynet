#ifndef VEC_H
#define VEC_H

#include <stddef.h>
#include <stdlib.h>

#define VEC_INIT_CAP 16
#define VEC_GET_HDR(V) ((vec_header*)((void*)(V) - sizeof(vec_header)))

typedef struct vec_header_t
{
    size_t len;
    size_t cap;
    char _buf[0];
} vec_header;

#define vec_push(V,E)\
    do{\
        vec_header *hdr = VEC_GET_HDR((V));\
        if((V) == NULL) {\
            hdr = (vec_header*)malloc(sizeof(vec_header) + sizeof(E) * VEC_INIT_CAP);\
            hdr->len = 0;\
            hdr->cap = VEC_INIT_CAP;\
            *((void**)&(V)) = (void*)hdr->_buf;\
        }\
        if(hdr->len == hdr->cap) {\
            hdr->cap *= 2;\
            hdr = (vec_header*)realloc(hdr, sizeof(vec_header) + hdr->cap * sizeof(E));\
            *((void**)&(V)) = (void*)hdr->_buf;\
        }\
        (V)[hdr->len++] = E;\
    }while(0)

#define vec_pop(V,E)\
    do{\
        if((V)) {\
            vec_header *hdr = VEC_GET_HDR((V));\
            if(hdr->len > 0) {\
                E = (V)[--hdr->len];\
            }\
        }\
    }while(0)

#define vec_len(V) ((V) ? (VEC_GET_HDR((V))->len) : (0))

#define vec_end(V) ((V) + (vec_len(V)))

#define vec_free(V) do { if((V)) free(VEC_GET_HDR((V))) } while(0)

#define vec_foreach(I,V) for(I=(V);I<vec_end((V));I++)

#endif