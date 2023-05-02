#include <stdio.h>
#include "heap.h"
#include "tested_declarations.h"
#include "rdebug.h"
#include "tested_declarations.h"
#include "rdebug.h"

int main(void) {
    heap_setup();
    char *ptr[100];
    for(int i = 0; i<5; i++)
    {
        ptr[i] = heap_malloc(123);
    }
    heap_free(ptr[0]);
    heap_free(ptr[3]);
    heap_free(ptr[1]);
    ptr[6] = heap_malloc_aligned(9538);
    ptr[7] = heap_malloc_aligned(9538);
    if(((intptr_t)ptr[6] & (intptr_t)(PAGE_SIZE - 1)) == 0)
    {
        printf("jd33");
    }

    PrintMyHeap();
    int status = heap_validate();
    if(status == 1 || status == 2 || status == 3)
    {
        return -1;
    }
    return 0;
}


