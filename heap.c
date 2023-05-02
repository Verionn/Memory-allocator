#include "heap.h"
#include <stdio.h>
#include <string.h>
#include "custom_unistd.h"
#include "tested_declarations.h"
#include "rdebug.h"

#define ZAOKRAGLENIE 8
int align_size(int size) {
    return (size + ZAOKRAGLENIE - 1) & ~(ZAOKRAGLENIE - 1);
}
int empty = 0;
struct memory_manager_t memory_manager;

void SetMyFences(struct memory_chunk_t *ptr)
{
    memset((void*)((char *) ptr + sizeof(struct memory_chunk_t)), '#', FENCE);
    memset((void*)((char *) ptr + ptr->size + sizeof(struct memory_chunk_t) +FENCE), '#', FENCE);
}
size_t find_me_good_size_of_page(size_t size)
{
    size_t page = 4096;
    while(1)
    {
        if(size > page)
        {
            page += 4096;
        }
        else
        {
            return page;
        }
    }
}
struct memory_chunk_t* find_chunk(size_t size)
{
    struct memory_chunk_t *ptr = memory_manager.first_memory_chunk;
    while(ptr)
    {
        if(ptr->original_size >= size)
        {
            if(ptr->free == 1)
            {
                return ptr;
            }
        }
        ptr = ptr->next;
    }
    return NULL;

}
struct memory_chunk_t* find_chunk_aligned(size_t size)
{
    struct memory_chunk_t *ptr = memory_manager.first_memory_chunk;
    while(ptr)
    {
        if(ptr->original_size >= size)
        {
            if(ptr->free == 1)
            {
                void* address = (void*)((char*)ptr + sizeof(struct memory_chunk_t) + FENCE);
                if(((intptr_t)address & (intptr_t)(PAGE_SIZE - 1)) == 0)
                {
                    return ptr;
                }
            }
        }
        ptr = ptr->next;
    }
    return NULL;

}
void PrintMyHeap(void)
{
    struct memory_chunk_t *ptr = memory_manager.first_memory_chunk;
    printf("===============\n");
    int counter = 0;
    int free_blocks = 0;
    while(ptr)
    {
        printf("%d - Size: %zu | Free: %d | Original Size: %zu | Address: %lu\n", counter,ptr->size, ptr->free, ptr->original_size, (intptr_t)ptr);
        if(ptr->free == 0)
        {
            free_blocks++;
        }
        ptr = ptr->next;
        counter++;
    }
    printf("===============\n");
    printf("Ilosc blokow: %d\n", counter);
    printf("Ilosc niezwolnionych blokow: %d\n", free_blocks);
}
struct memory_chunk_t* ReturnMeLastChunk(void)
{
    struct memory_chunk_t* ptr= memory_manager.first_memory_chunk;
    while(ptr)
    {
        if(ptr->next == NULL)
        {
            return ptr;
        }
        else
        {
            ptr = ptr->next;
        }
    }
    return NULL;
}
long hash_memory_chunk(struct memory_chunk_t* chunk)
{
    long result = 0;

    for (size_t i = 0; i < 40; ++i)
    {
        result += ((unsigned char*)chunk)[i];
        result %= 97;
    }

    return result;
}
int connect_chunks(struct memory_chunk_t *chunk)
{
    if(!chunk)
    {
        return -1;
    }
    int res = 0;
    if(chunk->next)
    {
        if(chunk->next->free == 1)
        {
            res = 1;
            struct memory_chunk_t *next_chunk = chunk->next;
            chunk->original_size += next_chunk->original_size;
            void* address1 = (void*)((char*)chunk + sizeof(struct memory_chunk_t) + FENCE);
            void* address2 = (void*)((char*)next_chunk + sizeof(struct memory_chunk_t) + FENCE);
            if(((intptr_t)address1 & (intptr_t)(PAGE_SIZE - 1)) != 0 || ((intptr_t)address2 & (intptr_t)(PAGE_SIZE - 1)) != 0)
            {
                chunk->original_size += sizeof(struct memory_chunk_t) + 2 * FENCE;
            }
            chunk->size = chunk->original_size;
            if(next_chunk->next)
            {
                chunk->next = next_chunk->next;
                next_chunk->next->prev = chunk;
                next_chunk->next->hash = hash_memory_chunk(next_chunk->next);
            }
            else
            {
                chunk->next = NULL;
            }
            SetMyFences(chunk);
        }
    }
    if(chunk->prev)
    {
        if (chunk->prev->free == 1)
        {
            res = 1;
            struct memory_chunk_t *prev_chunk = chunk->prev;
            prev_chunk->original_size += chunk->original_size;
            void* address1 = (void*)((char*)chunk + sizeof(struct memory_chunk_t) + FENCE);
            void* address2 = (void*)((char*)prev_chunk + sizeof(struct memory_chunk_t) + FENCE);
            if(((intptr_t)address1 & (intptr_t)(PAGE_SIZE - 1)) != 0 || ((intptr_t)address2 & (intptr_t)(PAGE_SIZE - 1)) != 0)
            {
                prev_chunk->original_size += sizeof(struct memory_chunk_t) + 2 * FENCE;
            }
            if(chunk->next)
            {
                prev_chunk->next = chunk->next;
                chunk->next->prev = prev_chunk;
                chunk->next->hash = hash_memory_chunk(chunk->next);
            }
            else
            {
                prev_chunk->next = NULL;
            }
            prev_chunk->size = prev_chunk->original_size;
            SetMyFences(prev_chunk);
            prev_chunk->hash = hash_memory_chunk(prev_chunk);
        }
    }
    return res;
}
int heap_setup(void)
{
    memory_manager.memory_start = custom_sbrk(4096);
    memory_manager.memory_size = 4096;
    memory_manager.first_memory_chunk = NULL;
    empty = 0;
    return 0;
}
void heap_clean(void)
{
    if(empty == 1)
    {
        return;
    }
    memset(memory_manager.memory_start, 0, memory_manager.memory_size);
    custom_sbrk((intptr_t)-memory_manager.memory_size);
    empty = 1;
}
void* heap_malloc(size_t size)
{
    if(size == 0)
    {
        return NULL;
    }
    size_t aligned_size = align_size((int)size);
    void* request = custom_sbrk((intptr_t)(aligned_size));
    if(request == (void*) -1)
    {
        return NULL;
    }
    memory_manager.memory_size +=aligned_size;
    struct memory_chunk_t *ptr;
    if(memory_manager.first_memory_chunk == NULL)
    {
        ptr = memory_manager.memory_start;
        ptr->next = NULL;
        ptr->free = 0;
        ptr->size = size;
        ptr->original_size = aligned_size;
        ptr->prev = NULL;
        ptr->hash = hash_memory_chunk(ptr);
        memory_manager.first_memory_chunk = ptr;
        SetMyFences(memory_manager.first_memory_chunk);
    }
    else
    {
        ptr = find_chunk(size);
        if(ptr == NULL)
        {
            struct memory_chunk_t* last_ptr = ReturnMeLastChunk();
            ptr = (struct memory_chunk_t*)((char*)last_ptr + sizeof(struct memory_chunk_t) + FENCE + last_ptr->original_size + FENCE);
            ptr->size = size;
            ptr->original_size = aligned_size;
            ptr->free = 0;
            SetMyFences(ptr);
            ptr->next = NULL;
            ptr->prev = last_ptr;
            ptr->hash = hash_memory_chunk(ptr);
            last_ptr->next = ptr;
            last_ptr->hash = hash_memory_chunk(last_ptr);
        }
        else
        {
            ptr->size = size;
            ptr->free = 0;
            ptr->hash = hash_memory_chunk(ptr);
            SetMyFences(ptr);

        }
    }
    //PrintMyHeap();
    return (void*)((char*)ptr + sizeof(struct memory_chunk_t) + FENCE);
}
void* heap_calloc(size_t number, size_t size)
{
    if(size == 0 || number == 0)
    {
        return NULL;
    }

    size_t aligned_size = align_size((int)(size*number));
    void* request = custom_sbrk((intptr_t)(aligned_size));
    if(request == (void*) -1)
    {
        return NULL;
    }
    memory_manager.memory_size +=aligned_size;
    struct memory_chunk_t *ptr;
    if(memory_manager.first_memory_chunk == NULL)
    {
        ptr = memory_manager.memory_start;
        ptr->next = NULL;
        ptr->free = 0;
        ptr->size = size*number;
        ptr->original_size = aligned_size;
        ptr->prev = NULL;
        ptr->hash = hash_memory_chunk(ptr);
        memory_manager.first_memory_chunk = ptr;
        SetMyFences(memory_manager.first_memory_chunk);
        memset((void*)((char*)ptr+sizeof(struct memory_chunk_t)+FENCE),0,size*number);
    }
    else
    {
        ptr = find_chunk(aligned_size);
        if(ptr == NULL)
        {
            struct memory_chunk_t* last_ptr = ReturnMeLastChunk();
            ptr = (struct memory_chunk_t*)((char*)last_ptr + sizeof(struct memory_chunk_t) + FENCE + align_size((int)last_ptr->original_size) + FENCE);
            ptr->size = size*number;
            ptr->original_size = aligned_size;
            ptr->free = 0;
            SetMyFences(ptr);
            memset((void*)((char*)ptr+sizeof(struct memory_chunk_t)+FENCE),0,size*number);
            ptr->next = NULL;
            ptr->prev = last_ptr;
            ptr->hash = hash_memory_chunk(ptr);
            last_ptr->next = ptr;
            last_ptr->hash = hash_memory_chunk(last_ptr);
        }
        else
        {
            ptr->size = size*number;
            ptr->free = 0;
            ptr->hash = hash_memory_chunk(ptr);
            memset((void*)((char*)ptr+sizeof(struct memory_chunk_t)+FENCE),0,ptr->size);
            SetMyFences(ptr);

        }
    }
    return (void*)((char*)ptr + sizeof(struct memory_chunk_t) + FENCE);
}
int Check_Everything(void* memblock)
{
    if(empty == 1)
    {
        return -1;
    }
    int status = heap_validate();
    if(status != 0)
    {
        return -1;
    }
    enum pointer_type_t typ = get_pointer_type(memblock);
    if(typ == pointer_inside_data_block || typ == pointer_unallocated)
    {
        return -1;
    }
    return 0;
}
void* heap_realloc(void* memblock, size_t count)
{
    if(Check_Everything(memblock) == -1)
    {
        return NULL;
    }
    enum pointer_type_t ptr_type = get_pointer_type(memblock);
    if(ptr_type == pointer_inside_data_block || ptr_type == pointer_control_block)
    {
        return NULL;
    }
    if(memblock == NULL)
    {
        return heap_malloc(count);
    }
    struct memory_chunk_t *ptr = (struct memory_chunk_t*)((char*)memblock-sizeof(struct memory_chunk_t)-FENCE);
    if(count == 0)
    {
        heap_free(memblock);
        return NULL;
    }
    if(ptr->size == count)
    {
        return memblock;
    }
    else if(ptr->original_size > count)
    {
        ptr->size = count;
        SetMyFences(ptr);
        ptr->hash = hash_memory_chunk(ptr);
        return memblock;
    }
    if(ptr->next && ptr->next->free == 1)
    {
        size_t free_memory = (size_t)(ptr->original_size + ptr->next->original_size + 2*FENCE + sizeof(struct memory_chunk_t));
        if(free_memory >= count)
        {
            size_t real_size = free_memory - align_size((int)count);
            if(real_size <= 64)
            {
                ptr->size = count;
                ptr->original_size = align_size((int)count);
                if(ptr->next->next)
                {
                    if(ptr->prev)
                    {
                        ptr->next->next->prev = ptr;
                    }
                    else
                    {
                        ptr->next->next->prev = NULL;
                    }
                    ptr->next->next->hash = hash_memory_chunk(ptr->next->next);
                    ptr->next = ptr->next->next;
                }
                else
                {
                    ptr->next = NULL;
                }
                SetMyFences(ptr);
                ptr->hash = hash_memory_chunk(ptr);
                return memblock;
            }
            else
            {
                size_t new_size = ptr->original_size + ptr->next->original_size - align_size((int)count);
                struct memory_chunk_t *save_next_ptr;
                if(ptr->next->next)
                {
                    save_next_ptr = ptr->next->next;
                }
                else
                {
                    save_next_ptr = NULL;
                }
                ptr->size = count;
                ptr->original_size = align_size((int)count);
                struct memory_chunk_t *updated_chunk = (struct memory_chunk_t*)((char*)ptr+sizeof(struct memory_chunk_t)+FENCE+ptr->original_size+FENCE);
                updated_chunk->prev = ptr;
                updated_chunk->size = new_size;
                updated_chunk->original_size = align_size((int)new_size);
                ptr->next = updated_chunk;
                if(save_next_ptr)
                {
                    save_next_ptr->prev = updated_chunk;
                }
                updated_chunk->next = save_next_ptr;
                updated_chunk->free = 1;
                SetMyFences(ptr);
                SetMyFences(updated_chunk);
                ptr->hash = hash_memory_chunk(ptr);
                updated_chunk->hash = hash_memory_chunk(updated_chunk);
                if(save_next_ptr)
                {
                    save_next_ptr->hash = hash_memory_chunk(save_next_ptr);
                }
                return memblock;
            }
        }
    }
    if(!ptr->next)
    {
        size_t used_mem = (size_t)((char*)ptr - (char*)memory_manager.first_memory_chunk)+ count + 2*FENCE + sizeof(struct memory_chunk_t);
        if(memory_manager.memory_size < used_mem)
        {
            if(custom_sbrk((int)count) == (void*)-1)
            {
                return NULL;
            }
            memory_manager.memory_size +=count;
        }
        ptr->size = count;
        ptr->original_size = align_size((int)count);
        ptr->hash = hash_memory_chunk(ptr);
        SetMyFences(ptr);
        return memblock;
    }
    void *new_ptr = heap_malloc(count);
    if(!new_ptr)
    {
        return NULL;
    }
    memcpy(new_ptr, memblock, count);
    heap_free(memblock);
    return new_ptr;
}
int IsPointerGood(void *memblock)
{
    if(memory_manager.first_memory_chunk)
    {
        struct memory_chunk_t *wsk = memory_manager.first_memory_chunk;
        while (wsk)
        {
            if((void*) ((char*) wsk) == (void*) ((char*) memblock - sizeof(struct memory_chunk_t) - FENCE))
            {
                return 0;
            }
            wsk = wsk->next;
        }
    }
    else
    {
        return -1;
    }
    return -1;
}
void heap_free(void* memblock)
{
    if(memblock == NULL || empty == 1)
    {
        return;
    }
    if(IsPointerGood(memblock) == -1)
    {
        return;
    }
    struct memory_chunk_t *ptr = (struct memory_chunk_t*)((char*)memblock - sizeof(struct memory_chunk_t)-FENCE);
    ptr->free = 1;
    ptr->size = ptr->original_size;
    if(connect_chunks(ptr) == 0)
    {
        SetMyFences(ptr);
    }
    ptr->hash = hash_memory_chunk(ptr);
}
size_t heap_get_largest_used_block_size(void)
{
    if(!memory_manager.first_memory_chunk || memory_manager.memory_size == 0 || empty == 1)
    {
        return 0;
    }
    int status = heap_validate();
    if(status == 1 || status == 2 || status == 3)
    {
        return 0;
    }
    size_t Max_Mem = 0;
    struct memory_chunk_t *ptr = memory_manager.first_memory_chunk;
    while(ptr)
    {
        if(ptr->size > Max_Mem && ptr->free == 0)
        {
            Max_Mem = ptr->size;
        }
        ptr = ptr->next;
    }
    return Max_Mem;
}
enum pointer_type_t get_pointer_type(const void* const pointer)
{
    if(pointer == NULL)
    {
        return pointer_null;
    }
    struct memory_chunk_t *chunk = memory_manager.first_memory_chunk;
    while(chunk)
    {
        if ((char *) pointer >= (char *) chunk+sizeof(struct memory_chunk_t) + chunk->size + 2*FENCE)
        {
            chunk = chunk->next;
        }
        else
        {
            break;
        }
    }
    if((char*)chunk+sizeof(struct memory_chunk_t)+FENCE == (char*)pointer)
    {
        if(chunk->free == 1)
        {
            return pointer_unallocated;
        }
        else
        {
            return pointer_valid;
        }
    }
    else
    {
        if(chunk && chunk->free == 0)
        {
            for(int i = 0; i<FENCE; i++)
            {
                if((char*)chunk+sizeof(struct memory_chunk_t)+i == (char*)pointer)
                {
                    return pointer_inside_fences;
                }
            }
            for(int i = 0; i<FENCE; i++)
            {
                if((char*)chunk+sizeof(struct memory_chunk_t)+FENCE+chunk->size+i == (char*)pointer)
                {
                    return pointer_inside_fences;
                }
            }
            for(size_t i = 1; i <= chunk->size;i++)
            {
                if((char*)chunk+sizeof(struct memory_chunk_t)+FENCE+i == (char*)pointer)
                {
                    return pointer_inside_data_block;
                }
            }
            for(unsigned long i = 0; i < sizeof(struct memory_chunk_t); i++)
            {
                if((char*)chunk+i == (char*)pointer)
                {
                    return pointer_control_block;
                }
            }
        }
    }
    return pointer_unallocated;
}
int heap_validate(void)
{
    if(empty == 1)
    {
        return 2;
    }
    struct memory_chunk_t *ptr = memory_manager.first_memory_chunk;
    while(ptr)
    {
        long check_suma = hash_memory_chunk(ptr);
        if(check_suma != ptr->hash)
        {

            return 3;
        }
        char *wsk = (char*)ptr+sizeof(struct memory_chunk_t);
        for(int i = 0; i < FENCE; i++)
        {
            if(*wsk != '#')
            {
                return 1;
            }
            wsk++;
        }
        wsk = (char*)ptr + sizeof(struct memory_chunk_t) + FENCE + ptr->size;
        for(int i = 0; i < FENCE; i++)
        {
            if(*wsk != '#')
            {
                return 1;
            }
            wsk++;
        }
        ptr = ptr->next;
    }
    return 0;
}
struct memory_chunk_t* move_forward_until_aligned(struct memory_chunk_t* chunk) {
    while(1)
    {
        //printf("[%lu]\n", (intptr_t)chunk);
        if(((intptr_t)chunk & (intptr_t)(PAGE_SIZE - 1)) == 0)
        {
            chunk = (struct memory_chunk_t*)((char*)chunk - sizeof(struct memory_chunk_t) - FENCE);
            return chunk;
        }
        else
        {
            chunk = (struct memory_chunk_t*)((char*)chunk + 1);
        }
    }
}
void* heap_malloc_aligned(size_t count)
{
    if(count == 0)
    {
        return NULL;
    }
    size_t aligned_size = align_size((int)count);
    uint64_t used_mem = custom_sbrk_get_reserved_memory();
    if(used_mem < memory_manager.memory_size+ 2 * PAGE + aligned_size)
    {
        void* request = custom_sbrk((intptr_t)(2 * PAGE + aligned_size));
        if(request == (void*) -1)
        {
            return NULL;
        }
        memory_manager.memory_size += 2 * PAGE + aligned_size;
    }
    //PrintMyHeap();
    struct memory_chunk_t *ptr;
    if(memory_manager.first_memory_chunk == NULL)
    {
        ptr = (struct memory_chunk_t*)((char*)memory_manager.memory_start + PAGE - sizeof(struct memory_chunk_t) - FENCE);
        ptr->next = NULL;
        ptr->free = 0;
        ptr->size = count;
        ptr->original_size = find_me_good_size_of_page(count);
        ptr->prev = NULL;
        ptr->hash = hash_memory_chunk(ptr);
        memory_manager.first_memory_chunk = ptr;
        SetMyFences(ptr);
    }
    else
    {
        ptr = find_chunk_aligned(count);
        if(ptr == NULL)
        {
            struct memory_chunk_t* last_ptr = ReturnMeLastChunk();
            ptr = (struct memory_chunk_t*)((char*)last_ptr + last_ptr->original_size+PAGE);
            ptr = move_forward_until_aligned(ptr);
            ptr->size = count;
            ptr->original_size = find_me_good_size_of_page(count);
            ptr->free = 0;
            SetMyFences(ptr);
            ptr->next = NULL;
            ptr->prev = last_ptr;
            ptr->hash = hash_memory_chunk(ptr);
            last_ptr->next = ptr;
            last_ptr->hash = hash_memory_chunk(last_ptr);
        }
        else
        {
            ptr->size = count;
            ptr->free = 0;
            ptr->hash = hash_memory_chunk(ptr);
            SetMyFences(ptr);

        }
    }
    //PrintMyHeap();
    return (void*)((char*)ptr + sizeof(struct memory_chunk_t) + FENCE);
}
void* heap_calloc_aligned(size_t number, size_t size)
{
    if(size == 0 || number == 0)
    {
        return NULL;
    }
    size_t aligned_size = align_size((int)size*number);
    uint64_t used_mem = custom_sbrk_get_reserved_memory();
    if(used_mem < memory_manager.memory_size+ 2 * PAGE + aligned_size)
    {
        void* request = custom_sbrk((intptr_t)(2 * PAGE + aligned_size));
        if(request == (void*) -1)
        {
            return NULL;
        }
        memory_manager.memory_size += 2 * PAGE + aligned_size;
    }
    struct memory_chunk_t *ptr;
    if(memory_manager.first_memory_chunk == NULL)
    {
        ptr = (struct memory_chunk_t*)((char*)memory_manager.memory_start + PAGE - sizeof(struct memory_chunk_t) - FENCE);
        ptr->next = NULL;
        ptr->free = 0;
        ptr->size = size*number;
        memset((void*)((char*)ptr+sizeof(struct memory_chunk_t)+FENCE),0,ptr->size);
        ptr->original_size = find_me_good_size_of_page(size*number);
        ptr->prev = NULL;
        ptr->hash = hash_memory_chunk(ptr);
        memory_manager.first_memory_chunk = ptr;
        SetMyFences(ptr);
    }
    else
    {
        ptr = find_chunk_aligned(size*number);
        if(ptr == NULL)
        {
            struct memory_chunk_t* last_ptr = ReturnMeLastChunk();
            ptr = (struct memory_chunk_t*)((char*)last_ptr + last_ptr->original_size+PAGE);
            ptr = move_forward_until_aligned(ptr);
            ptr->size = size*number;
            ptr->original_size = find_me_good_size_of_page(size*number);
            memset((void*)((char*)ptr+sizeof(struct memory_chunk_t)+FENCE),0,ptr->size);
            ptr->free = 0;
            SetMyFences(ptr);
            ptr->next = NULL;
            ptr->prev = last_ptr;
            ptr->hash = hash_memory_chunk(ptr);
            last_ptr->next = ptr;
            last_ptr->hash = hash_memory_chunk(last_ptr);
        }
        else
        {
            ptr->size = size*number;
            ptr->free = 0;
            ptr->hash = hash_memory_chunk(ptr);
            memset((void*)((char*)ptr+sizeof(struct memory_chunk_t)+FENCE),0,ptr->size);
            SetMyFences(ptr);

        }
    }
    return (void*)((char*)ptr + sizeof(struct memory_chunk_t) + FENCE);
}
void* heap_realloc_aligned(void* memblock, size_t size)
{
    if(Check_Everything(memblock) == -1)
    {
        return NULL;
    }
    enum pointer_type_t ptr_type = get_pointer_type(memblock);
    if(ptr_type == pointer_inside_data_block || ptr_type == pointer_control_block)
    {
        return NULL;
    }
    if(memblock == NULL)
    {
        return heap_malloc_aligned(size);
    }
    struct memory_chunk_t *ptr = (struct memory_chunk_t*)((char*)memblock-sizeof(struct memory_chunk_t)-FENCE);
    if(size == 0)
    {
        heap_free(memblock);
        return NULL;
    }
    else if(ptr->original_size >= size)
    {
        ptr->size = size;
        SetMyFences(ptr);
        ptr->hash = hash_memory_chunk(ptr);
        return memblock;
    }
    if(ptr->next && ptr->next->free == 1)
    {
        size_t free_memory = (size_t)(ptr->original_size + ptr->next->original_size + sizeof(struct memory_chunk_t) + 2 * FENCE);
        if(free_memory >= size)
        {
            ptr->size = size;
            ptr->original_size = find_me_good_size_of_page(size);
            if(ptr->next->next)
            {
                if(ptr->prev)
                {
                    ptr->next->next->prev = ptr;
                }
                else
                {
                    ptr->next->next->prev = NULL;
                }
                ptr->next->next->hash = hash_memory_chunk(ptr->next->next);
                ptr->next = ptr->next->next;
            }
            else
            {
                ptr->next = NULL;
            }
            SetMyFences(ptr);
            ptr->hash = hash_memory_chunk(ptr);
            //PrintMyHeap();
            return memblock;
        }
    }
    if(!ptr->next)
    {
        size_t used_mem = (size_t)((char*)ptr - (char*)memory_manager.first_memory_chunk)+ size + 2*FENCE + sizeof(struct memory_chunk_t);
        if(memory_manager.memory_size < used_mem)
        {
            if(custom_sbrk((int)size) == (void*)-1)
            {
                return NULL;
            }
            memory_manager.memory_size +=size;
        }
        ptr->size = size;
        ptr->original_size = find_me_good_size_of_page(size);
        ptr->hash = hash_memory_chunk(ptr);
        SetMyFences(ptr);
        return memblock;
    }
    void *new_ptr = heap_malloc_aligned(size);
    if(!new_ptr)
    {
        return NULL;
    }
    memcpy(new_ptr, memblock, size);
    heap_free(memblock);
    return new_ptr;
}
