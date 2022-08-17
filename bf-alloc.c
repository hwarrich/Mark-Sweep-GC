// ==============================================================================
/**
 * bf-alloc.c
 *
 * A _best-fit_ heap allocator.  This allocator uses a _doubly-linked free list_
 * from which to allocate the best fitting free block.  If the list does not
 * contain any blocks of sufficient size, it uses _pointer bumping_ to expand
 * the heap.
 **/
// ==============================================================================



// ==============================================================================
// INCLUDES

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#include "safeio.h"
// ==============================================================================



// ==============================================================================
// TYPES AND STRUCTURES

/** The header for each allocated object. */
typedef struct header {

  /** Pointer to the next header in the list. */
  struct header* next;

  /** Pointer to the previous header in the list. */
  struct header* prev;

  /** The usable size of the block (exclusive of the header itself). */
  size_t         size;

  /** Is the block allocated or free? */
  bool           allocated;

} header_s;
// ==============================================================================



// ==============================================================================
// MACRO CONSTANTS AND FUNCTIONS

/** The system's page size. */
#define PAGE_SIZE sysconf(_SC_PAGESIZE)

/**
 * Macros to easily calculate the number of bytes for larger scales (e.g., kilo,
 * mega, gigabytes).
 */
#define KB(size)  ((size_t)size * 1024)
#define MB(size)  (KB(size) * 1024)
#define GB(size)  (MB(size) * 1024)

/** The virtual address space reserved for the heap. */
#define HEAP_SIZE GB(2)

/** Given a pointer to a header, obtain a `void*` pointer to the block itself. */
#define HEADER_TO_BLOCK(hp) ((void*)((intptr_t)hp + sizeof(header_s)))

/** Given a pointer to a block, obtain a `header_s*` pointer to its header. */
#define BLOCK_TO_HEADER(bp) ((header_s*)((intptr_t)bp - sizeof(header_s)))
// ==============================================================================


// ==============================================================================
// GLOBALS

/** The address of the next available byte in the heap region. */
static intptr_t free_addr  = 0;

/** The beginning of the heap. */
static intptr_t start_addr = 0;

/** The end of the heap. */
static intptr_t end_addr   = 0;

/** The head of the free list. */
static header_s* free_list_head = NULL;

/** The head of the allocated list. */
static header_s* allocated_list_head = NULL;
// ==============================================================================



// ==============================================================================
/**
 * The initialization method.  If this is the first use of the heap, initialize it.
 */

void init () {

  // Only do anything if there is no heap region (i.e., first time called).
  if (start_addr == 0) {

    DEBUG("Trying to initialize");
    
    // Allocate virtual address space in which the heap will reside. Make it
    // un-shared and not backed by any file (_anonymous_ space).  A failure to
    // map this space is fatal.
    void* heap = mmap(NULL,
		      HEAP_SIZE,
		      PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS,
		      -1,
		      0);
    if (heap == MAP_FAILED) {
      ERROR("Could not mmap() heap region");
    }

    // Hold onto the boundaries of the heap as a whole.
    start_addr = (intptr_t)heap;
    end_addr   = start_addr + HEAP_SIZE;
    free_addr  = start_addr;

    // DEBUG: Emit a message to indicate that this allocator is being called.
    DEBUG("bf-alloc initialized");

  }

} // init ()
// ==============================================================================


// ==============================================================================
/**
 * Allocate and return `size` bytes of heap space.  Specifically, search the
 * free list, choosing the _best fit_.  If no such block is available, expand
 * into the heap region via _pointer bumping_.
 *
 * \param size The number of bytes to allocate.
 * \return A pointer to the allocated block, if successful; `NULL` if unsuccessful.
 */
void* malloc (size_t size) {

  //initialize heap
  init();

  //if requested to allocate a space of 0 bytes then return NULL
  if (size == 0) {
    return NULL;
  }

  //current is a pointer to a header and  gets a pointer to the head of the free list
  header_s* current = free_list_head;
  //best is a pointer to a header and gets set to NULL
  header_s* best    = NULL;

  //while there are still free blocks left to iterate over
  while (current != NULL) {

    //if the current block is allocted then we have an error
    //because we should only be iterating over free blocks
    if (current->allocated) {
      ERROR("Allocated block on free list", (intptr_t)current);
    }

    //if we have not previously found a block that is larger than or equal to the requested size and the current block is large enough for the requested size
    //OR if we have have previously found a block that is large enough to hold the requested size and the size of the current block is large enough to hold the request size and 
    //the current size is smaller than than the size of the previously found best block
    //then best points to the header of the current block
    if ( (best == NULL && size <= current->size) ||
	 (best != NULL && size <= current->size && current->size < best->size) ) {
      best = current;
    }

    // if best is not null and the best points to a block that is of the requested size then break
    if (best != NULL && best->size == size) {
      break;
    }

    //current points to next header in the free list
    current = current->next;
    
  }

  //new_block_ptr is a void pointer that gets set to NULL
  void* new_block_ptr = NULL;
  //if best is not null (we have found a block for the requested size)
  if (best != NULL) {

    //if the header before best is null
    if (best->prev == NULL) {
      //free_list_head points to header of the next free block after best
      free_list_head   = best->next;
    } else {
      //if the header before best is not null then the header before next has its next header pointer set to the next free header after best
      best->prev->next = best->next;
    }
    //if the pointer to to next free header after next is not null
    if (best->next != NULL) {
      //the next free header after best gets a pointer to the header of the block before best as the previous free block
      best->next->prev = best->prev;
    }
    //best's previous header pointer gets set to null
    best->prev       = NULL;
    //best's next header pointer gets set to null
    best->next       = NULL;

    //header that best points to now is now allocated
    best->allocated = true;
    //new block pointer now points to the block of memory associated with the best header (points to best block of memory found) 
    new_block_ptr   = HEADER_TO_BLOCK(best);

    //we have allocated this block so add it to the allocated list
    //the best header's next pointer now points to the head of the allocated list
    best->next = allocated_list_head;
    //the best header is now the head of the allocated list
    allocated_list_head = best;
    //the header in front of best will now point back to best
    if(best->next != NULL){
      best->next->prev = best;
    } 
    
  } else {//if best is null

    //header ptr is a pointer to a header is at the free addr
    header_s* header_ptr = (header_s*)free_addr;
     //new_block_ptr points to the memory after the header pointer
    new_block_ptr = HEADER_TO_BLOCK(header_ptr);

    //if block_ptr is not double word aligned
    if((intptr_t)new_block_ptr%16 != 0){
      int change = (16-(intptr_t)new_block_ptr % 16);
      //move the block_ptr over to a double word aligned address
      new_block_ptr = (void*)((intptr_t)new_block_ptr + change);
      //move the header ptr over the same amount
      header_ptr = (header_s*)((intptr_t)header_ptr + change);
    }

    //header_ptr's next and prev pointers are set to NULL, size is set to size, and now reflects that this block is allocated
    header_ptr->next      = NULL;
    header_ptr->prev      = NULL;
    header_ptr->size      = size;
    header_ptr->allocated = true;

    //the new free addr is the the size of the block requested plus the size of the pointer to the block plus any shifting to make the block pointer double word aligned
    intptr_t new_free_addr = (intptr_t)new_block_ptr + size + 2* (16-(intptr_t)new_block_ptr % 16);
    //if we have gone past the end addr of the heap
    if (new_free_addr > end_addr) {

      //return null
      return NULL;

    } else {

      //otherwise the free_addr is the new_free_addr
      free_addr = new_free_addr;

    }
    //add this new block from pointer bumping to allocated list
    header_ptr->next = allocated_list_head;
    allocated_list_head = header_ptr;
    if(header_ptr->next != NULL){
      header_ptr->next->prev = header_ptr;
    }

  }
  

  //return pointer to allocated block
  return new_block_ptr;

} // malloc()
// ==============================================================================



// ==============================================================================
/**
 * Deallocate a given block on the heap.  Add the given block (if any) to the
 * free list.
 *
 * \param ptr A pointer to the block to be deallocated.
 */
void free (void* ptr) {

  //if given a NULL pointer
  if (ptr == NULL) {
    return;
  }

  //header_ptr is a pointer that points to header of the given block
  header_s* header_ptr = BLOCK_TO_HEADER(ptr);

  //if header_ptr is not allocated then raise an error (can't free an already free block)
  if (!header_ptr->allocated) {
    ERROR("Double-free: ", (intptr_t)header_ptr);
  }

  //remove header_ptr from allocated list
  if(header_ptr->prev == NULL){
    allocated_list_head = header_ptr->next;
  } else{
    header_ptr->prev->next = header_ptr->next;
   }
  if(header_ptr->next != NULL){
    header_ptr->next->prev = header_ptr->prev;
  }
  header_ptr->next = NULL;
  header_ptr->prev = NULL;

  //add header_ptr to free list
  header_ptr->next = free_list_head;
  free_list_head   = header_ptr;
  header_ptr->prev = NULL;
  if (header_ptr->next != NULL) {
    header_ptr->next->prev = header_ptr;
  }
  header_ptr->allocated = false;

} // free()
// ==============================================================================



// ==============================================================================
/**
 * Allocate a block of `nmemb * size` bytes on the heap, zeroing its contents.
 *
 * \param nmemb The number of elements in the new block.
 * \param size  The size, in bytes, of each of the `nmemb` elements.
 * \return      A pointer to the newly allocated and zeroed block, if successful;
 *              `NULL` if unsuccessful.
 */
void* calloc (size_t nmemb, size_t size) {

  // Allocate a block of the requested size.
  size_t block_size    = nmemb * size;
  void*  new_block_ptr = malloc(block_size);

  // If the allocation succeeded, clear the entire block.
  if (new_block_ptr != NULL) {
    memset(new_block_ptr, 0, block_size);
  }

  return new_block_ptr;
  
} // calloc ()
// ==============================================================================



// ==============================================================================
/**
 * Update the given block at `ptr` to take on the given `size`.  Here, if `size`
 * fits within the given block, then the block is returned unchanged.  If the
 * `size` is an increase for the block, then a new and larger block is
 * allocated, and the data from the old block is copied, the old block freed,
 * and the new block returned.
 *
 * \param ptr  The block to be assigned a new size.
 * \param size The new size that the block should assume.
 * \return     A pointer to the resultant block, which may be `ptr` itself, or
 *             may be a newly allocated block.
 */
void* realloc (void* ptr, size_t size) {

  // Special case: If there is no original block, then just allocate the new one
  // of the given size.
  if (ptr == NULL) {
    return malloc(size);
  }

  // Special case: If the new size is 0, that's tantamount to freeing the block.
  if (size == 0) {
    free(ptr);
    return NULL;
  }

  // Get the current block size from its header.
  header_s* header_ptr = BLOCK_TO_HEADER(ptr);

  // If the new size isn't an increase, then just return the original block as-is.
  if (size <= header_ptr->size) {
    return ptr;
  }

  // The new size is an increase.  Allocate the new, larger block, copy the
  // contents of the old into it, and free the old.
  void* new_block_ptr = malloc(size);
  if (new_block_ptr != NULL) {
    memcpy(new_block_ptr, ptr, header_ptr->size);
    free(ptr);
  }
    
  return new_block_ptr;
  
} // realloc()
// ==============================================================================

header_s* getFreeList(){
  return free_list_head;
}

header_s* getAllocatedList(){
return allocated_list_head;
}
