// ==============================================================================
/**
 * sf-alloc.c
 *
 * A _segregated-fits_ heap allocator.  This allocator uses _power-of-2 class
 * sizes_ of _singly-linked free lists_.  Each allocation is "rounded up" to its
 * class size, and the first available free block allocated from that free list.
 * If the list does not contain any blocks, a page is allocated and used to
 * populate that free list.
 **/
// ==============================================================================



// ==============================================================================
// INCLUDES

#define _GNU_SOURCE
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

/** The header for each free object. */
typedef struct header {

  /** Pointer to the next header in the list. */
  struct header* next;

} header_s;
// ==============================================================================



// ==============================================================================
// MACRO CONSTANTS AND FUNCTIONS

/** The system's page size. */
#define PAGE_SIZE sysconf(_SC_PAGESIZE)

/** Mask of the offset bits of a virtual address. */
#define OFFSET_MASK (PAGE_SIZE - 1)

/**
 * Macros to easily calculate the number of bytes for larger scales (e.g., kilo,
 * mega, gigabytes).
 */
#define KB(size)  ((size_t)size * 1024)
#define MB(size)  (KB(size) * 1024)
#define GB(size)  (MB(size) * 1024)

/** The virtual address space reserved for the heap. */
#define HEAP_SIZE GB(2)

/** The smallest size class, 16 bytes (a double-word). */
#define MIN_SIZE_CLASS 4

/** The largest size class, 2048 bytes (half-page). */
#define MAX_SIZE_CLASS 11

/** Calculate the log of a size-1, used to determine the size class. */
#define CALC_SIZE_CLASS(x) ((unsigned int) (8*sizeof(size_t) - __builtin_clzll((x - 1))))

/** Calculate the size of a block in a given size class, given as 2^class. */
#define CALC_CLASS_SIZE(x) (1 << x)

/**
 * Given a pointer to a block, find the header at the top of the page that
 * contains the size class, and return that size.
 */
#define GET_SIZE_CLASS(bp) (*(size_t*)((intptr_t)bp & ~OFFSET_MASK))
// ==============================================================================


// ==============================================================================
// GLOBALS

/** The address of the next available byte in the heap region. */
static intptr_t free_addr  = 0;

/** The beginning of the heap. */
static intptr_t start_addr = 0;

/** The end of the heap. */
static intptr_t end_addr   = 0;

/** The array of free list heads, one per size class. */
static header_s* free_lists[MAX_SIZE_CLASS + 1] = { NULL };
// ==============================================================================



bool
check () {

  bool error = false;
  for (int i = MIN_SIZE_CLASS; i <= MAX_SIZE_CLASS; i += 1) {
    if (free_lists[i] != NULL &&
	(intptr_t)free_lists[i]->next < 0) {
      error = true;
    }
  }

  return error;
  
}



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
    void* heap = mmap(NULL,                         // No particular location
		      HEAP_SIZE,
		      PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS,  // Not backed by a file
		      -1,                           // ditto
		      0);                           // ditto
    if (heap == MAP_FAILED) {
      ERROR("Could not mmap() heap region");
    }

    // Hold onto the boundaries of the heap as a whole.
    start_addr = (intptr_t)heap;
    end_addr   = start_addr + HEAP_SIZE;
    free_addr  = start_addr;

    // DEBUG: Emit a message to indicate that this allocator is being called.
    DEBUG("sf-alloc initialized");

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

  check();
  init();

  // Cannot allocate an empty block.
  if (size == 0) {
    return NULL;
  }

  // Grab the size class, and determine how to handle the request.
  unsigned int size_class = CALC_SIZE_CLASS(size);
  size_t       class_size = CALC_CLASS_SIZE(size_class);
  DEBUG("malloc(): ", size, class_size, size_class);
  if (size_class < MIN_SIZE_CLASS) {

    // Bump it the request size to the minimum that we handle.
    size_class = MIN_SIZE_CLASS;
    class_size = CALC_CLASS_SIZE(size_class);
    DEBUG("malloc(): Too small, bumped up size class", size_class);

  } else if (size_class > MAX_SIZE_CLASS) {

    // Handle this large allocation as an `mmap()`, separating it from the rest
    // of the heap.
    DEBUG("malloc(): Too large, mapping separately");
    void* new_block_ptr = mmap(NULL,                         // No particular location
			       sizeof(size_t) + size,        // A header + the block
			       PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS,  // Not backed by a file
			       -1,                           // ditto
			       0);                           // ditto
    if (new_block_ptr == MAP_FAILED) {
      DEBUG("Could not mmap() large allocation", size);
      return NULL;
    }

    size_t* header = new_block_ptr;
    *header = class_size;
    intptr_t block_addr = (intptr_t)header + sizeof(size_t);
    DEBUG("malloc(): Returning large block", block_addr);
    check();
    return (void*)block_addr;

  }

  // Do we have a free block in the needed size class?
  if (free_lists[size_class] == NULL) {

    // No blocks of this size.  Is there more heap space?
    if (free_addr >= end_addr) {
      DEBUG("malloc(): Failing because heap is full");
      return NULL;
    }

    // Allocate a new page, making sure it is aligned.
    DEBUG("malloc(): Size class free list empty, replenishing");
    assert((free_addr & OFFSET_MASK) == 0);
    intptr_t new_page_addr = free_addr;
    free_addr += PAGE_SIZE;

    // Record the size class of the blocks in this page within the first block's
    // space (which won't be used).
    *(unsigned int*)new_page_addr = size_class;

    // Loop through the remaining blocks of the page, chaining them together.
    intptr_t current       = new_page_addr + class_size;
    free_lists[size_class] = (header_s*)current;
    while (current < free_addr) {

      // Make this block point to the next one, unless we're at the last block,
      // in which case mark the end of the list with a `NULL` next.
      intptr_t next = current + class_size;
      if (next < free_addr) {
	((header_s*)current)->next = (header_s*)next;
      } else {
	((header_s*)current)->next = NULL;
      }

      // Move forward.
      current = next;
      
    }

  }

  // There is now at least one block of this size class, so allocate the first
  // available.
  assert(free_lists[size_class] != NULL);
  void* new_block_ptr = (void*)free_lists[size_class];
  check();
  free_lists[size_class] = free_lists[size_class]->next;
  
  DEBUG("malloc() returning: ", (intptr_t)new_block_ptr);
  check();
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

  DEBUG("free(): ", (intptr_t)ptr);
  check();

  // This function is allowed to be passed a `NULL` pointer.  Do nothing.
  if (ptr == NULL) {
    DEBUG("free(): Doing nothing for NULL block");
    return;
  }

  // Special case:  Is this a large block mmap'ed outside of the heap?
  intptr_t addr = (intptr_t)ptr;
  if ((addr < start_addr) || (end_addr < addr)) {

    // Yes.  Walk back to its size header...
    DEBUG("free(): Large block");
    size_t* header = (size_t*)(addr - sizeof(size_t));
    size_t  size   = *header;
    assert(CALC_SIZE_CLASS(size) > MAX_SIZE_CLASS);
    DEBUG("free(): Large block size = ", size);

    // ...and unmap the region.
    int result = munmap((void*)header, size + sizeof(size_t));
    if (result == -1) {
      ERROR("Could not unmap large block", (intptr_t)ptr);
    }

    check();
    return;
    
  }
  
  // Grab the size of this block from the top of the page.
  unsigned int size_class = GET_SIZE_CLASS(ptr);
  assert((MIN_SIZE_CLASS <= size_class) && (size_class <= MAX_SIZE_CLASS));
  DEBUG("free(): Returning to size class free list", size_class);

  // Insert it at the head of its size class's free list.
  header_s* header       = ptr;
  header->next           = free_lists[size_class];
  free_lists[size_class] = header;

  check();

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

  // Special case:  Is this a large block that has been mmap'ed outside the heap?
  intptr_t addr = (intptr_t)ptr;
  if ((addr < start_addr) || (end_addr <= addr)) {

    // Yes.  Grab its size from its header.  Calculate the size of the new block
    // with the header, and then let mremap() handle the situation,
    void*  old_ptr  = (void*)(addr - sizeof(size_t)); 
    size_t old_size = *(size_t*)old_ptr;
    size_t new_size = size + sizeof(size_t);
    void*  new_ptr  = mremap(old_ptr, old_size, new_size, MREMAP_MAYMOVE);
    if (new_ptr == MAP_FAILED) {
      DEBUG("realloc(): mremap() of large block failed", old_size, new_size);
      return NULL;
    }
    void* new_block_ptr = (void*)((intptr_t)new_ptr + sizeof(size_t));
    return new_block_ptr;
    
  }
  
  // Get the current block size class.
  unsigned int size_class = GET_SIZE_CLASS(ptr);

  // If the new size fits in the current size, we're done.
  if (CALC_SIZE_CLASS(size) <= size_class) {
    return ptr;
  }
  
  // Allocate the new, larger block, copy the contents of the old into it, and
  // free the old.
  void*  new_block_ptr = malloc(size);
  size_t old_size      = 1 << size_class;
  if (new_block_ptr != NULL) {
    memcpy(new_block_ptr, ptr, old_size);
    free(ptr);
  }
    
  return new_block_ptr;
  
} // realloc()
// ==============================================================================



#if defined (ALLOC_MAIN)
// ==============================================================================
#define MIN_SIZE 16
#define MAX_SIZE 2048

/**
 * The entry point if this code is compiled as a standalone program for testing
 * purposes.
 */
int main (int argc, char **argv){

  if (argc != 2) {
    fprintf(stderr, "USAGE: %s <# alloc ops>\n", argv[0]);
    return 1;
  }

  int total_ops = atoi(argv[1]);
  void** ptrs = calloc(total_ops, sizeof(void*));
  int index = 0;
  srandom(1);
  int op;
  for (op = 0; op < total_ops / 4; ++op) {
    ptrs[index++] = malloc(random() % MAX_SIZE);
  }
  for (; op < total_ops / 2; ++op) {
    int i = random() % index--;
    free(ptrs[i]);
    while (ptrs[i] != NULL) {
      ptrs[i] = ptrs[i + 1];
      ++i;
    }
  }

  // Allocate a block that's too large for the normal heap.
  void* large = malloc(MAX_SIZE * 4);
  free(large);
  
  for (; op < total_ops * 3 / 4; ++op) {
    ptrs[index++] = malloc(random() % MAX_SIZE);
  }
  for (; op < total_ops; ++op) {
    int i = random() % index--;
    free(ptrs[i]);
    while (ptrs[i] != NULL) {
      ptrs[i] = ptrs[i + 1];
      ++i;
    }
  }
  
} // main ()
// ==============================================================================
#endif
