/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Slabs memory allocation, based on powers-of-N. Slabs are up to 1MB in size
 * and are divided into chunks. The chunk sizes start off at the size of the
 * "item" structure plus space for a small key and value. They increase by
 * a multiplier factor from there, up to half the maximum slab size. The last
 * slab size is always 1MB, since that's the maximum item size allowed by the
 * memcached protocol.
*
 * $Id$
 */
#include "memcached.h"
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#ifdef HAVE_MALLOC_H
/* OpenBSD has a malloc.h, but warns to use stdlib.h instead */
#ifndef __OpenBSD__
#include <malloc.h>
#endif
#endif

#define POWER_SMALLEST 1
#define POWER_LARGEST  200
#define POWER_BLOCK 1048576
#define CHUNK_ALIGN_BYTES 8
#define DONT_PREALLOC_SLABS

/* powers-of-N allocation structures */

typedef struct {
    unsigned int size;      /* sizes of items */
    unsigned int perslab;   /* how many items per slab */

    void **slots;           /* list of item ptrs */
    unsigned int sl_total;  /* size of previous array */
    unsigned int sl_curr;   /* first free slot */

    void *end_page_ptr;         /* pointer to next free item at end of page, or 0 */
    unsigned int end_page_free; /* number of items remaining at end of last alloced page */

    unsigned int slabs;     /* how many slabs were allocated for this class */

    void **slab_list;       /* array of slab pointers */
    unsigned int list_size; /* size of prev array */

    unsigned int killing;  /* index+1 of dying slab, or zero if none */
} slabclass_t;

static slabclass_t slabclass[POWER_LARGEST + 1];
static size_t mem_limit = 0;
static size_t mem_malloced = 0;
static int power_largest;

static void *mem_base = NULL;
static void *mem_current = NULL;
static size_t mem_avail = 0;

/*
 * Forward Declarations
 */
static int do_slabs_newslab(const unsigned int id);
static void *memory_allocate(size_t size);

#ifndef DONT_PREALLOC_SLABS
/* Preallocate as many slab pages as possible (called from slabs_init)
   on start-up, so users don't get confused out-of-memory errors when
   they do have free (in-slab) space, but no space to make new slabs.
   if maxslabs is 18 (POWER_LARGEST - POWER_SMALLEST + 1), then all
   slab types can be made.  if max memory is less than 18 MB, only the
   smaller ones will be made.  */
static void slabs_preallocate (const unsigned int maxslabs);
#endif

/*
 * Figures out which slab class (chunk size) is required to store an item of
 * a given size.
 *
 * Given object size, return id to use when allocating/freeing memory for object
 * 0 means error: can't store such a large object
 */

unsigned int slabs_clsid(const size_t size) {
    int res = POWER_SMALLEST;

    if (size == 0)
        return 0;
    while (size > slabclass[res].size)
        if (res++ == power_largest)     /* won't fit in the biggest slab */
            return 0;
    return res;
}

/**
 * Determines the chunk sizes and initializes the slab class descriptors
 * accordingly.
 */
void slabs_init(const size_t limit, const double factor, const bool prealloc) {
    int i = POWER_SMALLEST - 1;
    unsigned int size = sizeof(item) + settings.chunk_size;

    /* Factor of 2.0 means use the default memcached behavior */
    if (factor == 2.0 && size < 128)
        size = 128;

    mem_limit = limit;

    if (prealloc) {
        /* Allocate everything in a big chunk with malloc */
        mem_base = malloc(mem_limit);
        if (mem_base != NULL) {
            mem_current = mem_base;
            mem_avail = mem_limit;
        } else {
            fprintf(stderr, "Warning: Failed to allocate requested memory in"
                    " one large chunk.\nWill allocate in smaller chunks\n");
        }
    }

    memset(slabclass, 0, sizeof(slabclass));

    while (++i < POWER_LARGEST && size <= POWER_BLOCK / 2) {
        /* Make sure items are always n-byte aligned */
        if (size % CHUNK_ALIGN_BYTES)
            size += CHUNK_ALIGN_BYTES - (size % CHUNK_ALIGN_BYTES);

        slabclass[i].size = size;
        slabclass[i].perslab = POWER_BLOCK / slabclass[i].size;
        size *= factor;
        if (settings.verbose > 1) {
            fprintf(stderr, "slab class %3d: chunk size %6u perslab %5u\n",
                    i, slabclass[i].size, slabclass[i].perslab);
        }
    }

    power_largest = i;
    slabclass[power_largest].size = POWER_BLOCK;
    slabclass[power_largest].perslab = 1;

    /* for the test suite:  faking of how much we've already malloc'd */
    {
        char *t_initial_malloc = getenv("T_MEMD_INITIAL_MALLOC");
        if (t_initial_malloc) {
            mem_malloced = (size_t)atol(t_initial_malloc);
        }

    }

#ifndef DONT_PREALLOC_SLABS
    {
        char *pre_alloc = getenv("T_MEMD_SLABS_ALLOC");

        if (pre_alloc == NULL || atoi(pre_alloc) != 0) {
            slabs_preallocate(power_largest);
        }
    }
#endif
}

#ifndef DONT_PREALLOC_SLABS
static void slabs_preallocate (const unsigned int maxslabs) {
    int i;
    unsigned int prealloc = 0;

    /* pre-allocate a 1MB slab in every size class so people don't get
       confused by non-intuitive "SERVER_ERROR out of memory"
       messages.  this is the most common question on the mailing
       list.  if you really don't want this, you can rebuild without
       these three lines.  */

    for (i = POWER_SMALLEST; i <= POWER_LARGEST; i++) {
        if (++prealloc > maxslabs)
            return;
        do_slabs_newslab(i);
    }

}
#endif

static int grow_slab_list (const unsigned int id) {
    slabclass_t *p = &slabclass[id];
    if (p->slabs == p->list_size) {
        size_t new_size =  (p->list_size != 0) ? p->list_size * 2 : 16;
        void *new_list = realloc(p->slab_list, new_size * sizeof(void *));
        if (new_list == 0) return 0;
        p->list_size = new_size;
        p->slab_list = new_list;
    }
    return 1;
}

static int do_slabs_newslab(const unsigned int id) {
    slabclass_t *p = &slabclass[id];
#ifdef ALLOW_SLABS_REASSIGN
    int len = POWER_BLOCK;
#else
    int len = p->size * p->perslab;
#endif
    char *ptr;

    if ((mem_limit && mem_malloced + len > mem_limit && p->slabs > 0) ||
        (grow_slab_list(id) == 0) ||
        ((ptr = memory_allocate((size_t)len)) == 0)) {

        MEMCACHED_SLABS_SLABCLASS_ALLOCATE_FAILED(id);
        return 0;
    }

    memset(ptr, 0, (size_t)len);
    p->end_page_ptr = ptr;
    p->end_page_free = p->perslab;

    p->slab_list[p->slabs++] = ptr;
    mem_malloced += len;
    MEMCACHED_SLABS_SLABCLASS_ALLOCATE(id);

    return 1;
}

/*@null@*/
void *do_slabs_alloc(const size_t size, unsigned int id) {
    slabclass_t *p;
    void *ret = NULL;

    if (id < POWER_SMALLEST || id > power_largest) {
        MEMCACHED_SLABS_ALLOCATE_FAILED(size, 0);
        return NULL;
    }

    p = &slabclass[id];
    assert(p->sl_curr == 0 || ((item *)p->slots[p->sl_curr - 1])->slabs_clsid == 0);

#ifdef USE_SYSTEM_MALLOC
    if (mem_limit && mem_malloced + size > mem_limit) {
        MEMCACHED_SLABS_ALLOCATE_FAILED(size, id);
        return 0;
    }
    mem_malloced += size;
    ret = malloc(size);
    MEMCACHED_SLABS_ALLOCATE(size, id, 0, ret);
    return ret;
#endif

    /* fail unless we have space at the end of a recently allocated page,
       we have something on our freelist, or we could allocate a new page */
    if (! (p->end_page_ptr != 0 || p->sl_curr != 0 ||
           do_slabs_newslab(id) != 0)) {
        /* We don't have more memory available */
        ret = NULL;
    } else if (p->sl_curr != 0) {
        /* return off our freelist */
        ret = p->slots[--p->sl_curr];
    } else {
        /* if we recently allocated a whole page, return from that */
        assert(p->end_page_ptr != NULL);
        ret = p->end_page_ptr;
        if (--p->end_page_free != 0) {
            p->end_page_ptr = ((caddr_t)p->end_page_ptr) + p->size;
        } else {
            p->end_page_ptr = 0;
        }
    }

    if (ret) {
        MEMCACHED_SLABS_ALLOCATE(size, id, p->size, ret);
    } else {
        MEMCACHED_SLABS_ALLOCATE_FAILED(size, id);
    }

    return ret;
}

void do_slabs_free(void *ptr, const size_t size, unsigned int id) {
    slabclass_t *p;

    assert(((item *)ptr)->slabs_clsid == 0);
    assert(id >= POWER_SMALLEST && id <= power_largest);
    if (id < POWER_SMALLEST || id > power_largest)
        return;

    MEMCACHED_SLABS_FREE(size, id, ptr);
    p = &slabclass[id];

#ifdef USE_SYSTEM_MALLOC
    mem_malloced -= size;
    free(ptr);
    return;
#endif

    if (p->sl_curr == p->sl_total) { /* need more space on the free list */
        int new_size = (p->sl_total != 0) ? p->sl_total * 2 : 16;  /* 16 is arbitrary */
        void **new_slots = realloc(p->slots, new_size * sizeof(void *));
        if (new_slots == 0)
            return;
        p->slots = new_slots;
        p->sl_total = new_size;
    }
    p->slots[p->sl_curr++] = ptr;
    return;
}

char *get_stats(const char *stat_type, uint32_t (*add_stats)(char *buf,
                const char *key, const uint16_t klen, const char *val,
                const uint32_t vlen), int *buflen) {

    char *buf, *pos;
    char val[128];
    int size = 0;
    *buflen = 0;

    if (add_stats == NULL)
        return NULL;

    if (!stat_type) {
        if ((buf = malloc(512)) == NULL) {
            *buflen = -1;
            return NULL;
        }

        pos = buf;

        /* prepare general statistics for the engine */
        sprintf(val, "%llu", (unsigned long long)stats.curr_bytes);
        size = add_stats(pos, "bytes", strlen("bytes"), val, strlen(val));
        *buflen += size;
        pos += size;

        sprintf(val, "%u", stats.curr_items);
        size = add_stats(pos, "curr_items", strlen("curr_items"), val,
                         strlen(val));
        *buflen += size;
        pos += size;

        sprintf(val, "%u", stats.total_items);
        size = add_stats(pos, "total_items", strlen("total_items"), val,
                         strlen(val));
        *buflen += size;
        pos += size;

        sprintf(val, "%llu", (unsigned long long)stats.evictions);
        size = add_stats(pos, "evictions", strlen("evictions"), val,
                         strlen(val));
        *buflen += size;
        pos += size;

        return buf;
    } else if (strcmp(stat_type, "items") == 0) {
        buf = item_stats(add_stats, &size);
        *buflen = size;
        return buf;
    } else if (strcmp(stat_type, "slabs") == 0) {
        buf = slabs_stats(add_stats, &size);
        *buflen = size;
        return buf;
    } else if (strcmp(stat_type, "sizes") == 0) {
        buf = item_stats_sizes(add_stats, &size);
        *buflen = size;
        return buf;
    }

#ifdef HAVE_MALLOC_H
#ifdef HAVE_STRUCT_MALLINFO
    else if (strcmp(stat_type, "malloc") == 0) {
        buf = malloc(1024);
        char *pos = buf;
        struct mallinfo info;
        uint32_t linelen = 0;

        if (buf == NULL) {
            *buflen = -1;
            return NULL;
        }

        info = mallinfo();

        char val[128];
        uint32_t nbytes = 0;

        sprintf(val, "%ld", info.arena);
        nbytes = add_stats(pos, "arena_size", strlen("arena_size"), val,
                           strlen(val));
        linelen += nbytes;
        pos += nbytes;

        sprintf(val, "%ld", info.ordblks);
        nbytes = add_stats(pos, "free_chunks", strlen("free_chunks"), val,
                           strlen(val));
        linelen += nbytes;
        pos += nbytes;

        sprintf(val, "%ld", info.smblks);
        nbytes = add_stats(pos, "fastbin_blocks", strlen("fastbin_blocks"),
                           val, strlen(val));
        linelen += nbytes;
        pos += nbytes;

        sprintf(val, "%ld", info.hblks);
        nbytes = add_stats(pos, "mmapped_regions", strlen("mmapped_regions"),
                           val, strlen(val));
        linelen += nbytes;
        pos += nbytes;

        sprintf(val, "%ld", info.hblkhd);
        nbytes = add_stats(pos, "mmapped_space", strlen("mmapped_space"),
                           val, strlen(val));
        linelen += nbytes;
        pos += nbytes;

        sprintf(val, "%ld", info.usmblks);
        nbytes = add_stats(pos, "max_total_alloc", strlen("max_total_alloc"),
                           val, strlen(val));
        linelen += nbytes;
        pos += nbytes;

        sprintf(val, "%ld", info.fsmblks);
        nbytes = add_stats(pos, "fastbin_space", strlen("fastbin_space"),
                           val, strlen(val));
        linelen += nbytes;
        pos += nbytes;

        sprintf(val, "%ld", info.uordblks);
        nbytes = add_stats(pos, "total_alloc", strlen("total_alloc"), val,
                           strlen(val));
        linelen += nbytes;
        pos += nbytes;

        sprintf(val, "%ld", info.fordblks);
        nbytes = add_stats(pos, "total_free", strlen("total_free"), val,
                            strlen(val));
        linelen += nbytes;
        pos += nbytes;

        sprintf(val, "%ld", info.keepcost);
        nbytes = add_stats(pos, "releasable_space",
                           strlen("releasable_space"), val, strlen(val));
        linelen += nbytes;
        pos += nbytes;

        linelen += add_stats(pos, NULL, 0, NULL, 0);
        *buflen = linelen;

        return buf;
    }
#endif /* HAVE_STRUCT_MALLINFO */
#endif /* HAVE_MALLOC_H */

    return NULL;
}

/*@null@*/
char *do_slabs_stats(uint32_t (*add_stats)(char *buf, const char *key,
                     const uint16_t klen, const char *val,
                     const uint32_t vlen), int *buflen) {
    int i, total, linelen;
    char *buf = (char *)malloc(power_largest * 200 + 100);
    char *bufcurr = buf;

    *buflen = 0;
    linelen = 0;

    if (buf == NULL) {
        *buf = -1;
        return NULL;
    }

    total = 0;
    for(i = POWER_SMALLEST; i <= power_largest; i++) {
        slabclass_t *p = &slabclass[i];
        if (p->slabs != 0) {
            uint32_t perslab, slabs;
            slabs = p->slabs;
            perslab = p->perslab;

            char key[128];
            char val[128];
            uint32_t nbytes = 0;

            sprintf(key, "%d:chunk_size", i);
            sprintf(val, "%u", p->size);
            nbytes = add_stats(bufcurr, key, strlen(key), val, strlen(val));
            linelen += nbytes;
            bufcurr += nbytes;

            sprintf(key, "%d:chunks_per_page", i);
            sprintf(val, "%u", perslab);
            nbytes = add_stats(bufcurr, key, strlen(key), val, strlen(val));
            linelen += nbytes;
            bufcurr += nbytes;

            sprintf(key, "%d:total_page", i);
            sprintf(val, "%u", slabs);
            nbytes = add_stats(bufcurr, key, strlen(key), val, strlen(val));
            linelen += nbytes;
            bufcurr += nbytes;

            sprintf(key, "%d:total_chunks", i);
            sprintf(val, "%u", slabs*perslab);
            nbytes = add_stats(bufcurr, key, strlen(key), val, strlen(val));
            linelen += nbytes;
            bufcurr += nbytes;

            sprintf(key, "%d:used_chunks", i);
            sprintf(val, "%u", ((slabs*perslab) - p->sl_curr));
            nbytes = add_stats(bufcurr, key, strlen(key), val, strlen(val));
            linelen += nbytes;
            bufcurr += nbytes;

            sprintf(key, "%d:free_chunks", i);
            sprintf(val, "%u", p->sl_curr);
            nbytes = add_stats(bufcurr, key, strlen(key), val, strlen(val));
            linelen += nbytes;
            bufcurr += nbytes;

            sprintf(key, "%d:free_chunks_end", i);
            sprintf(val, "%u", p->end_page_free);
            nbytes = add_stats(bufcurr, key, strlen(key), val, strlen(val));
            linelen += nbytes;
            bufcurr += nbytes;

            total++;
        }
    }

    /* add overall slab stats and append terminator */
    uint32_t nbytes = 0;
    char key[128];
    char val[128];

    sprintf(key, "active_slabs");
    sprintf(val, "%d", total);
    nbytes = add_stats(bufcurr, key, strlen(key), val, strlen(val));
    linelen += nbytes;
    bufcurr += nbytes;

    sprintf(key, "total_malloced");
    sprintf(val, "%llu", (unsigned long long)mem_malloced);
    nbytes = add_stats(bufcurr, key, strlen(key), val, strlen(val));
    linelen += nbytes;
    bufcurr += nbytes;

    linelen += add_stats(bufcurr, NULL, 0, NULL, 0);
    *buflen = linelen;

    return buf;
}

#ifdef ALLOW_SLABS_REASSIGN
/* Blows away all the items in a slab class and moves its slabs to another
   class. This is only used by the "slabs reassign" command, for manual tweaking
   of memory allocation. It's disabled by default since it requires that all
   slabs be the same size (which can waste space for chunk size mantissas of
   other than 2.0).
   1 = success
   0 = fail
   -1 = tried. busy. send again shortly. */
int do_slabs_reassign(unsigned char srcid, unsigned char dstid) {
    void *slab, *slab_end;
    slabclass_t *p, *dp;
    void *iter;
    bool was_busy = false;

    if (srcid < POWER_SMALLEST || srcid > power_largest ||
        dstid < POWER_SMALLEST || dstid > power_largest)
        return 0;

    p = &slabclass[srcid];
    dp = &slabclass[dstid];

    /* fail if src still populating, or no slab to give up in src */
    if (p->end_page_ptr || ! p->slabs)
        return 0;

    /* fail if dst is still growing or we can't make room to hold its new one */
    if (dp->end_page_ptr || ! grow_slab_list(dstid))
        return 0;

    if (p->killing == 0) p->killing = 1;

    slab = p->slab_list[p->killing - 1];
    slab_end = (char*)slab + POWER_BLOCK;

    for (iter = slab; iter < slab_end; (char*)iter += p->size) {
        item *it = (item *)iter;
        if (it->slabs_clsid) {
            if (it->refcount) was_busy = true;
            item_unlink(it);
        }
    }

    /* go through free list and discard items that are no longer part of this slab */
    {
        int fi;
        for (fi = p->sl_curr - 1; fi >= 0; fi--) {
            if (p->slots[fi] >= slab && p->slots[fi] < slab_end) {
                p->sl_curr--;
                if (p->sl_curr > fi) p->slots[fi] = p->slots[p->sl_curr];
            }
        }
    }

    if (was_busy) return -1;

    /* if good, now move it to the dst slab class */
    p->slab_list[p->killing - 1] = p->slab_list[p->slabs - 1];
    p->slabs--;
    p->killing = 0;
    dp->slab_list[dp->slabs++] = slab;
    dp->end_page_ptr = slab;
    dp->end_page_free = dp->perslab;
    /* this isn't too critical, but other parts of the code do asserts to
       make sure this field is always 0.  */
    for (iter = slab; iter < slab_end; (char*)iter += dp->size) {
        ((item *)iter)->slabs_clsid = 0;
    }
    return 1;
}
#endif

static void *memory_allocate(size_t size) {
    void *ret;

    if (mem_base == NULL) {
        /* We are not using a preallocated large memory chunk */
        ret = malloc(size);
    } else {
        ret = mem_current;

        if (size > mem_avail) {
            return NULL;
        }

        /* mem_current pointer _must_ be aligned!!! */
        if (size % CHUNK_ALIGN_BYTES) {
            size += CHUNK_ALIGN_BYTES - (size % CHUNK_ALIGN_BYTES);
        }

        mem_current = ((char*)mem_current) + size;
        if (size < mem_avail) {
            mem_avail -= size;
        } else {
            mem_avail = 0;
        }
    }

    return ret;
}