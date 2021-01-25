#include <radamsa.h>

void radamsa_init() {
   int nobjs=0, nwords=0;
   hp = (byte *) &heap; /* builtin heap */
   state = IFALSE;
   heap_metrics(&nwords, &nobjs);
   max_heap_mb = (W == 4) ? 4096 : 65535;
   nwords += nobjs + INITCELLS;
   memstart = genstart = fp = (word *) realloc(NULL, (nwords + MEMPAD)*W);
   if (!memstart) return;
   memend = memstart + nwords - MEMPAD;
   state = (word) load_heap(nobjs);
}

/* bvec → value library call test with preserved state */
word library_call(word val) {
   word program_state = state;
   word res;
   state = IFALSE; 
   if (program_state == IFALSE) {
      exit(1);
   }
   res = vm((word *) program_state, val);
   return res;
}

size_t list_length(word lispval) {
   size_t l = 0;
   while(lispval != INULL) {
      lispval = G(lispval, 2);
      l++;
   }
   return l;
}

size_t copy_list(uint8_t *ptr, word lispval, size_t max) {
   size_t n = 0;
   while(pairp((word)lispval) && max-- && lispval != INULL) {
      *ptr++ = 255 & immval(G(lispval, 1)); // *ptr++ = car(list)
      n++;
      lispval = G(lispval, 2);              // list   = cdr(list)
   }
   if (lispval != INULL && max == 0) {
      printf("ERROR: lisp return value was not a proper list. Trailing %lu\n", lispval);
   }
   return n;
}

/* read data from *ptr - *(ptr + len), write output to *target and return amount of data written */
size_t radamsa(uint8_t *ptr, size_t len, uint8_t *target, size_t max, unsigned int seed) {
   word *arg, res;
   word lptr = onum((word)ptr, 0);
   word llen = onum((word)len, 0);
   word lmax = onum((word)max, 0);
   word lseed = onum((word)seed, 0);
   arg = fp;
   fp += 5;
   arg[0] = make_header(5, TTUPLE);
   arg[1] = lptr;
   arg[2] = llen;
   arg[3] = lmax;
   arg[4] = lseed;
   res = library_call((word) arg);
   return copy_list(target, res, max);
}

size_t radamsa_inplace(uint8_t *ptr, size_t len, size_t max, unsigned int seed) {
   return radamsa(ptr, len, ptr, max, seed);
}

