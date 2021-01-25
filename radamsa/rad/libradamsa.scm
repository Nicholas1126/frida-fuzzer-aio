(import
   (owl base)
   (only (owl sys) peek-byte getenv)
   (only (rad main) urandom-seed)
   (only (rad output) byte-list-checksummer)
   (only (rad mutations)
      mutators->mutator
      string->mutators default-mutations)
   (only (rad output)
      stream-chunk)
   (only (rad patterns)
      default-patterns
      string->patterns)
   (only (rad generators)
      rand-block-size)
   (only (rad digest)
      string->hash
      empty-digests
      dget
      dput))

(import
   (only (owl syscall) library-exit)) ;; library call return/resume


;; when testing
; (define sample-data (list->vector (string->list "<b>HAL</b> 9000")))
; (define (peek-byte ptr) (vector-ref sample-data (band ptr 15)))

;; todo: add a proper read primop
(define (read-memory-simple ptr len)
   (if (eq? len 0)
      #null
      (cons (peek-byte ptr)
         (read-memory-simple (+ ptr 1) (- len 1)))))

(define (read-memory-simple ptr len)
   (if (eq? len 0)
      #null
      (cons (peek-byte ptr)
         (read-memory-simple (+ ptr 1) (- len 1)))))


;; rs ptr len → rs (bvec ...)
(define (read-memory->chunks rs source len)
   (if (> len 0)
      (lets
         ((rs s (rand-block-size rs))
          (s (min s len))
          (rs tail (read-memory->chunks rs (+ source s) (- len s)))
          (bv (list->bytevector (read-memory-simple source s))))
         (values rs
            (cons bv tail)))
      (values rs #null)))

(define mutas
   (lets ((rs mutas
            (mutators->mutator
               (seed->rands 42)
               (string->mutators default-mutations))))
      mutas))

(define patterns
   (string->patterns default-patterns))

(define library-checksummer
   (byte-list-checksummer (string->hash "stream")))

(define initial-digests
   (empty-digests (* 8 1024)))

;; fuzzer output is a ll of byte vectors followed by a #(rs muta meta) -tuple
;; generate a byte list (for now) of the data to be returned and also return
;; the mutas, which is where radamsa learns

;; rs muta input-chunks → rs' muta' (byte ...)
(define (fuzz->output rs muta chunks)
   (lets
      ((routput (reverse (force-ll (patterns rs chunks muta empty))))
       (state (car routput))
       (rs muta meta state)
       (output-bytes
          (fold
             (λ (out chunk)
                (let ((n (vector-length chunk)))
                   (if (eq? n 0)
                      out
                      (stream-chunk chunk (- n 1) out))))
             #null
             (cdr routput))))
       (values rs muta output-bytes)))


(define (mutate-simple mutator byte-list seed)
   (lets
      ((mutator rs chunks meta
         (mutator
            (seed->rands seed)
            (list (list->bytevector byte-list))
            empty)))
      (values
         mutator
         (foldr
            (λ (bvec out)
               (append (bytevector->list bvec) out))
            '()
            chunks))))

(define (fuzz-unseen rs cs muta input)
   (lets
      ((rs muta output
         (fuzz->output rs muta input))
       (out-lst cs csum
          (library-checksummer cs output)))
      (if csum
         ;; this was unique
         (values rs cs muta output)
         ;; duplicate, retry with subsequent random state
         (fuzz-unseen rs cs muta input))))

(define (fuzz-maybe-seen rs cs muta input)
   (lets
      ((rs muta output
         (fuzz->output rs muta input)))
      (values rs cs muta output)))

(define fuzzer
   fuzz-maybe-seen  ;; just output mutated data
   ;fuzz-unseen     ;; with uniqueness filter
   )

; (define (library-exit value) (print "LIBRARY WOULD RETURN " value) "foo")

(define (debug . what)
   (if (getenv "RADAMSA_DEBUG")
      (print-to stderr (apply str (cons "libradamsa/lisp: " what)))))

;(define debug #false)

(define (fuzz muta digests)
   (λ (tuple-from-c)
      (lets
         ((ptr len max seed tuple-from-c)
          (start (time-ms)))
         (debug "input " tuple-from-c)
         (cond
            ((= len 0)
               ;; dummy handling of empty sample input
               (debug "dummy")
               ((fuzz muta digests)
                  (library-exit (list (band seed #xff)))))
            (else
               (lets
                  ((rs (seed->rands seed))
                   (rs inputp (read-memory->chunks rs ptr len))
                   (rs digests muta output
                      (fuzzer rs digests muta inputp)))
                  (debug "input " inputp)
                  (debug "output " output)
                  ((fuzz muta digests)
                     (library-exit output))))))))

(define (try input)
   ((fuzz mutas initial-digests)
      (tuple input 32 64  (time-ms))))

;; load-time test
; (try 0)

;; fasl test
; (λ (args) (try (fuzz mutas initial-digests)))

;; C test
(fuzz mutas initial-digests)


