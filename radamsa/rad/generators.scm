;;;
;;; Data Generators
;;;


;; a generator

(define-library (rad generators)

   (import
      (owl base)
      (owl sys)
      (rad shared)
      (rad fuse)
      (only (owl primop) halt)
      (rad pcapng))

   (export
      string->generator-priorities         ;; done at cl args parsing time
      generator-priorities->generator      ;; done after cl args
      stream-port
      rand-block-size                      ;; rs → rs n
      )

   (begin

      (define null '())

      (define (rand-block-size rs)
         (lets ((rs n (rand rs max-block-size)))
            (values rs (max n min-block-size))))

      ;; bvec|F bvec → bvec
      (define (merge head tail)
         (if head
            (list->vector (vec-foldr cons (vec-foldr cons null tail) head))
            tail))

      (define (finish rs len)
         null)

      ;; store length so that extra data can be generated in case of no or very
      ;; little sample data, which would cause one or very few possible outputs

      (define (stream-port rs port)
         (lets ((rs first (rand-block-size rs)))
            (let loop ((rs rs) (last #false) (wanted first) (len 0)) ;; 0 = block ready (if any)
               (let ((block (read-bytevector wanted port)))
                  (cond
                     ((eof-object? block) ;; end of stream
                        (if (not (eq? port stdin)) (close-port port))
                        (if last
                           (cons last (finish rs (+ len (sizeb last))))
                           (finish rs len)))
                     ((not block) ;; read error, could be treated as error
                        (if (not (eq? port stdin)) (close-port port))
                        (if last (list last) null))
                     ((eq? (sizeb block) wanted)
                        ;; a block of required (deterministic) size is ready
                        (lets
                           ((block (merge last block))
                            (rs next (rand-block-size rs)))
                           (pair block (loop rs #false next (+ len (sizeb block))))))
                     (else
                        (loop rs (merge last block)
                           (- wanted (sizeb block))
                           len)))))))

      (define (pcapng-port->stream port)
         (define (recognize-endianness block-header block-body default-endianness)
            (let ((block-type (bytes->uint32 (take block-header 4))))
               (if (and (equal? block-type #x0A0D0D0A) (>= (length block-body) 4))
                  (let ((byte-order-magic (take block-body 4)))
                     (cond
                        ((equal? byte-order-magic '(#x1A #x2B #x3C #x4D))
                           ;; 'big-endian
                           (print "pcapng-port->stream (recognize-endianness): big-endian is not supported")
                           (close-port port)
                           (halt 1))
                        ((equal? byte-order-magic '(#x4D #x3C #x2B #x1A))
                           'little-endian)
                        (else
                           (print "pcapng-port->stream (recognize-endianness): cannot recognize endianness")
                           (print "expecting either " '(#x1A #x2B #x3C #x4D) " or " '(#x4D #x3C #x2B #x1A) ", found " byte-order-magic)
                           (close-port port)
                           (halt 1))))
                  default-endianness)))

         (define (read-block-header port)
            (let ((block-header (read-bytevector 8 port)))
               (cond
                  ((eof-object? block-header)
                     (close-port port)
                     null)
                  ((eq? 8 (vector-length block-header))
                     (vector->list block-header))
                  (else
                     (print "pcapng-port->stream: cannot read the initial 8 bytes of the current block")
                     (close-port port)
                     (halt 1)))))

         (define (read-block-content port block-header)
            (let* ((block-type (bytes->uint32 (take block-header 4)))
                   (block-length (bytes->uint32 (drop block-header 4)))
                   (block-content-length (- block-length 12))
                   (block-content (read-bytevector block-content-length port)))
               (cond
                  ((eof-object? block-content)
                     (print "pcapng-port->stream: cannot read block content, encountered end of file earlier than expected")
                     (close-port port)
                     (halt 2))
                  ((eq? block-content-length (vector-length block-content))
                     (vector->list block-content))
                  (else
                     (print "pcapng-port->stream: cannot read block content, received less than expected (length=" block-content-length ")")
                     (close-port port)
                     (halt 3)))))

         (define (read-last-block-length port block-header)
            (let ((expected-block-length (bytes->uint32 (drop block-header 4)))
                  (last-block-length (read-bytevector 4 port)))
               (cond
                  ((eof-object? last-block-length)
                     (print "pcapng-port->stream:  cannot read last block length, encountered end of file earlier than expected")
                     (close-port port)
                     (halt 4))
                  ((and (eq? 4 (vector-length last-block-length))
                        (eq? expected-block-length (bytes->uint32 (vector->list last-block-length))))
                     (vector->list last-block-length))
                  (else
                     (print "pcapng-port->stream:  bad last block length")
                     (close-port port)
                     (halt 5)))))

         (define (read-next-block port endianness)
            (let ((block-header (read-block-header port)))
               (if (not (null? block-header))
                  (let ((block-content (read-block-content port block-header)))
                     (if (not (null? block-content))
                        (let ((last-block-length (read-last-block-length port block-header)))
                           (if (not (null? last-block-length))
                              (values (list->bytevector (append block-header (append block-content last-block-length)))
                                 (recognize-endianness block-header block-content endianness)
                                 (equal? '(#x06 #x00 #x00 #x00) (take block-header 4)))
                              (values null endianness #false)))
                        (values null endianness #false)))
                  (values null endianness #false))))

         (let loop ((endianness 'little-endian) (encountered-interesting-block #false))
            (lets
               ((block endianness encountered-new-interesting-block (read-next-block port endianness)))
               (if (not (null? block))
                  (pair block (loop endianness (or encountered-interesting-block encountered-new-interesting-block)))
                  (if encountered-interesting-block
                     null
                     (begin
                        (print "pcapng-port->stream: you must provide a file which has at least an EPB block to mutate!")
                        (halt 6)))))))

      ;; rs port → rs' (bvec ...), closes port unless stdin
      (define (port->stream rs port)
         (lets ((rs seed (rand rs 100000000000000000000)))
            (values rs
               (λ () (stream-port (seed->rands seed) port)))))

      ;; dict paths → gen
      ;; gen :: rs → rs' ll meta
      (define (stdin-generator rs online?)
         (lets
            ((rs ll (port->stream rs stdin))
             (ll (if online? ll (force-ll ll)))) ;; preread if necessary
            (λ (rs)
               ;; note: independent of rs. could in offline case read big chunks and resplit each.
               ;; not doing now because online case is 99.9% of stdin uses
               (values rs ll (put empty 'generator 'stdin)))))

      (define (random-block rs n out)
         (if (eq? n 0)
            (values rs (list->bytevector out))
            (lets ((digit rs (uncons rs #f)))
               (random-block rs (- n 1) (cons (fxand digit 255) out)))))

      (define (random-stream rs)
         (lets
            ((rs n (rand-range rs 32 max-block-size))
             (rs b (random-block rs n null))
             (rs ip (rand-range rs 1 100))
             (rs o (rand rs ip)))
            (if (eq? o 0) ;; end
               (list b)
               (pair b (random-stream rs)))))

      (define (random-generator rs)
         (lets ((rs seed (rand rs #x1000000000000000000)))
            (values rs
               (random-stream (seed->rands seed))
               (put empty 'generator 'random))))

      (define (fatal-read-error path)
         (if (dir->list path)
            (print*-to stderr (list "Error: failed to open '" path "'. Please use -r if you want to include samples from directories."))
            (print*-to stderr (list "Error: failed to open '" path "'")))
         (halt exit-read-error))

      ;; paths → (rs → rs' ll|#false meta|error-str)
      (define (file-streamer paths)
         (lets
            ((n (vector-length paths)))
            (define (gen rs)
               (lets
                  ((rs n (rand rs n))
                   (path (vector-ref paths n))
                   (port (open-input-file path)))
                  (if port
                     (lets ((rs ll (port->stream rs port)))
                        (values rs ll
                           (list->ff (list '(generator . file) (cons 'source path)))))
                     (fatal-read-error path))))
            gen))

      (define (pcapng-streamer paths)
         (define (gen rs)
            (if (= (vector-length paths) 1)
               (lets
                  ((path (vector-ref paths 0))
                   (port (open-input-file path)))
                  (if port
                     (values rs (pcapng-port->stream port)
                        (list->ff (list '(generator . pcapng) (cons 'source path))))
                     (fatal-read-error path)))
               (begin
                  (print*-to stderr (list "pcapng-streamer: multiple pcapng files are not supported."))
                  (halt 1))))
         gen)

      (define (consume ll)
         (cond
            ((null? ll) ll)
            ((pair? ll) (consume (cdr ll)))
            (else (consume (ll)))))

      (define (walk-to-jump rs ip a as b bs)
         (lets
            ((finish
               (λ ()
                  (lets
                     ((a (vector->list a))
                      (b (vector->list b))
                      (rs ab (fuse rs a b)))
                     (consume as)
                     (cons (list->bytevector ab) bs))))
             (rs n (rand rs ip))
             (ip (+ ip 1)))
             (if (eq? n 0)
               (finish)
               (lets ((aa as (uncons as #false)))
                  (if aa
                     (lets ((rs n (rand rs 3)))
                        (if (eq? n 0)
                           (cons a
                              (walk-to-jump rs ip aa as b bs))
                           (lets ((bb bs (uncons bs #false)))
                              (if bb
                                 (cons a
                                    (walk-to-jump rs ip aa as bb bs))
                                 (finish)))))
                     (finish))))))

      (define (jump-somewhere rs la lb)
         (lets ((a as (uncons la #false)))
            (if a
               (lets ((b bs (uncons lb #false)))
                  (if b
                     (walk-to-jump rs 3 a as b bs)
                     (cons a as)))
               lb)))

      (define (jump-streamer paths)
         (lets ((n (vector-length paths)))
            (define (gen rs)
               (lets
                  ((rs ap (rand rs n))
                   (rs bp (rand rs n))
                   (a (vector-ref paths ap))
                   (b (vector-ref paths bp))
                   (pa (open-input-file a))
                   (pb (open-input-file b)))
                  (cond
                     ((not pa) (fatal-read-error a))
                     ((not pb) (fatal-read-error b))
                     (else
                        (lets
                           ((rs lla (port->stream rs pa))
                            (rs llb (port->stream rs pb))
                            (rs seed (rand rs #xfffffffff)))
                           (values rs
                              (jump-somewhere (seed->rands seed) lla llb)
                              (list->ff
                                 (list
                                    '(generator . jump)
                                    (cons 'head a)
                                    (cons 'tail b)))))))))
            gen))

      (define cut-= (string->regex "c/=/"))
      (define cut-comma (string->regex "c/,/"))

      (define (string->generator-priorities str)
         (lets
            ((ps (map cut-= (cut-comma str))) ; ((name [priority-str]) ..)
             (ps (map selection->priority ps)))
            (if (every self ps) ps #false)))

      ;; ((pri . gen) ...) → (rs → gen output)
      (define (mux-generators gs)
         (lets
            ((gs (sort car> gs))
             (n (fold + 0 (map car gs))))
            (define (gen rs)
               (lets
                  ((rs n (rand rs n)))
                  ((choose-pri gs n) rs)))
            gen))

      (define (priority->generator rs args fail n)
         ;; → (priority . generator) | #false
         (λ (pri)
            (lets
               ((paths (filter (λ (x) (not (equal? x "-"))) args))
                (paths (if (null? paths) #false (list->vector paths))))
               (if pri
                  (lets ((name priority pri))
                     (cond
                        ((equal? name "stdin")
                           ;; a generator to read data from stdin
                           ;; check n and preread if necessary
                           (if (find (λ (x) (equal? x "-")) args)
                              ;; "-" was given, so start stdin generator + possibly preread
                              (cons priority
                                 (stdin-generator rs (eq? n 1)))
                              #false))
                        ((equal? name "file")
                           (if paths
                              (cons priority (file-streamer paths))
                              #false))
                        ((equal? name "pcapng")
                           (if paths
                              (cons priority (pcapng-streamer paths))
                              #false))
                        ((equal? name "jump")
                           (if paths
                              (cons priority
                                 (jump-streamer paths))
                              #false))
                        ((equal? name "random")
                           (cons priority random-generator))
                        (else
                           (fail (list "Unknown data generator: " name)))))
                  (fail "Bad generator priority")))))

      (define (generator-priorities->generator rs pris args fail n)
         (lets
            ((gs (map (priority->generator rs args fail n) pris))
             (gs (filter self gs)))
            (cond
               ((null? gs) (fail "no generators"))
               ((null? (cdr gs)) (cdar gs))
               (else (mux-generators gs)))))

))
