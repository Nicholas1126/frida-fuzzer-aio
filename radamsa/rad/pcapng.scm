(define-library (rad pcapng)

  (import
    (owl list-extra)
    (scheme base)
    (owl base)
    (owl lazy))

  (export
    pcapng-input?
    pcapng-block-to-mutate?
    pcapng-instrument-mutations
    uint32->bytes
    bytes->uint32)

  (begin

    ;; list utils

    (define (lget lst pos def)
      (cond
        ((null? lst) def)
        ((eq? pos 0) (car lst))
        (else
         (lget (cdr lst) (- pos 1) def))))

    (define (flatten l)
      (cond
        ((null? l) '())
        ((list? (car l)) (append (flatten (car l)) (flatten (cdr l))))
        (else (cons (car l) (flatten (cdr l))))))

    (define (pick from n l)
      (take (drop l from) n))

    ;; bytes utils

    (define (bytes->uint32 bytes)
      (let ((b0 (car bytes))
            (b1 (cadr bytes))
            (b2 (caddr bytes))
            (b3 (cadddr bytes)))
        (+ (<< b3 24) (+ (<< b2 16) (+ (<< b1 8) b0)))))

    (define (uint32->bytes n)
      (list (modulo (>> n 0)  256)
            (modulo (>> n 8)  256)
            (modulo (>> n 16) 256)
            (modulo (>> n 24) 256)))

    ;; Enhanced Packet Block

    (define (build-padding packet-length)
      (let ((remaining-bytes (modulo packet-length 4)))
        (cond ((eq? remaining-bytes 1) '(0 0 0))
              ((eq? remaining-bytes 2) '(0 0))
              ((eq? remaining-bytes 3) '(0))
              (else                    '()))))

    (define (parse-enhanced-block block)
      (let* ((packet-length (bytes->uint32 (pick 20 4 block)))
             (padding-length (- 4 (modulo packet-length 4)))
             (packet-length-with-padding (+ packet-length padding-length))
             (options-length (- (length block) (+ 28 packet-length-with-padding 4))))
        (list (cons 'block-type               (pick 0  4 block))
              (cons 'first-block-total-length (bytes->uint32 (pick 4 4 block)))
              (cons 'interface-id             (pick 8  4 block))
              (cons 'timestamp-high           (pick 12 4 block))
              (cons 'timestamp-low            (pick 16 4 block))
              (cons 'captured-packet-length   (pick 20 4 block))
              (cons 'original-packet-length   (pick 24 4 block))
              (cons 'packet-data              (pick 28 (+ packet-length) block))
              (cons 'options                  (pick (+ 28 packet-length-with-padding) options-length block))
              (cons 'last-block-total-length  (bytes->uint32 (pick (+ 28 packet-length-with-padding options-length) 4 block))))))

    (define (extract-enhanced-packet block)
      (cdr (assq 'packet-data (parse-enhanced-block block))))

    (define (new-enhanced-block original-block-bytes modified-packet)
      (let* ((original-block (parse-enhanced-block original-block-bytes))
             (packet-with-padding (append modified-packet (build-padding (length modified-packet)))))
        (flatten (list (cdr (assq 'block-type original-block))
                       (uint32->bytes (+ 32 (length packet-with-padding) (length (cdr (assq 'options original-block)))))
                       (cdr (assq 'interface-id original-block))
                       (cdr (assq 'timestamp-high original-block))
                       (cdr (assq 'timestamp-low original-block))
                       (uint32->bytes (length modified-packet))
                       (cdr (assq 'original-packet-length original-block))
                       packet-with-padding
                       (cdr (assq 'options original-block))
                       (uint32->bytes (+ 32 (length packet-with-padding) (length (cdr (assq 'options original-block)))))))))

    ;; instrumentation

    (define (pcapng-input? dict)
      (string=? "pcapng" (caar (get dict 'generators))))

    (define (pcapng-block-to-mutate? block)
      (equal? '(#x06 #x00 #x00 #x00) (take (vector->list block) 4)))

    (define (pcapng-instrument-mutations mutations)
      (define (nop-mutation rs ll meta)
        (values nop-mutation rs ll meta 0))
      (define (instrument mutation)
        (define (instrumented-mutation rs ll meta)
          (let* ((current-block (vector->list (car ll)))
                 (current-block-type (bytes->uint32 (take current-block 4)))
                 (next-blocks (cdr ll)))
            (cond ((equal? current-block-type #x0A0D0D0A)
                   ;; Section Header Block
                   (values nop-mutation rs ll meta 0))
                  ((equal? current-block-type #x00000001)
                   ;; Interface Description Block
                   (values nop-mutation rs ll meta 0))
                  ((equal? current-block-type #x00000003)
                   ;; Simple Packet Block
                   (values nop-mutation rs ll meta 0))
                  ((equal? current-block-type #x00000004)
                   ;; Name Resolution Block
                   (values nop-mutation rs ll meta 0))
                  ((equal? current-block-type #x00000005)
                   ;; Interface Statistics Block
                   (values nop-mutation rs ll meta 0))
                  ((equal? current-block-type #x00000006)
                   ;; Enhanced Packet Block
                   (lets ((original-packet (list->bytevector (extract-enhanced-packet current-block)))
                          (f rs ll meta d (mutation rs (list original-packet) meta))
                          (mutated-packets (map vector->list ll))
                          (mutated-blocks (map (lambda (p)
                                                 (list->bytevector (new-enhanced-block current-block p)))
                                               mutated-packets)))
                         (values instrumented-mutation rs (append mutated-blocks next-blocks) meta d)))
                  ((or (equal? current-block-type #x00000BAD)
                       (equal? current-block-type #x40000BAD))
                   ;; Custom Block
                   (values nop-mutation rs ll meta 0))
                  (else
                   ;; unrecognized block, do not apply the mutation
                   (values nop-mutation rs ll meta 0)))))
        instrumented-mutation)
      (map (lambda (m)
             (tuple (ref m 1) (ref m 2) (instrument (ref m 3)) (ref m 4)))
           mutations))
))
