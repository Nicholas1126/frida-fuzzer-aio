

(define-library (rad digest)

   (import
      (owl base)
      (owl lazy)
      (owl codec)
      (owl digest)) ;; sha256-raw ll → (fixnum ...)

   (export
      string->hash    ;; used for command line argument
      empty-digests
      bytes->trits
      dget            ;; digests digest -> bool
      dput            ;; digests digest -> digests
      digest)

   (begin

      (define max-hash-count (* 1024 1024))

      (define null '())

      (define (empty-digests max)
         (tuple empty max 0))

      (define (dget* tree d)
         (if (eq? tree empty)
            #false
            (lets ((digit d d))
               (if (null? d)
                  (get tree digit #false)
                  (dget* (get tree digit empty) d)))))

      (define (dget tree d)
         (dget* (ref tree 1) d))

      (define (dput* tree d)
         (if (null? (cdr d))
            (put tree (car d) #true)
            (put tree (car d)
               (dput* (get tree (car d) empty) (cdr d)))))

      (define (prune tree size)
         (tuple empty size 0))

      (define (grow tree old-size)
         (empty-digests
            (min (* old-size 2) max-hash-count)))

      (define (dput cs d)
         (lets ((tree max n cs))
            (if (eq? n max)
               (dput (grow tree max) d)
               (tuple (dput* tree d) max (+ n 1)))))

      (define (bs->trits bs)
         (if (null? bs)
            null
            (lets
               ((a bs (uncons bs 0))
                (b bs (uncons bs a))
                (c bs (uncons bs b))
                (a (<< a 16))
                (b (<< b 8)))
               (pair
                  (fxior (fxior a b) c)
                  (bs->trits bs)))))

      (define (trit a b c)
         (lets
            ((a (<< a 16))
             (b (<< b 8)))
            (fxior (fxior a b) c)))

      (define (get-trit ll)
         (cond
            ((null? ll) (values 0 0 ll))
            ((pair? ll)
               (lets ((a ll ll))
                  (cond
                     ((null? ll) (values a 1 ll))
                     ((pair? ll)
                        (lets ((b ll ll))
                           (cond
                              ((null? ll) (values (trit a b 0) 2 ll))
                              ((pair? ll) (lets ((c ll ll)) (values (trit a b c) 3 ll)))
                              (else
                                 (lets ((c ll (uncons ll #f)))
                                    (if c (values (trit a b c) 3 ll)
                                          (values (trit a b 0) 2 ll)))))))
                    (else
                       (get-trit (cons a (ll)))))))
            (else (get-trit (ll)))))


      ;;; Custom Stream hash

      (define (pollinate a b)
         (lets ((ah a (fx>> a 21))
                (bh b (fx>> b 21))
                (a (fxior a bh))
                (b (fxior b ah)))
            (values a b)))

      (define (digest ll)
         (lets ((fst len ll (get-trit ll)))
            (let loop ((ll ll) (a fst) (sum fst) (len len) (par fst) (lag 0))
               (if (null? ll)
                  (list
                     (band #xffffff (bior (<< sum 10) len))
                     (if (= fst a) fst (fxxor fst a))
                     par
                     lag)
                  (lets ((b n ll (get-trit ll))
                         (sum _ (fx+ sum b))
                         (len _ (fx+ len n))
                         (par (fxxor par b)))
                        (if (eq? (fxand len #b1) #b1)
                           (lets ((par lag (pollinate par lag)))
                              (loop ll b sum len par lag))
                           (lets ((sum par (pollinate sum par)))
                              (loop ll b sum len par lag))))))))

      ;; 1111 1111 1111 1111 1111 1111
      (define (hexes f tl)
         (lets
            ((a (band     f     #b1111))
             (b (band (>> f  4) #b1111))
             (c (band (>> f  8) #b1111))
             (d (band (>> f 12) #b1111))
             (e (band (>> f 16) #b1111))
             (f (band (>> f 20) #b1111)))
            (ilist a b c d e f tl)))

      (define hex-chars
         (vector #\0 #\1 #\2 #\3 #\4 #\5 #\6 #\7 #\8 #\9 #\A #\B #\C #\D #\E #\F))

      (define (stringify hash)
         (list->string
            (map
               (λ (x) (vector-ref hex-chars x))
               (foldr hexes #null hash))))

      (define (hash-stream ll)
         (let ((res (digest ll)))
            (values res (stringify res))))


      ;;; SHA256

      ;; merge 3 bytes, since they fit a fixnum
      (define (bytes->trits lst)
         (let loop ((lst lst) (trit 0) (n 0))
            (cond
               ((null? lst)
                  (if (eq? n 0)
                     null
                     (list trit)))
               ((eq? n 3)
                  (cons trit (loop lst 0 0)))
               (else
                  (loop (cdr lst)
                     (bior (<< trit 8) (car lst))
                     (+ n 1))))))

      (define (hash-sha256 lst)
         (let ((bs (sha256-bytes lst)))
            (values
               (bytes->trits bs)
               (hex-encode-list bs))))

      (define (hash-sha1 lst)
         (let ((bs (sha1-bytes lst)))
            (values
               (bytes->trits bs)
               (hex-encode-list bs))))

      (define (string->hash s)
         (cond
            ((string-ci=? s "stream") hash-stream)
            ((string-ci=? s "sha256") hash-sha256)
            ((string-ci=? s "sha1") hash-sha1)
            ((string-ci=? s "sha") hash-sha256)
            (else #f)))

))



