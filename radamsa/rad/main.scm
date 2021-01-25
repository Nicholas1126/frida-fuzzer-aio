#!/usr/bin/ol -r

;;;
;;; Radamsa
;;;

(define-library (rad main)

   (import
      (owl base)
      (owl args)
      (owl sys)
      (rad generators)
      (rad output)
      (rad digest)
      (rad patterns)
      (rad mutations)
      (rad shared)
      (rad pcapng))

   (export
      urandom-seed
      radamsa)

   (begin

      (define null '())

      (define (string->count str)
         (cond
            ((member str '("inf" "infinity" "-1" "forever"))
               'infinity)
            ((string->number str 10) =>
               (λ (n)
                  (if (> n 0)
                     n
                     #false)))
            (else #f)))

      (define version-str "Radamsa 0.6")

      (define usage-text "Usage: radamsa [arguments] [file ...]")

      (define about-text

"Radamsa is a general purpose fuzzer. It modifies given sample data
in ways, which might expose errors in programs intended to process
the data. For more information, read the fine manual page, or visit
https://gitlab.com/akihe/radamsa.

Radamsa was written by Aki Helin, initially at OUSPG.")

      (define (string->natural str)
         (let ((i (string->integer str)))
            (if (and i (>= i 0))
               i
               #false)))



      (define command-line-rules
         (cl-rules
            `((help "-h" "--help" comment "show this thing")
              (about "-a" "--about" comment "what is this thing?")
              (version "-V" "--version" comment "show program version")
              (output-pattern "-o" "--output" has-arg default "-" cook ,(λ (x) x)
                  comment "output pattern, e.g. out.bin /tmp/fuzz-%n.%s, -, :80 or 127.0.0.1:80 or 127.0.0.1:123/udp")
              (count "-n" "--count" cook ,string->count
                  default "1" comment "how many outputs to generate (number or inf)")
              (seed "-s" "--seed" cook ,string->natural comment "random seed (number, default random)")
              (mutations "-m" "--mutations" cook ,string->mutators ;; seed not yet known so intermediate value here
                  comment "which mutations to use"
                  default ,default-mutations) ;; these come from (rad mutations)
              (patterns "-p" "--patterns" cook ,string->patterns
                  comment "which mutation patterns to use"
                  default ,default-patterns)
              (generators "-g" "--generators" cook ,string->generator-priorities ; the rest of initialization needs all args
                  comment "which data generators to use"
                  default "random,file=1000,jump=200,stdin=100000")
              (metadata "-M" "--meta" has-arg
                  comment "save metadata about generated files to this file")
              (recursive "-r" "--recursive"
                  comment "include files in subdirectories")
              (offset "-S" "--seek" cook ,string->integer
                  comment "start from given testcase")
              (truncate "-T" "--truncate" cook ,string->integer
                  comment "take only first n bytes of each output (mainly intended for UDP)")
              (delay "-d" "--delay" cook ,string->natural
                  comment "sleep for n milliseconds between outputs")
              (list "-l" "--list" comment "list mutations, patterns and generators")
              (csums "-C" "--checksums" has-arg default "10000" cook ,string->natural
                    comment "maximum number of checksums in uniqueness filter (0 disables)")
              (hash "-H" "--hash" cook ,string->hash default "stream"
                    comment "hash algorithm for uniqueness checks (stream, sha1 or sha256)")
              (verbose "-v" "--verbose" comment "show progress during generation"))))

      ;; () → string
      (define (urandom-seed)
         (let ((fd (open-input-file "/dev/urandom"))) ;; #false if not there
            (if fd
               (let ((data (read-bytevector 10 fd)))
                  (close-port fd)
                  (if (vector? data)
                     (vec-fold (λ (n d) (+ d (<< n 8))) 0 data)
                     #false))
               #false)))

      ;; () → string (decimal number)
      (define (time-seed)
         (fold
            (lambda (n b) (bior (<< n 8) b))
            0 (sha256-bytes (str (time-ms)))))

      (define (show-options)
         (print "Mutations (-m)")
         (for-each (λ (opt) (print* (list "  " (ref opt 1) ": " (ref opt 3)))) *mutations*)
         (print "")
         (print "Mutation patterns (-p)")
         (for-each (λ (opt) (print* (list "  " (ref opt 1) ": " (ref opt 3)))) *patterns*)
         (print "")
         (print "Generators (-g)")
         (print " stdin: read data from standard input if no paths are given or - is among them")
         (print " file: read data from given files")
         (print " random: generate random data"))

      ;; drop B as implied
      (define (verbose-size n)
         (define (verb n u)
            (if (or (< n 1024) (null? (cdr u)))
               (render n (render (car u) null))
               (verb (quotient n 1024) (cdr u))))
         (list->string
            (verb n '("b" "K" "M" "T" "P"))))

      (define (serialize-meta val)
         (if (function? val)
            (ff-fold
               (λ (out key val)
                  (render key
                     (ilist #\: #\space
                        ((if (string? val) (make-serializer empty) render)
                           val
                           (if (null? out)
                              '(#\newline)
                              (ilist #\, #\space out))))))
               null val)))

      (define (verbose-target meta)
         (cond
            ((get meta 'path) =>
               (λ (path) path))
            ((eq? 'tcp-client (get meta 'output))
               (str
                  (get meta 'ip '?) ":" (get meta 'port '?) "/"
                  (get meta 'nth 0)))
            ((eq? 'tcp-server (get meta 'output))
               (str ":" (get meta 'port '?) "/"
                  (get meta 'nth 0)
                  " <- " (get meta 'ip "???")))
            (else
               (str (get meta 'nth 0)))))

      ;; ... → (ff | seed | 'close → ...)
      (define (maybe-meta-logger path verbose? fail)
         (define verb
            (if verbose?
               (λ (x)
                  (cond
                     ((eq? x 'close) 42)
                     ((get x 'seed) =>
                        (λ (seed) (print*-to stderr (list "Random seed: " seed))))
                     (else
                        (print*-to stderr
                           (list " - " (verbose-target x)
                              ": " (verbose-size (get x 'length 0)))))))
               (λ (x) x)))
         (cond
            (path
               (let ((port (if (equal? path "-") stdout (open-output-file path))))
                  (if port
                     (λ (stuff)
                        (if (eq? stuff 'close)
                           (if (not (eq? port stdout)) (close-port port))
                           (write-bytes port (serialize-meta stuff)))
                        (verb stuff))
                     (fail "Cannot open metadata log file"))))
            (verbose?
               verb)
            (else
               (λ (x) x))))

      (define (maybe-printer verbose)
         (if verbose
            (λ (args) (print*-to stderr args))
            (λ (args) args)))

      ;; paths → paths' | #false + error to stderr
      (define (include-dirs paths)
         ;; ".../" paths out → out' | #false
         (define (walk prefix paths out)
            (cond
               ((null? paths) out)
               ((not (car paths))
                  (print-to stderr
                     "Error reading sample files. Too long paths?")
                  #false) ;; return nothing so radamsa wil exit
               (else
                  (lets
                     ((this (string-append prefix (car paths))) ;; sans trailing slash
                      (subs (dir->list this)))
                     (if subs
                        ;; need to add the slash to current path
                        (walk prefix (cdr paths)
                           (walk (string-append this "/") subs out))
                        ;; this is a complete path with prefix, if any
                        (walk prefix (cdr paths) (cons this out)))))))
         (walk "" paths null))

      ;; (sample-path ..) → (byte ...)
      (define (pick-suffix paths)
         (if (null? paths)
            (pick-suffix (list ""))
            (let loop ((cs (reverse (string->list (car paths)))) (out null))
               (cond
                  ((null? cs) (string->list "data"))
                  ((eq? (car cs) #\.) out)
                  (else (loop (cdr cs) (cons (car cs) out)))))))

      (define K (λ (a b) a))

      ;; todo: separate generation steps properly
      (define (run-radamsa dict paths)
         (lets/cc ret
            ((fail (λ (why) (print why) (ret 1)))
             (rs (seed->rands (get dict 'seed)))
             (record-meta
               (maybe-meta-logger
                  (get dict 'metadata)
                  (get dict 'verbose)
                  fail))
             (n (get dict 'count))
             (end (if (number? n) (+ n (get dict 'offset 0)) n))
             (mutas (if (pcapng-input? dict)
                  (pcapng-instrument-mutations (get dict 'mutations))
                       (get dict 'mutations)))
             (hash (get dict 'hash))
             (checksummer
                ((if (eq? 0 (get dict 'csums)) dummy-checksummer checksummer)
                   hash))
             (rs muta (mutators->mutator rs mutas))
             (sleeper
              (let ((n (get dict 'delay)))
                (if n (λ () (sleep n)) (λ () 42))))
             (gen
               (generator-priorities->generator rs
                  (get dict 'generators) paths fail end)))
            ;; possibly save the seed to metadata
            (record-meta (put empty 'seed (get dict 'seed)))
            (let loop
               ((rs rs)
                (muta muta)
                (pat (get dict 'patterns))
                (out (get dict 'output 'bug))
                (offset (get dict 'offset 1))
                (p 1)
                (cs (empty-digests (get dict 'csums)))
                (left (if (number? n) n -1)))
               (cond
                ((= left 0)
                   (record-meta 'close)
                   0)
                (else
                  (lets
                     ((rs ll meta (gen rs))
                      (meta (put meta 'nth p))
                      (out-ll (pat rs ll muta meta))
                      (out-lst cs csum (checksummer cs out-ll))
                      (meta (put meta 'checksum (or csum "blank"))))
                     (if csum
                        (if (eq? offset 1)
                           (lets
                              ((out fd meta (out meta))
                               (rs muta generation-meta n-written
                                 (output out-lst fd))
                               (meta
                                  (-> (ff-union meta generation-meta K)
                                     (put 'length n-written))))
                              (record-meta meta)
                              (sleeper)
                              (loop rs muta pat out 1 (+ p 1) cs (- left 1)))
                           (lets ((rs muta meta (dummy-output out-lst)))
                              (loop rs muta pat out (- offset 1) (+ p 1) cs left)))
                        ;; checksum match - drop duplicate
                        (loop rs muta pat out offset p cs left))))))))

      ;; dict args → rval
      (define (start-radamsa dict paths)
         ;; show command line stuff
         (cond
            ((null? paths)
               ;; fuzz stdin when called as $ cat foo | radamsa | bar -
               (start-radamsa dict (list "-")))
            ((not (get dict 'seed))
               ;; get a random seed, prefer urandom
               (start-radamsa
                  (put dict 'seed (or (urandom-seed) (time-seed)))
                  paths))
            ((get dict 'version)
               (print version-str)
               0)
            ((not (get dict 'output))
               (let
                  ((os
                     (string->outputs
                        (get dict 'output-pattern)
                        (get dict 'count)
                        (pick-suffix paths)
                        (not (eq? (get dict 'csums) 0))
                        )))
                  (if os
                     (start-radamsa (put dict 'output os) paths)
                     1)))
            ((get dict 'help)
               (print usage-text)
               (print-rules command-line-rules)
               0)
            ((get dict 'about)
               (print about-text)
               0)
            ((get dict 'list)
               (show-options)
               0)
            ((get dict 'recursive)
               (let ((paths (include-dirs paths)))
                  (if paths ;; could fail due to overly long paths etc
                     (start-radamsa (del dict 'recursive) paths)
                     2)))
            (else
               (run-radamsa dict paths))))

      (define (radamsa args)
         (process-arguments (cdr args)
            command-line-rules
            usage-text
            start-radamsa))))

(import (rad main))

radamsa ;; (arg ...) → int

