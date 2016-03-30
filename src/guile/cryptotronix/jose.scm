(define-module (cryptotronix jose)
  #:version (0 1)
  #:use-module (rnrs bytevectors)
  #:use-module (srfi srfi-1)
  #:use-module (ice-9 format)
  #:use-module (srfi srfi-64)
  #:use-module (srfi srfi-9)
  #:use-module (srfi srfi-9 gnu)
  #:use-module (srfi srfi-11)
  #:export (bv->base64url
            base64url->bv
            jwt->scm
            yacl-p256-verify))

(load-extension "/usr/local/lib/libjosec" "josec_init_guile")


(define (key-get-components key)
  (filter list? (cadr key)))

(define (component-match x)
  (lambda (y) (eq? (car y) x)))

(define (key-get-component x key)
  (cadar (filter (component-match x) (key-get-components key))))
