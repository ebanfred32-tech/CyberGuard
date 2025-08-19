;; CyberGuard Threat Submission Contract
;; Clarity v2
;; Handles anonymous submissions of encrypted threat intelligence, bug reports, and vulnerabilities.
;; Stores metadata for severity, affected systems, proof-of-concept, and other details.
;; Implements access control for revealing sensitive data only to verified parties (e.g., DAO members).
;; Integrates hooks for verification and reward processes.

(define-constant ERR-NOT-AUTHORIZED u100)
(define-constant ERR-INVALID-SUBMISSION u101)
(define-constant ERR-THREAT-NOT-FOUND u102)
(define-constant ERR-ALREADY-REVEALED u103)
(define-constant ERR-PAUSED u104)
(define-constant ERR-ZERO-ADDRESS u105)
(define-constant ERR-INVALID-SEVERITY u106)
(define-constant ERR-INVALID-STATUS u107)
(define-constant ERR-ACCESS-DENIED u108)
(define-constant ERR-INVALID-METADATA u109)
(define-constant ERR-SUBMISSION-EXISTS u110)
(define-constant ERR-INVALID-ENCRYPTED-DATA u111)

;; Severity levels
(define-constant SEVERITY-LOW u1)
(define-constant SEVERITY-MEDIUM u2)
(define-constant SEVERITY-HIGH u3)
(define-constant SEVERITY-CRITICAL u4)

;; Status enums
(define-constant STATUS-PENDING u0)
(define-constant STATUS-VERIFIED u1)
(define-constant STATUS-REJECTED u2)
(define-constant STATUS-REWARDED u3)

;; Admin and contract state
(define-data-var admin principal tx-sender)
(define-data-var paused bool false)
(define-data-var threat-counter uint u0)
(define-data-var verifier-contract (optional principal) none) ;; Optional DAO contract for verification

;; Threat storage: threat-id -> threat details
(define-map threats uint
  {
    submitter: principal,
    encrypted-data: (buff 1024), ;; Encrypted threat details
    metadata: {
      severity: uint,
      affected-systems: (string-ascii 256),
      proof-of-concept: (optional (buff 512)),
      description: (string-ascii 512),
      timestamp: uint
    },
    status: uint,
    revealed-to: (list 10 principal), ;; List of principals allowed to view decrypted data
    is-revealed: bool
  }
)

;; Map for submitter's submissions: principal -> list of threat-ids
(define-map submitter-threats principal (list 100 uint))

;; Private helper: is-admin
(define-private (is-admin)
  (is-eq tx-sender (var-get admin))
)

;; Private helper: ensure not paused
(define-private (ensure-not-paused)
  (asserts! (not (var-get paused)) (err ERR-PAUSED))
)

;; Private helper: validate severity
(define-private (validate-severity (severity uint))
  (or (is-eq severity SEVERITY-LOW)
      (is-eq severity SEVERITY-MEDIUM)
      (is-eq severity SEVERITY-HIGH)
      (is-eq severity SEVERITY-CRITICAL))
)

;; Private helper: is-verifier
(define-private (is-verifier)
  (match (var-get verifier-contract)
    some-verifier (is-eq tx-sender some-verifier)
    false
  )
)

;; Transfer admin rights
(define-public (transfer-admin (new-admin principal))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (asserts! (not (is-eq new-admin 'SP000000000000000000002Q6VF78)) (err ERR-ZERO-ADDRESS))
    (var-set admin new-admin)
    (ok true)
  )
)

;; Set verifier contract (e.g., DAO)
(define-public (set-verifier (verifier principal))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (var-set verifier-contract (some verifier))
    (ok true)
  )
)

;; Pause/unpause the contract
(define-public (set-paused (pause bool))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (var-set paused pause)
    (ok pause)
  )
)

;; Submit a new threat
(define-public (submit-threat 
  (encrypted-data (buff 1024))
  (severity uint)
  (affected-systems (string-ascii 256))
  (proof-of-concept (optional (buff 512)))
  (description (string-ascii 512)))
  (begin
    (ensure-not-paused)
    (asserts! (> (len encrypted-data) u0) (err ERR-INVALID-ENCRYPTED-DATA))
    (asserts! (validate-severity severity) (err ERR-INVALID-SEVERITY))
    (asserts! (> (len affected-systems) u0) (err ERR-INVALID-METADATA))
    (asserts! (> (len description) u0) (err ERR-INVALID-METADATA))
    (let 
      (
        (threat-id (+ (var-get threat-counter) u1))
        (current-submissions (default-to (list) (map-get? submitter-threats tx-sender)))
      )
      (map-set threats threat-id
        {
          submitter: tx-sender,
          encrypted-data: encrypted-data,
          metadata: {
            severity: severity,
            affected-systems: affected-systems,
            proof-of-concept: proof-of-concept,
            description: description,
            timestamp: block-height
          },
          status: STATUS-PENDING,
          revealed-to: (list),
          is-revealed: false
        }
      )
      (map-set submitter-threats tx-sender (unwrap-panic (as-max-len? (append current-submissions threat-id) u100)))
      (var-set threat-counter threat-id)
      (print { event: "threat-submitted", threat-id: threat-id, submitter: tx-sender })
      (ok threat-id)
    )
  )
)

;; Update threat status (called by verifier/DAO)
(define-public (update-status (threat-id uint) (new-status uint))
  (begin
    (asserts! (or (is-admin) (is-verifier)) (err ERR-NOT-AUTHORIZED))
    (asserts! (or (is-eq new-status STATUS-VERIFIED)
                  (is-eq new-status STATUS-REJECTED)
                  (is-eq new-status STATUS-REWARDED)) (err ERR-INVALID-STATUS))
    (match (map-get? threats threat-id)
      threat
      (begin
        (map-set threats threat-id (merge threat { status: new-status }))
        (print { event: "status-updated", threat-id: threat-id, new-status: new-status })
        (ok true)
      )
      (err ERR-THREAT-NOT-FOUND)
    )
  )
)

;; Grant access to reveal data to a principal
(define-public (grant-access (threat-id uint) (to principal))
  (begin
    (asserts! (or (is-admin) (is-verifier)) (err ERR-NOT-AUTHORIZED))
    (match (map-get? threats threat-id)
      threat
      (let ((current-revealed (get revealed-to threat)))
        (asserts! (< (len current-revealed) u10) (err ERR-INVALID-SUBMISSION))
        (map-set threats threat-id (merge threat { revealed-to: (unwrap-panic (as-max-len? (append current-revealed to) u10)) }))
        (ok true)
      )
      (err ERR-THREAT-NOT-FOUND)
    )
  )
)

;; Reveal encrypted data (only if granted access or admin/verifier)
(define-read-only (reveal-data (threat-id uint))
  (match (map-get? threats threat-id)
    threat
    (if (or (is-admin) (is-verifier) (is-some (index-of (get revealed-to threat) tx-sender)))
      (ok (get encrypted-data threat))
      (err ERR-ACCESS-DENIED)
    )
    (err ERR-THREAT-NOT-FOUND)
  )
)

;; Mark as fully revealed (e.g., after verification)
(define-public (mark-revealed (threat-id uint))
  (begin
    (asserts! (or (is-admin) (is-verifier)) (err ERR-NOT-AUTHORIZED))
    (match (map-get? threats threat-id)
      threat
      (if (not (get is-revealed threat))
        (begin
          (map-set threats threat-id (merge threat { is-revealed: true }))
          (print { event: "threat-revealed", threat-id: threat-id })
          (ok true)
        )
        (err ERR-ALREADY-REVEALED)
      )
      (err ERR-THREAT-NOT-FOUND)
    )
  )
)

;; Read-only: get threat metadata
(define-read-only (get-threat-metadata (threat-id uint))
  (match (map-get? threats threat-id)
    threat (ok (get metadata threat))
    (err ERR-THREAT-NOT-FOUND)
  )
)

;; Read-only: get threat status
(define-read-only (get-threat-status (threat-id uint))
  (match (map-get? threats threat-id)
    threat (ok (get status threat))
    (err ERR-THREAT-NOT-FOUND)
  )
)

;; Read-only: get submitter's threats
(define-read-only (get-submitter-threats (submitter principal))
  (ok (default-to (list) (map-get? submitter-threats submitter)))
)

;; Read-only: get total threats
(define-read-only (get-total-threats)
  (ok (var-get threat-counter))
)

;; Read-only: get admin
(define-read-only (get-admin)
  (ok (var-get admin))
)

;; Read-only: get verifier
(define-read-only (get-verifier)
  (ok (var-get verifier-contract))
)

;; Read-only: check if paused
(define-read-only (is-paused)
  (ok (var-get paused))
)