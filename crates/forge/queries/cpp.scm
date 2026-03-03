; cpp.scm — C++ antipattern queries for the Slop Hunter.
;
; Pattern 0: raw_new — raw `new` expression.
; Prefer std::make_unique<T>() or std::make_shared<T>() for exception safety
; and deterministic ownership.
(new_expression) @raw_new

; Pattern 1: raw_delete — raw `delete` / `delete[]` expression.
; Manual `delete` is error-prone (double-free, leak on exception).
; Ownership should be managed by RAII types (unique_ptr, shared_ptr, vector).
(delete_expression) @raw_delete
