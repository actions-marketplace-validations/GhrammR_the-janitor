; java.scm — Java antipattern queries for the Slop Hunter.
;
; Pattern 0: empty_catch — catch block (Rust checks named_child_count == 0).
(catch_clause
  body: (block) @catch_body) @empty_catch

; Pattern 1: sysout_call — method_invocation on a field_access.
; Rust code checks object=="System", field=="out", method starts with "print".
; Text predicates omitted: filtering is done in Rust for grammar portability.
(method_invocation
  object: (field_access
    object: (identifier) @sys
    field: (identifier) @out)
  name: (identifier) @method) @sysout_call
