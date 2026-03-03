; c_sharp.scm — C# antipattern queries for the Slop Hunter.
;
; Pattern 0: async_void_method — method declarations.
; Text predicate filtering (async + void) is done in Rust because tree-sitter
; predicate support varies across grammar versions.  Rust code checks
; node.utf8_text() for "async " AND for a void return type.
(method_declaration) @async_void_method
