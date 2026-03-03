; bash.scm — Bash antipattern queries for the Slop Hunter.
;
; Pattern 0: unquoted_var — unquoted variable expansion as a command argument.
;
; `$VAR` without double quotes is subject to word splitting and glob expansion,
; producing unpredictable behaviour with values containing spaces or special
; characters (e.g., `rm -rf $DIR` deletes multiple paths if DIR has spaces).
; Always quote: `"$VAR"`.
;
; Captures simple_expansion ($VAR) and expansion (${VAR}) nodes that appear
; as direct children of a command node — i.e., unquoted top-level arguments.
; Expansions inside double-quoted strings are NOT captured (they are children
; of a string node, not a command node).
(command
  (simple_expansion) @unquoted_var)

(command
  (expansion) @unquoted_var)
