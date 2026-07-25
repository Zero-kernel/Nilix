#!/usr/bin/env bash
# D2-ERR-VFS-FALLIBILITY: mechanized fallibility lint (PO-VFS-01 section 4.2, as-built).
#
# Flags INFALLIBLE heap-growth operations on recoverable VFS paths -- operations
# that turn an out-of-memory condition into a kernel panic instead of a returned
# ENOMEM. Pure POSIX grep/awk/find: NO ripgrep (the CI lint job provisions nothing
# beyond checkout; no `rg` exists anywhere in the Makefile).
#
# A candidate line is SUPPRESSED if ANY of:
#   1. it is a pure comment/doc line, or the candidate appears only in a trailing
#      `// ...` comment (lint-fetch-add precedent);
#   2. FN-SCOPE GUARD: the enclosing fn body contains `try_reserve` / `heap_no_space(`
#      / `try_insert(` anywhere (order-insensitive) -- the fn demonstrably practices
#      fallible-reservation discipline;
#   3. TEST EXCLUSION (deliberate -- boot self-tests are boot-fatal-by-policy on OOM):
#      the fn name contains `test`, or a `#[test]`/`#[cfg(test)]` attribute sits within
#      3 lines above the fn decl, or the file is under a `*/tests/*` path;
#   4. LITERAL-SOURCE forms (`"...".to_string()`, `"...".to_owned()`,
#      `String::from("...")`) -- compile-time bounded by construction;
#   5. an ANNOTATION on the hit line or up to 3 lines above.
#
# Annotation grammar (reason parenthetical MUST be non-empty):
#   // lint-fallible: PREALLOCATED(<evidence>) | BOUNDED(<bound>) | INFALLIBLE-OK(<reason>)
#   // lint-fallible-fn: <same tokens>(<reason>)   (3 lines above a fn; blesses its body)
#
# This is a grep-based CANDIDATE-FINDER backed by audit rounds (same trust model as
# lint-fetch-add / lint-repr-c-copy), NOT a complete static proof. Known escape
# classes (documented in PO-VFS-01 as-built; tracked as backlog):
#   G4  fn-scope guard is coarse: one try_reserve in a fn blesses sibling candidates
#       (no receiver identity / control-flow dominance / capacity accounting).
#   G5  format!/write!/writeln! are NOT in the candidate set: VFS content-building
#       goes through AdmittedString (ledger-charged) and Debug/Display write to a
#       Formatter (no alloc), so a naive `write!(`/`format!(` gate is all false
#       positives. A try_format! primitive + a targeted gate is backlog.
#   G6  fn-level exemptions are future-wide (a later candidate added to the same fn
#       is silently blessed); string `+=`, Vec::from, entry().or_insert(), alias
#       imports, and allocation-hiding macros are not modelled.
# These bound the gate's guarantee to "flags the enumerated infallible-growth surface
# on kernel/vfs unless guarded/annotated"; deeper coverage is a semantic (dylint)
# follow-on.
#
# Usage:  scripts/lint_fallible.sh <dir-or-file> [more...]
# Prints  file:line:content  for each unsuppressed candidate; exit 1 if any, else 0.
set -u

status=0
files=$(find "$@" -name '*.rs' -not -path '*/tests/*' 2>/dev/null | sort)
# also accept explicit .rs file arguments (fixtures) that `find` already yields

for f in $files; do
    out=$(awk '
    { line=$0; sub(/\r$/,"",line); a[NR]=line }
    END {
        CAND="\\.push\\(|\\.push_str\\(|\\.extend\\(|\\.extend_from_slice\\(|\\.append\\(|\\.resize\\(|\\.insert\\(|\\.to_vec\\(|\\.to_string\\(|\\.to_owned\\(|String::from\\(|\\.collect\\(|\\.join\\(|with_capacity\\(|\\.reserve\\(|vec!\\[|Box::new\\(|Rc::new\\(|Arc::new\\("
        GUARD="try_reserve|heap_no_space\\(|try_insert\\("
        ALLOW="lint-fallible(-fn)?: (PREALLOCATED|BOUNDED|INFALLIBLE-OK)\\([^)]*[^ ()][^)]*\\)"
        FNDECL="(^|[[:space:]])fn[[:space:]]+[A-Za-z_][A-Za-z0-9_]*"
        # A line that DECLARES a fn (anchored) -- skipped in pass 2 so a fn name
        # like `fn f_with_capacity()` is not mistaken for an allocation call.
        FNLINE="^[[:space:]]*(pub[[:space:]]+(\\(crate\\)[[:space:]]+)?)?(async[[:space:]]+)?(unsafe[[:space:]]+)?fn[[:space:]]"

        # ---- pass 1: region boundaries + per-region flags ----
        # A region runs from a fn decl (or a top-level `}` opening a no-fn region)
        # to the next boundary. reg[i] = region id for line i.
        rid=0; istest[0]=0; fnallow[0]=0; guard[0]=0
        for (i=1;i<=NR;i++) {
            l=a[i]
            stripped=l; sub(/^[[:space:]]*/,"",stripped)
            is_comment = (stripped ~ /^\/\//)
            if (!is_comment && l ~ FNDECL) {
                rid++
                # fn name (robust to a column-0 `fn` with no leading whitespace)
                fname=""
                if (match(l, /fn[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/)) {
                    fname=substr(l, RSTART, RLENGTH); sub(/^fn[[:space:]]+/, "", fname)
                }
                istest[rid] = (fname ~ /(^|_)test(_|$)/) ? 1 : 0
                # #[test]/#[cfg(test)] within 3 lines above
                for (k=i-1;k>=i-3 && k>=1;k--) if (a[k] ~ /#\[(cfg\()?test/) istest[rid]=1
                # fn-level annotation within 3 lines above
                fnallow[rid]=0
                for (k=i-1;k>=i-3 && k>=1;k--) if (a[k] ~ ALLOW && a[k] ~ /lint-fallible-fn:/) fnallow[rid]=1
                guard[rid]=0
            } else if (l ~ /^}/) {
                # top-level close brace: open a fresh no-fn region so file-scope
                # items never inherit a preceding fn guard
                rid++; istest[rid]=0; fnallow[rid]=0; guard[rid]=0
            }
            reg[i]=rid
            if (l ~ GUARD) guard[reg[i]]=1
        }

        # ---- pass 2: candidate scan ----
        for (i=1;i<=NR;i++) {
            l=a[i]
            stripped=l; sub(/^[[:space:]]*/,"",stripped)
            if (stripped ~ /^\/\//) continue                 # pure comment/doc line
            if (l ~ FNLINE) continue                          # fn declaration, not a call
            code=l; sub(/[[:space:]]*\/\/.*$/,"",code)        # strip trailing comment
            # literal-source suppression: remove bounded literal forms, then re-test
            probe=code
            gsub(/"[^"]*"\.to_string\(\)/,"",probe)
            gsub(/"[^"]*"\.to_owned\(\)/,"",probe)
            gsub(/String::from\("[^"]*"\)/,"",probe)
            if (probe !~ CAND) continue
            r=reg[i]
            if (istest[r] || fnallow[r] || guard[r]) continue
            # line-level annotation on the hit line or up to 3 lines above
            allowed=0
            for (k=i;k>=i-3 && k>=1;k--) if (a[k] ~ ALLOW) allowed=1
            if (allowed) continue
            printf "%s:%d:%s\n", FILENAME, i, l
        }
    }' "$f")
    if [ -n "$out" ]; then
        echo "$out"
        status=1
    fi
done

exit $status
