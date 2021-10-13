package paas.lib.object

# tactical helpers to merge objects. This will be in the standard library soon as object.union.

has_key(x, k) { _ = x[k] }

pick_first(k, a, b) = a[k]
pick_first(k, a, b) = b[k] { not has_key(a, k) }

union(a, b) = c {
    ks := {k | some k; _ = a[k]} | {k | some k; _ = b[k]}
    c := {k: v | some k; ks[k]; v := pick_first(k, b, a)}
}
