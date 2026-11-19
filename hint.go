package authz

// HintSet is the claim-only view of a token's permissions. It is a hint: it
// may be stale until the token expires and must never authorize a write.
type HintSet struct {
	perms map[string]struct{}
}

// Hint builds the claim-only view. A missing or non-array "permissions" claim
// yields an empty set. Matching is exact: no wildcards.
func Hint(c Claims) *HintSet {
	h := &HintSet{perms: map[string]struct{}{}}
	list, _ := c.Permissions()
	for _, p := range list {
		h.perms[p] = struct{}{}
	}
	return h
}

// Can reports whether the claim lists permission. Claim only, no network, no
// token checks (use Verifier and Perms for those).
func (h *HintSet) Can(permission string) bool {
	_, ok := h.perms[permission]
	return ok
}
