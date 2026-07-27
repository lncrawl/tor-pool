package pool

import (
	"math/rand/v2"

	"github.com/lncrawl/tor-pool/internal/tor"
)

// pick chooses the instance a new session should be pinned to.
//
// Fewest pinned sessions wins, so callers spread across the pool instead of
// piling onto whichever instance happens to be first. Ties are broken randomly:
// with an all-equal pool (the common case at startup) a deterministic tie-break
// would send every new session to the same instance until its count rose.
//
// exclude lets a rotation avoid handing back the instance the caller is trying
// to get away from. It is a preference, not a guarantee — with a single healthy
// instance, that instance is still better than refusing to route.
func pick(candidates []*tor.Instance, counts map[int]int, exclude int) *tor.Instance {
	best := pickExcluding(candidates, counts, exclude)
	if best != nil {
		return best
	}
	return pickExcluding(candidates, counts, -1)
}

func pickExcluding(candidates []*tor.Instance, counts map[int]int, exclude int) *tor.Instance {
	var (
		best   []*tor.Instance
		lowest int
	)
	for _, inst := range candidates {
		idx := inst.Index()
		if idx == exclude {
			continue
		}
		n := counts[idx]
		switch {
		case len(best) == 0 || n < lowest:
			best = append(best[:0], inst)
			lowest = n
		case n == lowest:
			best = append(best, inst)
		}
	}

	switch len(best) {
	case 0:
		return nil
	case 1:
		return best[0]
	default:
		return best[rand.IntN(len(best))]
	}
}
