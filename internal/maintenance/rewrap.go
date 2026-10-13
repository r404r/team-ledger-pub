package maintenance

import (
	"context"
	"errors"
	"time"

	"github.com/r404r/team-ledger/internal/sensitive"
)

type Target struct {
	OrgID, Domain, KEKID string
	Version              uint32
	ManifestDigest       []byte
}
type Item struct {
	Table, ID string
	Key       sensitive.WrappedKey
}
type Actor struct {
	UID        int64
	HostDigest []byte
}
type Store interface {
	BeginKeyRewrap(context.Context, Target, time.Time) error
	NextKeyRewrap(context.Context, Target) (Item, bool, error)
	CommitKeyRewrap(context.Context, Target, Item, sensitive.WrappedKey, time.Time) error
	CompleteKeyRewrap(context.Context, Target, Actor, time.Time) error
}

func RunKeyRewrap(ctx context.Context, store Store, source, target sensitive.Wrapper, plan Target, actor Actor, limit int, now time.Time) (int, bool, error) {
	if store == nil || source == nil || target == nil || plan.OrgID == "" || plan.KEKID == "" || plan.Version == 0 || len(plan.ManifestDigest) != 32 || limit < 1 || limit > 1000 {
		return 0, false, errors.New("invalid key rewrap plan")
	}
	if err := store.BeginKeyRewrap(ctx, plan, now); err != nil {
		return 0, false, err
	}
	completed := 0
	for completed < limit {
		item, found, err := store.NextKeyRewrap(ctx, plan)
		if err != nil {
			return completed, false, err
		}
		if !found {
			if err = store.CompleteKeyRewrap(ctx, plan, actor, now); err != nil {
				return completed, false, err
			}
			return completed, true, nil
		}
		next, err := sensitive.RewrapKey(ctx, source, target, item.Key)
		if err != nil {
			return completed, false, err
		}
		if next.KEKID != plan.KEKID || next.Version != plan.Version {
			clear(next.Data)
			return completed, false, errors.New("key service returned unapproved target")
		}
		if err = store.CommitKeyRewrap(ctx, plan, item, next, now); err != nil {
			clear(next.Data)
			return completed, false, err
		}
		clear(next.Data)
		completed++
	}
	if _, found, err := store.NextKeyRewrap(ctx, plan); err != nil {
		return completed, false, err
	} else if !found {
		if err = store.CompleteKeyRewrap(ctx, plan, actor, now); err != nil {
			return completed, false, err
		}
		return completed, true, nil
	}
	return completed, false, nil
}

func RunKeyRewrapWith(ctx context.Context, store Store, rewrap func(context.Context, sensitive.WrappedKey) (sensitive.WrappedKey, error), plan Target, actor Actor, limit int, now time.Time) (int, bool, error) {
	if store == nil || rewrap == nil || plan.OrgID == "" || plan.KEKID == "" || plan.Version == 0 || len(plan.ManifestDigest) != 32 || limit < 1 || limit > 1000 {
		return 0, false, errors.New("invalid key rewrap plan")
	}
	if err := store.BeginKeyRewrap(ctx, plan, now); err != nil {
		return 0, false, err
	}
	completed := 0
	for completed < limit {
		item, found, err := store.NextKeyRewrap(ctx, plan)
		if err != nil {
			return completed, false, err
		}
		if !found {
			if err = store.CompleteKeyRewrap(ctx, plan, actor, now); err != nil {
				return completed, false, err
			}
			return completed, true, nil
		}
		next, err := rewrap(ctx, item.Key)
		if err != nil {
			return completed, false, err
		}
		if next.KEKID != plan.KEKID || next.Version != plan.Version {
			clear(next.Data)
			return completed, false, errors.New("key service returned unapproved target")
		}
		if err = store.CommitKeyRewrap(ctx, plan, item, next, now); err != nil {
			clear(next.Data)
			return completed, false, err
		}
		clear(next.Data)
		completed++
	}
	if _, found, err := store.NextKeyRewrap(ctx, plan); err != nil {
		return completed, false, err
	} else if !found {
		if err = store.CompleteKeyRewrap(ctx, plan, actor, now); err != nil {
			return completed, false, err
		}
		return completed, true, nil
	}
	return completed, false, nil
}
