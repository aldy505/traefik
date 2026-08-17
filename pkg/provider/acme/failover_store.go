package acme

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

var (
	_ Store         = (*FailoverStore)(nil)
	_ LockableStore = (*FailoverStore)(nil)
)

// FailoverStore wraps a primary Store (Redis or etcd) with a local Store
// (usually a JSON file) that acts as a fallback.
//
// Every save is written to both stores, so the fallback always holds a recent
// copy of the data and can take over when the primary is unreachable. A save
// succeeds as soon as one of the two stores persisted it: the ACME provider
// must not fail a registration or a renewal just because the primary is down.
//
// Reads prefer the primary, and fall back to the local store when the primary
// is unreachable or lost data. The certificates of both stores are merged as a
// union keyed by (Store, domain), and the merged list is written back to the
// primary: a primary that recovers from an outage catches up on the renewals
// that only reached the local store.
//
// Locks are taken on the primary when it is reachable; when it is not, an
// in-process lock with the same TTL semantics is used instead, so renewals
// keep working while the primary is down (several instances cannot coordinate
// during an outage anyway).
type FailoverStore struct {
	primary  Store
	fallback Store

	localLocks sync.Map // map[string]*localLockEntry
}

// NewFailoverStore creates a FailoverStore around the given primary and
// fallback stores.
func NewFailoverStore(primary Store, fallback Store) *FailoverStore {
	return &FailoverStore{primary: primary, fallback: fallback}
}

// Close closes the primary and fallback stores when they support it.
func (s *FailoverStore) Close() error {
	var errs []error

	if closer, ok := s.primary.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if closer, ok := s.fallback.(interface{ Close() error }); ok {
		if err := closer.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// GetAccount returns the ACME account from the primary store, falling back to
// the local store when the primary is unreachable or has no data. When the
// local store holds the account, it is written back to the primary so the
// primary catches up on recovery.
func (s *FailoverStore) GetAccount(resolverName string) (*Account, error) {
	account, err := s.primary.GetAccount(resolverName)
	if err == nil && account != nil {
		return account, nil
	}

	fallbackAccount, fallbackErr := s.fallback.GetAccount(resolverName)
	if fallbackErr != nil {
		if err != nil {
			return nil, err
		}
		return nil, fallbackErr
	}

	if fallbackAccount != nil {
		s.refreshPrimaryAccount(resolverName, fallbackAccount)
		return fallbackAccount, nil
	}

	return nil, err
}

// GetCertificates returns the ACME certificates as the union of the primary
// and the local store, so renewals that only reached the local store during an
// outage are not lost. The merged list is written back to the primary when the
// primary is unreachable or behind, so it catches up on recovery.
func (s *FailoverStore) GetCertificates(resolverName string) ([]*CertAndStore, error) {
	primaryCertificates, primaryErr := s.primary.GetCertificates(resolverName)
	fallbackCertificates, fallbackErr := s.fallback.GetCertificates(resolverName)

	if primaryErr != nil && fallbackErr != nil {
		return nil, primaryErr
	}

	if fallbackErr != nil {
		log.Debug().Err(fallbackErr).Msg("Unable to read the local fallback store, using the primary store")
		return primaryCertificates, nil
	}

	// On key collisions the fallback value wins: it is the one written during
	// an outage (the primary was unreachable), so it must survive the merge,
	// and any difference with the primary then triggers the refresh below,
	// which pushes the outage renewals back to the primary on recovery. The
	// mirror-image case (a fallback write failed while the primary succeeded)
	// serves the slightly older certificate until the next dual-write, which
	// converges both stores again.
	merged := mergeCertificates(primaryCertificates, fallbackCertificates)

	if primaryErr != nil || !reflect.DeepEqual(primaryCertificates, merged) {
		s.refreshPrimaryCertificates(resolverName, merged)
	}

	return merged, nil
}

// SaveAccount stores the ACME account in both stores. It succeeds when at
// least one store persisted the account.
func (s *FailoverStore) SaveAccount(resolverName string, account *Account) error {
	primaryFailed := false
	if err := s.primary.SaveAccount(resolverName, account); err != nil {
		primaryFailed = true
		log.Info().Err(err).Msg("Primary store unavailable, saving the ACME account to the local fallback store")
	}

	if err := s.fallback.SaveAccount(resolverName, account); err != nil {
		if primaryFailed {
			return errors.Join(errors.New("unable to save the ACME account to the primary store"), err)
		}

		log.Info().Err(err).Msg("Unable to save the ACME account to the local fallback store")
	}

	return nil
}

// SaveCertificates stores the ACME certificates in both stores. The fallback
// receives the union of its current certificates and the incoming ones, so
// several instances sharing the primary do not clobber each other's renewals
// in the file. The save succeeds when at least one store persisted them.
func (s *FailoverStore) SaveCertificates(resolverName string, certificates []*CertAndStore) error {
	// An empty list cannot clear the stores: the ACME provider never saves an
	// empty list anyway, and the merge used by both stores relies on it.
	if len(certificates) == 0 {
		return nil
	}

	primaryFailed := false
	if err := s.primary.SaveCertificates(resolverName, certificates); err != nil {
		primaryFailed = true
		log.Info().Err(err).Msg("Primary store unavailable, saving the ACME certificates to the local fallback store")
	}

	fallbackCertificates, err := s.fallback.GetCertificates(resolverName)
	if err != nil {
		if primaryFailed {
			return errors.Join(errors.New("unable to save the ACME certificates to the primary store"), err)
		}

		log.Info().Err(err).Msg("Unable to read the local fallback store, the ACME certificates were not saved to it")
		return nil
	}

	if err := s.fallback.SaveCertificates(resolverName, mergeCertificates(fallbackCertificates, certificates)); err != nil {
		if primaryFailed {
			return errors.Join(errors.New("unable to save the ACME certificates to the primary store"), err)
		}

		log.Info().Err(err).Msg("Unable to save the ACME certificates to the local fallback store")
	}

	return nil
}

// Lock acquires the lock on the primary store, falling back to an in-process
// lock when the primary is unreachable, so renewals keep working during an
// outage. Several instances cannot coordinate while the primary is down, so
// the fallback lock only prevents duplicate renewals within this instance.
func (s *FailoverStore) Lock(ctx context.Context, name, token string, ttl time.Duration) (bool, error) {
	if lockable, ok := s.primary.(LockableStore); ok {
		acquired, err := lockable.Lock(ctx, name, token, ttl)
		if err == nil {
			return acquired, nil
		}

		log.Debug().Err(err).Msgf("Primary store unavailable, using the local renewal lock %q", name)
	}

	return s.localLock(name, token, ttl), nil
}

// Unlock releases the lock on the primary store and the local fallback lock.
// A primary failure does not fail the unlock: the local lock is released
// anyway, and the primary lock is self-expiring (its lease or TTL), so it is
// only logged.
func (s *FailoverStore) Unlock(ctx context.Context, name, token string) error {
	if lockable, ok := s.primary.(LockableStore); ok {
		if err := lockable.Unlock(ctx, name, token); err != nil {
			log.Debug().Err(err).Msgf("Primary store unavailable, the local renewal lock %q was released", name)
		}
	}

	s.releaseLocalLock(name, token)

	return nil
}

func (s *FailoverStore) refreshPrimaryAccount(resolverName string, account *Account) {
	if err := s.primary.SaveAccount(resolverName, account); err != nil {
		log.Debug().Err(err).Msg("Unable to refresh the primary store from the local fallback store")
	}
}

func (s *FailoverStore) refreshPrimaryCertificates(resolverName string, certificates []*CertAndStore) {
	if err := s.primary.SaveCertificates(resolverName, certificates); err != nil {
		log.Debug().Err(err).Msg("Unable to refresh the primary store from the local fallback store")
	}
}

type localLockEntry struct {
	token     string
	expiresAt time.Time
}

func (s *FailoverStore) localLock(name, token string, ttl time.Duration) bool {
	entry := &localLockEntry{token: token, expiresAt: time.Now().Add(ttl)}

	for {
		now := time.Now()

		loaded, ok := s.localLocks.LoadOrStore(name, entry)
		if !ok {
			return true
		}

		existing := loaded.(*localLockEntry)
		if existing.expiresAt.After(now) {
			return false
		}

		// The previous lock expired: try to take it over.
		if s.localLocks.CompareAndSwap(name, existing, entry) {
			return true
		}
	}
}

func (s *FailoverStore) releaseLocalLock(name, token string) {
	loaded, ok := s.localLocks.Load(name)
	if !ok {
		return
	}

	if entry := loaded.(*localLockEntry); entry.token == token {
		s.localLocks.CompareAndDelete(name, entry)
	}
}
