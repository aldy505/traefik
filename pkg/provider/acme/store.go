package acme

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/traefik/traefik/v3/pkg/safe"
)

// StoredData represents the data managed by Store.
type StoredData struct {
	Account      *Account
	Certificates []*CertAndStore
}

// Store is a generic interface that represents a storage.
type Store interface {
	GetAccount(resolverName string) (*Account, error)
	SaveAccount(resolverName string, account *Account) error
	GetCertificates(resolverName string) ([]*CertAndStore, error)
	SaveCertificates(resolverName string, certificates []*CertAndStore) error
}

// LockableStore is an optional capability of a Store, used to coordinate
// certificate renewals across several Traefik instances sharing the same
// storage. Stores that do not implement it are used without coordination.
type LockableStore interface {
	// Lock acquires the lock named name if it is not already held.
	// It returns true when the lock has been acquired, false when it is
	// already held with another token. The lock is automatically released
	// after ttl, or sooner when Unlock is called with the same token.
	Lock(ctx context.Context, name, token string, ttl time.Duration) (bool, error)

	// Unlock releases the lock named name if it is still held with the given token.
	Unlock(ctx context.Context, name, token string) error
}

// NewStore creates a Store from the configured storage value.
//
// A storage value with a Redis URL scheme (redis://, rediss:// or
// redis+sentinel://) yields a distributed RedisStore, while any other value is
// treated as a local file path and yields a LocalStore.
func NewStore(storage string, routinesPool *safe.Pool) (Store, error) {
	scheme, err := storageScheme(storage)
	if err != nil {
		return nil, err
	}

	switch scheme {
	case "redis", "rediss", "redis+sentinel":
		return NewRedisStore(storage)

	case "":
		return NewLocalStore(storage, routinesPool), nil

	default:
		if strings.HasPrefix(scheme, "redis") {
			return nil, fmt.Errorf("unsupported Redis URL scheme %q for storage %q", scheme, storage)
		}

		return NewLocalStore(storage, routinesPool), nil
	}
}

func storageScheme(storage string) (string, error) {
	u, err := url.Parse(storage)
	if err != nil {
		return "", fmt.Errorf("unable to parse storage %q: %w", storage, err)
	}

	return u.Scheme, nil
}
