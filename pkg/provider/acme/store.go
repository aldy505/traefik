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
// redis+sentinel://) yields a distributed RedisStore, and a storage value with
// an etcd URL scheme (etcd://, etcds://, or the http:// and https:// aliases)
// yields a distributed EtcdStore, while any other value is treated as a local
// file path and yields a LocalStore.
//
// A "file" query parameter on a Redis or etcd URL (e.g.
// redis://localhost:6379?file=/var/traefik/acme.json) enables the local
// fallback: the store then writes to both the distributed store and the local
// file, reads fall back to the file when the distributed store is unreachable,
// and Traefik can start even when the distributed store is down.
func NewStore(storage string, routinesPool *safe.Pool) (Store, error) {
	scheme, err := storageScheme(storage)
	if err != nil {
		return nil, err
	}

	switch scheme {
	case "redis", "rediss", "redis+sentinel", "etcd", "etcds", "http", "https":
		return newDistributedStore(scheme, storage, routinesPool)

	case "":
		return NewLocalStore(storage, routinesPool), nil

	default:
		if strings.HasPrefix(scheme, "redis") {
			return nil, fmt.Errorf("unsupported Redis URL scheme %q for storage %q", scheme, storage)
		}

		if strings.HasPrefix(scheme, "etcd") {
			return nil, fmt.Errorf("unsupported etcd URL scheme %q for storage %q", scheme, storage)
		}

		return NewLocalStore(storage, routinesPool), nil
	}
}

// newDistributedStore creates the Redis or etcd store for the given scheme,
// wrapped in a FailoverStore when the storage URL carries a "file" query
// parameter. When the fallback is configured, the primary store is created
// without a connectivity check, so Traefik can start while it is down.
func newDistributedStore(scheme, storage string, routinesPool *safe.Pool) (Store, error) {
	primaryURL, filePath, err := splitFallbackFile(storage)
	if err != nil {
		return nil, err
	}

	var primary Store
	switch scheme {
	case "redis", "rediss", "redis+sentinel":
		primary, err = newRedisStore(primaryURL, filePath == "")

	case "etcd", "etcds", "http", "https":
		primary, err = newEtcdStore(primaryURL, filePath == "")

	default:
		return nil, fmt.Errorf("unsupported URL scheme %q for storage %q", scheme, storage)
	}
	if err != nil {
		return nil, err
	}

	if filePath == "" {
		return primary, nil
	}

	return NewFailoverStore(primary, NewLocalStore(filePath, routinesPool)), nil
}

// splitFallbackFile extracts the "file" query parameter from a store URL and
// removes it, so it is not passed to the Redis or etcd client parsers (which
// reject unknown query parameters).
func splitFallbackFile(storage string) (string, string, error) {
	u, err := url.Parse(storage)
	if err != nil {
		return "", "", fmt.Errorf("unable to parse storage %q: %w", storage, err)
	}

	query := u.Query()
	filePath := query.Get("file")
	if filePath != "" {
		query.Del("file")
		u.RawQuery = query.Encode()
	}

	return u.String(), filePath, nil
}

func storageScheme(storage string) (string, error) {
	u, err := url.Parse(storage)
	if err != nil {
		return "", fmt.Errorf("unable to parse storage %q: %w", storage, err)
	}

	return u.Scheme, nil
}
