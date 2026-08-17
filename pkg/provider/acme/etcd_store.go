package acme

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"
)

var (
	_ Store         = (*EtcdStore)(nil)
	_ LockableStore = (*EtcdStore)(nil)
)

const (
	// defaultEtcdKeyPrefix is the key prefix under which the ACME stored data
	// is kept. Each ACME resolver maps to the key "<prefix>/<resolverName>".
	defaultEtcdKeyPrefix = "traefik/acme"

	// etcdClientTimeout is the timeout used for the connectivity check
	// performed when the store is created.
	etcdClientTimeout = 5 * time.Second

	// etcdOpTimeout bounds each store operation. etcd operations without a
	// deadline can block for a long time on an unreachable cluster (the gRPC
	// client keeps retrying the connection with an exponential backoff), so
	// every operation runs under its own timeout.
	etcdOpTimeout = 5 * time.Second

	// maxSaveAttempts bounds the optimistic-concurrency retry loop of
	// saveField: under sustained contention the save fails loudly instead of
	// looping forever.
	maxSaveAttempts = 100
)

// EtcdStore is a distributed Store implementation backed by etcd.
type EtcdStore struct {
	client    *clientv3.Client
	keyPrefix string
}

// NewEtcdStore initializes a new EtcdStore from an etcd URL and fails when the
// cluster is unreachable.
//
// Supported URL schemes:
//
//	etcd://[user:password@]host1:port1[,host2:port2][/key-prefix]   plain etcd
//	etcds://[user:password@]host1:port1[,host2:port2][/key-prefix]  etcd over TLS
//
// The http:// and https:// schemes are accepted as aliases of etcd:// and
// etcds://. The URL path, when present, overrides the default key prefix.
func NewEtcdStore(etcdURL string) (*EtcdStore, error) {
	return newEtcdStore(etcdURL, true)
}

// newEtcdStore initializes a new EtcdStore from an etcd URL. When
// checkConnection is false, an unreachable cluster does not prevent the store
// creation: operations then fail and are handled by the caller (used by the
// failover store, so Traefik can start while the primary store is down).
func newEtcdStore(etcdURL string, checkConnection bool) (*EtcdStore, error) {
	client, keyPrefix, err := newEtcdClient(etcdURL)
	if err != nil {
		return nil, err
	}

	if checkConnection {
		ctx, cancel := context.WithTimeout(context.Background(), etcdClientTimeout)
		defer cancel()

		// clientv3.New does not dial: make sure the cluster is reachable
		// before accepting the store.
		if _, err := client.Status(ctx, client.Endpoints()[0]); err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("unable to connect to etcd: %w", err)
		}
	}

	return &EtcdStore{client: client, keyPrefix: keyPrefix}, nil
}

// Close closes the underlying etcd client connections.
func (s *EtcdStore) Close() error {
	return s.client.Close()
}

// GetAccount returns ACME Account.
func (s *EtcdStore) GetAccount(resolverName string) (*Account, error) {
	storedData, err := s.get(resolverName)
	if err != nil {
		return nil, err
	}

	return storedData.Account, nil
}

// SaveAccount stores ACME Account.
func (s *EtcdStore) SaveAccount(resolverName string, account *Account) error {
	return s.saveField(resolverName, "Account", account)
}

// GetCertificates returns ACME Certificates list.
func (s *EtcdStore) GetCertificates(resolverName string) ([]*CertAndStore, error) {
	storedData, err := s.get(resolverName)
	if err != nil {
		return nil, err
	}

	return storedData.Certificates, nil
}

// SaveCertificates stores ACME Certificates list.
func (s *EtcdStore) SaveCertificates(resolverName string, certificates []*CertAndStore) error {
	// Saving an empty certificate list is a no-op: it cannot clear the store,
	// and the ACME provider never saves an empty list anyway.
	if len(certificates) == 0 {
		return nil
	}

	return s.saveField(resolverName, "Certificates", certificates)
}

func (s *EtcdStore) get(resolverName string) (*StoredData, error) {
	ctx, cancel := context.WithTimeout(context.Background(), etcdOpTimeout)
	defer cancel()

	resp, err := s.client.Get(ctx, s.key(resolverName))
	if err != nil {
		return nil, fmt.Errorf("unable to read ACME stored data from etcd: %w", err)
	}

	if len(resp.Kvs) == 0 {
		return &StoredData{}, nil
	}

	storedData := &StoredData{}
	if err := json.Unmarshal(resp.Kvs[0].Value, storedData); err != nil {
		return nil, fmt.Errorf("unable to unmarshal ACME stored data from etcd: %w", err)
	}

	return storedData, nil
}

// saveField atomically updates one field of the resolver stored data in etcd.
//
// etcd has no compare-and-swap on arbitrary script logic, so the update is an
// optimistic-concurrency loop: read the key with its modification revision,
// compute the merged value, and write it back guarded by a transaction that
// only succeeds when the key was not modified in the meantime. Concurrent
// saves from several Traefik instances therefore never lose data: like the
// Redis store, Account saves replace the Account field and Certificates saves
// merge the incoming certificates into the stored ones.
func (s *EtcdStore) saveField(resolverName, field string, value any) error {
	key := s.key(resolverName)

	for attempt := 0; ; attempt++ {
		if attempt >= maxSaveAttempts {
			return fmt.Errorf("unable to write ACME %s to etcd: key %q modified concurrently too many times", field, key)
		}

		ctx, cancel := context.WithTimeout(context.Background(), etcdOpTimeout)

		resp, err := s.client.Get(ctx, key)
		if err != nil {
			cancel()
			return fmt.Errorf("unable to read ACME stored data from etcd: %w", err)
		}

		storedData := &StoredData{}
		var modRevision int64
		if len(resp.Kvs) > 0 {
			if err := json.Unmarshal(resp.Kvs[0].Value, storedData); err != nil {
				cancel()
				return fmt.Errorf("unable to unmarshal ACME stored data from etcd: %w", err)
			}
			modRevision = resp.Kvs[0].ModRevision
		}

		if err := mergeStoredData(storedData, field, value); err != nil {
			cancel()
			return err
		}

		newData, err := json.Marshal(storedData)
		if err != nil {
			cancel()
			return fmt.Errorf("unable to marshal ACME stored data: %w", err)
		}

		tresp, err := s.client.Txn(ctx).
			If(clientv3.Compare(clientv3.ModRevision(key), "=", modRevision)).
			Then(clientv3.OpPut(key, string(newData))).
			Else().
			Commit()
		cancel()
		if err != nil {
			return fmt.Errorf("unable to write ACME %s to etcd: %w", field, err)
		}
		if tresp.Succeeded {
			return nil
		}
	}
}

// mergeStoredData applies the incoming value to the stored data, mirroring the
// Redis store merge script: the Account field is replaced, the Certificates
// field is merged as a union keyed by (Store, domain).
func mergeStoredData(storedData *StoredData, field string, value any) error {
	switch field {
	case "Account":
		account, ok := value.(*Account)
		if !ok {
			return fmt.Errorf("invalid account value of type %T", value)
		}

		storedData.Account = account

	case "Certificates":
		certificates, ok := value.([]*CertAndStore)
		if !ok {
			return fmt.Errorf("invalid certificates value of type %T", value)
		}

		storedData.Certificates = mergeCertificates(storedData.Certificates, certificates)

	default:
		return fmt.Errorf("unknown stored data field %q", field)
	}

	return nil
}

func (s *EtcdStore) key(resolverName string) string {
	return s.keyPrefix + "/" + resolverName
}

// Lock acquires the lock named name if it is not already held.
// It returns true when the lock has been acquired, false when it is already
// held with another token. The lock is automatically released after ttl via
// its etcd lease, or sooner when Unlock is called with the same token.
func (s *EtcdStore) Lock(ctx context.Context, name, token string, ttl time.Duration) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, etcdOpTimeout)
	defer cancel()

	lease, err := s.client.Grant(ctx, int64(ttl.Seconds()))
	if err != nil {
		return false, fmt.Errorf("unable to grant etcd lease for lock %q: %w", name, err)
	}

	key := s.lockKey(name)
	tresp, err := s.client.Txn(ctx).
		If(clientv3.Compare(clientv3.CreateRevision(key), "=", 0)).
		Then(clientv3.OpPut(key, token, clientv3.WithLease(lease.ID))).
		Else().
		Commit()
	if err != nil {
		_, _ = s.client.Revoke(ctx, lease.ID)
		return false, fmt.Errorf("unable to acquire etcd lock %q: %w", name, err)
	}

	if !tresp.Succeeded {
		// The lock is held by another instance: drop the unused lease.
		_, _ = s.client.Revoke(ctx, lease.ID)
		return false, nil
	}

	return true, nil
}

// Unlock releases the lock named name if it is still held with the given token.
// The lease attached to the lock key is left to expire by itself: revoking it
// would require tracking it across calls.
func (s *EtcdStore) Unlock(ctx context.Context, name, token string) error {
	ctx, cancel := context.WithTimeout(ctx, etcdOpTimeout)
	defer cancel()

	key := s.lockKey(name)
	if _, err := s.client.Txn(ctx).
		If(clientv3.Compare(clientv3.Value(key), "=", token)).
		Then(clientv3.OpDelete(key)).
		Else().
		Commit(); err != nil {
		return fmt.Errorf("unable to release etcd lock %q: %w", name, err)
	}

	return nil
}

func (s *EtcdStore) lockKey(name string) string {
	return s.keyPrefix + "/lock/" + name
}

func newEtcdClient(etcdURL string) (*clientv3.Client, string, error) {
	cfg, keyPrefix, err := etcdClientConfig(etcdURL)
	if err != nil {
		return nil, "", err
	}

	client, err := clientv3.New(*cfg)
	if err != nil {
		return nil, "", fmt.Errorf("unable to create etcd client: %w", err)
	}

	return client, keyPrefix, nil
}

// etcdClientConfig builds the client configuration and the key prefix from an
// etcd URL.
func etcdClientConfig(etcdURL string) (*clientv3.Config, string, error) {
	u, err := url.Parse(etcdURL)
	if err != nil {
		return nil, "", fmt.Errorf("unable to parse etcd URL: %w", err)
	}

	var secure bool
	switch u.Scheme {
	case "etcd", "http":
		secure = false
	case "etcds", "https":
		secure = true
	default:
		return nil, "", fmt.Errorf("unsupported etcd URL scheme %q", u.Scheme)
	}

	var endpoints []string
	for _, addr := range strings.Split(u.Host, ",") {
		if addr = strings.TrimSpace(addr); addr != "" {
			endpoints = append(endpoints, addr)
		}
	}
	if len(endpoints) == 0 {
		return nil, "", errors.New("missing etcd endpoints")
	}

	cfg := &clientv3.Config{
		Endpoints:   endpoints,
		DialTimeout: etcdClientTimeout,
		// The client's zap logger writes to stderr and bypasses Traefik's
		// logging: the store reports its own errors, so keep it quiet.
		Logger: zap.NewNop(),
	}

	// Credentials come from the URL userinfo.
	if u.User != nil {
		cfg.Username = u.User.Username()
		cfg.Password, _ = u.User.Password()
	}

	if secure {
		cfg.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	keyPrefix := strings.Trim(u.Path, "/")
	if keyPrefix == "" {
		keyPrefix = defaultEtcdKeyPrefix
	}

	return cfg, keyPrefix, nil
}
