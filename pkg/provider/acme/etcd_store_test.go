package acme

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/types"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"
)

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()

	return l.Addr().(*net.TCPAddr).Port, nil
}

// startEmbeddedEtcd starts a single-node embedded etcd server bound to the
// given ports and waits until it is ready. The returned stop function shuts
// the server down and releases the ports.
func startEmbeddedEtcd(dir string, clientPort, peerPort int) (string, func(), error) {
	clientHost := fmt.Sprintf("127.0.0.1:%d", clientPort)
	peerHost := fmt.Sprintf("127.0.0.1:%d", peerPort)
	peerURL := "http://" + peerHost

	cfg := embed.NewConfig()
	cfg.Dir = dir
	cfg.Logger = "zap"
	cfg.LogOutputs = []string{os.DevNull}
	cfg.LogLevel = "error"
	cfg.Name = "default"
	cfg.ListenClientUrls = []url.URL{{Scheme: "http", Host: clientHost}}
	cfg.ListenPeerUrls = []url.URL{{Scheme: "http", Host: peerHost}}
	cfg.AdvertiseClientUrls = []url.URL{{Scheme: "http", Host: clientHost}}
	cfg.AdvertisePeerUrls = []url.URL{{Scheme: "http", Host: peerHost}}
	cfg.InitialCluster = "default=" + peerURL
	cfg.ClusterState = embed.ClusterStateFlagNew

	e, err := embed.StartEtcd(cfg)
	if err != nil {
		return "", nil, err
	}

	select {
	case <-e.Server.ReadyNotify():
	case <-time.After(15 * time.Second):
		e.Close()
		return "", nil, errors.New("etcd server did not become ready in time")
	}

	var closeOnce sync.Once
	return e.Clients[0].Addr().String(), func() { closeOnce.Do(func() { e.Close() }) }, nil
}

var sharedEtcd struct {
	once sync.Once
	addr string
	err  error
}

// sharedTestEtcdAddr returns the client address of a shared embedded etcd
// server, started on first use and kept alive until the test process exits.
func sharedTestEtcdAddr(t *testing.T) string {
	t.Helper()

	sharedEtcd.once.Do(func() {
		dir, err := os.MkdirTemp("", "traefik-acme-etcd-")
		if err != nil {
			sharedEtcd.err = err
			return
		}

		clientPort, err := freePort()
		if err != nil {
			sharedEtcd.err = err
			return
		}

		peerPort, err := freePort()
		if err != nil {
			sharedEtcd.err = err
			return
		}

		sharedEtcd.addr, _, sharedEtcd.err = startEmbeddedEtcd(dir, clientPort, peerPort)
	})
	require.NoError(t, sharedEtcd.err)

	return sharedEtcd.addr
}

var resolverSeq atomic.Uint64

// newTestEtcdStore creates an EtcdStore connected to the shared test etcd
// server, and closes it when the test ends.
func newTestEtcdStore(t *testing.T) *EtcdStore {
	t.Helper()

	store, err := NewEtcdStore("etcd://" + sharedTestEtcdAddr(t))
	require.NoError(t, err)

	t.Cleanup(func() { require.NoError(t, store.Close()) })

	return store
}

// testResolverName returns a resolver name unique across the test package, so
// tests sharing the embedded etcd server do not collide.
func testResolverName() string {
	return fmt.Sprintf("resolver-%d", resolverSeq.Add(1))
}

func TestEtcdClientConfig(t *testing.T) {
	testCases := []struct {
		desc      string
		etcdURL   string
		cfg       func(t *testing.T, cfg *clientv3.Config)
		keyPrefix string
		err       string
	}{
		{
			desc:      "plain etcd",
			etcdURL:   "etcd://localhost:2379",
			keyPrefix: "traefik/acme",
			cfg: func(t *testing.T, cfg *clientv3.Config) {
				t.Helper()
				assert.Equal(t, []string{"localhost:2379"}, cfg.Endpoints)
				assert.Nil(t, cfg.TLS)
			},
		},
		{
			desc:      "multiple endpoints",
			etcdURL:   "etcd://localhost:2379,localhost:2380",
			keyPrefix: "traefik/acme",
			cfg: func(t *testing.T, cfg *clientv3.Config) {
				t.Helper()
				assert.Equal(t, []string{"localhost:2379", "localhost:2380"}, cfg.Endpoints)
			},
		},
		{
			desc:      "etcd with credentials and key prefix",
			etcdURL:   "etcd://user:secret@localhost:2379/custom/prefix",
			keyPrefix: "custom/prefix",
			cfg: func(t *testing.T, cfg *clientv3.Config) {
				t.Helper()
				assert.Equal(t, "user", cfg.Username)
				assert.Equal(t, "secret", cfg.Password)
			},
		},
		{
			desc:      "etcd over TLS",
			etcdURL:   "etcds://localhost:2379",
			keyPrefix: "traefik/acme",
			cfg: func(t *testing.T, cfg *clientv3.Config) {
				t.Helper()
				require.NotNil(t, cfg.TLS)
			},
		},
		{
			desc:      "https alias",
			etcdURL:   "https://localhost:2379",
			keyPrefix: "traefik/acme",
			cfg: func(t *testing.T, cfg *clientv3.Config) {
				t.Helper()
				require.NotNil(t, cfg.TLS)
			},
		},
		{
			desc:      "http alias",
			etcdURL:   "http://localhost:2379",
			keyPrefix: "traefik/acme",
			cfg: func(t *testing.T, cfg *clientv3.Config) {
				t.Helper()
				assert.Nil(t, cfg.TLS)
			},
		},
		{
			desc:    "unsupported scheme",
			etcdURL: "etcd-cluster://localhost:2379",
			err:     `unsupported etcd URL scheme "etcd-cluster"`,
		},
		{
			desc:    "missing endpoints",
			etcdURL: "etcd://",
			err:     "missing etcd endpoints",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			cfg, keyPrefix, err := etcdClientConfig(test.etcdURL)
			if test.err != "" {
				require.ErrorContains(t, err, test.err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.keyPrefix, keyPrefix)
			test.cfg(t, cfg)
		})
	}
}

func TestNewEtcdStore_ConnectionError(t *testing.T) {
	_, err := NewEtcdStore("etcd://localhost:1")
	require.Error(t, err)
	assert.ErrorContains(t, err, "unable to connect to etcd")
}

func TestEtcdStore_GetAccount(t *testing.T) {
	store := newTestEtcdStore(t)

	// Unknown resolver: an empty account is returned without error.
	account, err := store.GetAccount(testResolverName())
	require.NoError(t, err)
	assert.Nil(t, account)
}

func TestEtcdStore_SaveGetAccount(t *testing.T) {
	store := newTestEtcdStore(t)

	expected := &Account{
		Email:        "foo@bar.com",
		Registration: &Resource{URI: "https://acme-v02.api.letsencrypt.org/acme/acct/123", Body: acme.Account{Status: "valid"}},
		PrivateKey:   []byte("private-key"),
	}

	resolverName := testResolverName()

	err := store.SaveAccount(resolverName, expected)
	require.NoError(t, err)

	account, err := store.GetAccount(resolverName)
	require.NoError(t, err)
	assert.Equal(t, expected, account)

	// The stored data must be shared with the JSON serialization used by the
	// LocalStore.
	raw, err := rawEtcdValue(t, store.key(resolverName))
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"Account": {
			"Email": "foo@bar.com",
			"Registration": {"body": {"status": "valid"}, "uri": "https://acme-v02.api.letsencrypt.org/acme/acct/123"},
			"PrivateKey": "cHJpdmF0ZS1rZXk="
		},
		"Certificates": null
	}`, string(raw))
}

func TestEtcdStore_SaveGetCertificates(t *testing.T) {
	store := newTestEtcdStore(t)

	expected := []*CertAndStore{
		{
			Certificate: Certificate{
				Domain:      types.Domain{Main: "example.com", SANs: []string{"www.example.com"}},
				Certificate: []byte("cert-pem"),
				Key:         []byte("key-pem"),
			},
			Store: "default",
		},
		{
			Certificate: Certificate{
				Domain:      types.Domain{Main: "example.org"},
				Certificate: []byte("cert-pem-2"),
				Key:         []byte("key-pem-2"),
			},
			Store: "web",
		},
	}

	resolverName := testResolverName()

	err := store.SaveCertificates(resolverName, expected)
	require.NoError(t, err)

	certificates, err := store.GetCertificates(resolverName)
	require.NoError(t, err)
	assert.Equal(t, expected, certificates)
}

func TestEtcdStore_MergeKeepsAccountAndCertificates(t *testing.T) {
	store := newTestEtcdStore(t)

	account := &Account{Email: "foo@bar.com", PrivateKey: []byte("private-key")}
	certificates := []*CertAndStore{
		{
			Certificate: Certificate{
				Domain:      types.Domain{Main: "example.com"},
				Certificate: []byte("cert-pem"),
				Key:         []byte("key-pem"),
			},
			Store: "default",
		},
	}

	resolverName := testResolverName()

	// Save the account first, then the certificates: the account must survive.
	err := store.SaveAccount(resolverName, account)
	require.NoError(t, err)

	err = store.SaveCertificates(resolverName, certificates)
	require.NoError(t, err)

	gotAccount, err := store.GetAccount(resolverName)
	require.NoError(t, err)
	assert.Equal(t, account, gotAccount)

	gotCertificates, err := store.GetCertificates(resolverName)
	require.NoError(t, err)
	assert.Equal(t, certificates, gotCertificates)

	// Save the certificates first, then the account: the certificates must survive.
	err = store.SaveCertificates(resolverName, certificates)
	require.NoError(t, err)

	err = store.SaveAccount(resolverName, account)
	require.NoError(t, err)

	gotCertificates, err = store.GetCertificates(resolverName)
	require.NoError(t, err)
	assert.Equal(t, certificates, gotCertificates)

	gotAccount, err = store.GetAccount(resolverName)
	require.NoError(t, err)
	assert.Equal(t, account, gotAccount)
}

func TestEtcdStore_ConcurrentSaves(t *testing.T) {
	store := newTestEtcdStore(t)

	account := &Account{Email: "foo@bar.com", PrivateKey: []byte("private-key")}
	certificates := []*CertAndStore{
		{
			Certificate: Certificate{
				Domain:      types.Domain{Main: "example.com"},
				Certificate: []byte("cert-pem"),
				Key:         []byte("key-pem"),
			},
			Store: "default",
		},
	}

	resolverName := testResolverName()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for range 50 {
			err := store.SaveAccount(resolverName, account)
			assert.NoError(t, err)
		}
	}()

	go func() {
		defer wg.Done()
		for range 50 {
			err := store.SaveCertificates(resolverName, certificates)
			assert.NoError(t, err)
		}
	}()

	wg.Wait()

	gotAccount, err := store.GetAccount(resolverName)
	require.NoError(t, err)
	assert.Equal(t, account, gotAccount)

	gotCertificates, err := store.GetCertificates(resolverName)
	require.NoError(t, err)
	assert.Equal(t, certificates, gotCertificates)
}

func TestEtcdStore_ResolversAreIsolated(t *testing.T) {
	store := newTestEtcdStore(t)

	err := store.SaveAccount("resolver-a", &Account{Email: "a@example.com"})
	require.NoError(t, err)

	err = store.SaveAccount("resolver-b", &Account{Email: "b@example.com"})
	require.NoError(t, err)

	accountA, err := store.GetAccount("resolver-a")
	require.NoError(t, err)
	assert.Equal(t, "a@example.com", accountA.Email)

	accountB, err := store.GetAccount("resolver-b")
	require.NoError(t, err)
	assert.Equal(t, "b@example.com", accountB.Email)
}

func TestEtcdStore_CorruptedData(t *testing.T) {
	store := newTestEtcdStore(t)

	resolverName := testResolverName()

	err := putRawEtcdValue(t, store.key(resolverName), []byte("not-json"))
	require.NoError(t, err)

	_, err = store.GetAccount(resolverName)
	require.Error(t, err)
	assert.ErrorContains(t, err, "unable to unmarshal ACME stored data from etcd")
}

func TestEtcdStore_UnionMergeCertificates(t *testing.T) {
	storeA := newTestEtcdStore(t)
	storeB := newTestEtcdStore(t)

	resolverName := testResolverName()

	// Two Traefik instances sharing the same storage, each with a stale
	// in-memory view of the certificates.
	err := storeA.SaveCertificates(resolverName, []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.com"}, Certificate: []byte("cert-pem-a"), Key: []byte("key-pem-a")},
			Store:       "default",
		},
	})
	require.NoError(t, err)

	// Instance B renews a different certificate: the union merge must keep
	// instance A's renewal in the shared store.
	err = storeB.SaveCertificates(resolverName, []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.org"}, Certificate: []byte("cert-pem-b"), Key: []byte("key-pem-b")},
			Store:       "default",
		},
	})
	require.NoError(t, err)

	certificates, err := storeA.GetCertificates(resolverName)
	require.NoError(t, err)
	require.Len(t, certificates, 2)

	domains := make([]string, 0, len(certificates))
	for _, cert := range certificates {
		domains = append(domains, cert.Certificate.Domain.Main)
	}
	assert.ElementsMatch(t, []string{"example.com", "example.org"}, domains)
}

func TestEtcdStore_UnionMergeReplacesSameCertificate(t *testing.T) {
	storeA := newTestEtcdStore(t)
	storeB := newTestEtcdStore(t)

	resolverName := testResolverName()

	err := storeA.SaveCertificates(resolverName, []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.com"}, Certificate: []byte("cert-v1"), Key: []byte("key-v1")},
			Store:       "default",
		},
	})
	require.NoError(t, err)

	// Renewal of the same certificate (same domain and store) replaces it.
	err = storeB.SaveCertificates(resolverName, []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.com"}, Certificate: []byte("cert-v2"), Key: []byte("key-v2")},
			Store:       "default",
		},
	})
	require.NoError(t, err)

	certificates, err := storeA.GetCertificates(resolverName)
	require.NoError(t, err)
	require.Len(t, certificates, 1)

	assert.Equal(t, []byte("cert-v2"), certificates[0].Certificate.Certificate)
	assert.Equal(t, []byte("key-v2"), certificates[0].Key)
}

func TestEtcdStore_UnionMergeSameDomainDifferentStores(t *testing.T) {
	store := newTestEtcdStore(t)

	resolverName := testResolverName()

	// Same domain served by two TLS stores must result in two certificates.
	err := store.SaveCertificates(resolverName, []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.com"}, Certificate: []byte("cert-default"), Key: []byte("key-default")},
			Store:       "default",
		},
	})
	require.NoError(t, err)

	err = store.SaveCertificates(resolverName, []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.com"}, Certificate: []byte("cert-web"), Key: []byte("key-web")},
			Store:       "web",
		},
	})
	require.NoError(t, err)

	certificates, err := store.GetCertificates(resolverName)
	require.NoError(t, err)
	require.Len(t, certificates, 2)
}

func TestEtcdStore_UnionMergeEmptySaveIsNoOp(t *testing.T) {
	store := newTestEtcdStore(t)

	resolverName := testResolverName()

	err := store.SaveCertificates(resolverName, []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.com"}, Certificate: []byte("cert-pem"), Key: []byte("key-pem")},
			Store:       "default",
		},
	})
	require.NoError(t, err)

	// Saving an empty list must neither clear the store nor corrupt it.
	err = store.SaveCertificates(resolverName, []*CertAndStore{})
	require.NoError(t, err)

	certificates, err := store.GetCertificates(resolverName)
	require.NoError(t, err)
	require.Len(t, certificates, 1)
	assert.Equal(t, "example.com", certificates[0].Certificate.Domain.Main)
}

func TestEtcdStore_UnionMergeKeepsAccount(t *testing.T) {
	storeA := newTestEtcdStore(t)
	storeB := newTestEtcdStore(t)

	resolverName := testResolverName()

	account := &Account{Email: "foo@bar.com", PrivateKey: []byte("private-key")}

	err := storeA.SaveAccount(resolverName, account)
	require.NoError(t, err)

	// Instance B renews a certificate: the account must survive the merge.
	err = storeB.SaveCertificates(resolverName, []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.com"}, Certificate: []byte("cert-pem"), Key: []byte("key-pem")},
			Store:       "default",
		},
	})
	require.NoError(t, err)

	gotAccount, err := storeB.GetAccount(resolverName)
	require.NoError(t, err)
	assert.Equal(t, account, gotAccount)
}

func TestEtcdStore_Lock(t *testing.T) {
	store := newTestEtcdStore(t)

	ctx := context.Background()

	acquired, err := store.Lock(ctx, "example.com", "token-1", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired)

	// A second acquisition with another token must fail.
	acquired, err = store.Lock(ctx, "example.com", "token-2", time.Minute)
	require.NoError(t, err)
	assert.False(t, acquired)

	// Unlocking with a wrong token must not release the lock.
	err = store.Unlock(ctx, "example.com", "wrong-token")
	require.NoError(t, err)

	acquired, err = store.Lock(ctx, "example.com", "token-3", time.Minute)
	require.NoError(t, err)
	assert.False(t, acquired)

	// Unlocking with the right token releases the lock.
	err = store.Unlock(ctx, "example.com", "token-1")
	require.NoError(t, err)

	acquired, err = store.Lock(ctx, "example.com", "token-4", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired)
}

func TestEtcdStore_LockExpiry(t *testing.T) {
	store := newTestEtcdStore(t)

	acquired, err := store.Lock(context.Background(), "expiry.example.com", "token-1", time.Second)
	require.NoError(t, err)
	assert.True(t, acquired)

	// After the lease elapses, the lock is released (e.g. an instance that
	// crashed mid-renewal).
	time.Sleep(3 * time.Second)

	acquired, err = store.Lock(context.Background(), "expiry.example.com", "token-2", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired)
}

func TestEtcdStore_LockPerDomain(t *testing.T) {
	store := newTestEtcdStore(t)

	ctx := context.Background()

	acquired, err := store.Lock(ctx, "perdomain-a.example.com", "token-1", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired)

	// A different domain must not be blocked.
	acquired, err = store.Lock(ctx, "perdomain-b.example.com", "token-2", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired)
}

func TestEtcdStore_CustomKeyPrefix(t *testing.T) {
	store, err := NewEtcdStore("etcd://" + sharedTestEtcdAddr(t) + "/custom/prefix")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })

	resolverName := testResolverName()

	err = store.SaveAccount(resolverName, &Account{Email: "a@example.com"})
	require.NoError(t, err)

	// The default prefix must not be used.
	_, err = rawEtcdValue(t, "traefik/acme/"+resolverName)
	require.Error(t, err)

	// The account is stored under the custom prefix.
	raw, err := rawEtcdValue(t, store.key(resolverName))
	require.NoError(t, err)
	assert.Contains(t, string(raw), "a@example.com")
}

// rawEtcdValue reads the raw value of an etcd key through a fresh client
// connected to the shared test etcd server.
func rawEtcdValue(t *testing.T, key string) ([]byte, error) {
	t.Helper()

	return rawEtcdValueAt(t, sharedTestEtcdAddr(t), key)
}

// rawEtcdValueAt reads the raw value of an etcd key through a fresh client
// connected to the given endpoint.
func rawEtcdValueAt(t *testing.T, endpoint, key string) ([]byte, error) {
	t.Helper()

	client, err := clientv3.New(clientv3.Config{Endpoints: []string{endpoint}})
	require.NoError(t, err)
	defer client.Close()

	resp, err := client.Get(context.Background(), key)
	if err != nil {
		return nil, err
	}

	if len(resp.Kvs) == 0 {
		return nil, errors.New("key not found")
	}

	return resp.Kvs[0].Value, nil
}

// putRawEtcdValue writes the raw value of an etcd key through a fresh client.
func putRawEtcdValue(t *testing.T, key string, value []byte) error {
	t.Helper()

	client, err := clientv3.New(clientv3.Config{Endpoints: []string{sharedTestEtcdAddr(t)}})
	require.NoError(t, err)
	defer client.Close()

	_, err = client.Put(context.Background(), key, string(value))
	return err
}
