package acme

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-acme/lego/v5/acme"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/safe"
	"github.com/traefik/traefik/v3/pkg/types"
)

func TestNewRedisStore(t *testing.T) {
	testCases := []struct {
		desc     string
		redisURL string
		client   func(t *testing.T) redis.UniversalClient
		err      string
	}{
		{
			desc:     "plain redis",
			redisURL: "redis://localhost:6379",
			client: func(t *testing.T) redis.UniversalClient {
				t.Helper()

				client, err := newRedisClient("redis://localhost:6379")
				require.NoError(t, err)

				opts, ok := client.(*redis.Client)
				require.True(t, ok)
				assert.Equal(t, "localhost:6379", opts.Options().Addr)
				assert.Equal(t, 0, opts.Options().DB)
				assert.Nil(t, opts.Options().TLSConfig)
				return client
			},
		},
		{
			desc:     "redis with credentials and db",
			redisURL: "redis://user:secret@localhost:6380/3",
			client: func(t *testing.T) redis.UniversalClient {
				t.Helper()

				client, err := newRedisClient("redis://user:secret@localhost:6380/3")
				require.NoError(t, err)

				opts, ok := client.(*redis.Client)
				require.True(t, ok)
				assert.Equal(t, "localhost:6380", opts.Options().Addr)
				assert.Equal(t, "user", opts.Options().Username)
				assert.Equal(t, "secret", opts.Options().Password)
				assert.Equal(t, 3, opts.Options().DB)
				return client
			},
		},
		{
			desc:     "redis over TLS",
			redisURL: "rediss://localhost:6379",
			client: func(t *testing.T) redis.UniversalClient {
				t.Helper()

				client, err := newRedisClient("rediss://localhost:6379")
				require.NoError(t, err)

				opts, ok := client.(*redis.Client)
				require.True(t, ok)
				assert.Equal(t, "localhost:6379", opts.Options().Addr)
				require.NotNil(t, opts.Options().TLSConfig)
				assert.Equal(t, "localhost", opts.Options().TLSConfig.ServerName)
				return client
			},
		},
		{
			desc:     "redis sentinel",
			redisURL: "redis+sentinel://:sentinel-pass@sentinel1:26379,sentinel2:26379/1?masterName=mymaster&sentinelPassword=sentinel-pass",
			client: func(t *testing.T) redis.UniversalClient {
				t.Helper()

				client, err := newRedisClient("redis+sentinel://:sentinel-pass@sentinel1:26379,sentinel2:26379/1?masterName=mymaster&sentinelPassword=sentinel-pass")
				require.NoError(t, err)

				_, ok := client.(*redis.Client)
				require.True(t, ok)

				fo, err := parseSentinelURL("redis+sentinel://:sentinel-pass@sentinel1:26379,sentinel2:26379/1?masterName=mymaster&sentinelPassword=sentinel-pass")
				require.NoError(t, err)
				assert.Equal(t, "mymaster", fo.MasterName)
				assert.Equal(t, []string{"sentinel1:26379", "sentinel2:26379"}, fo.SentinelAddrs)
				assert.Equal(t, "sentinel-pass", fo.SentinelPassword)
				assert.Equal(t, "sentinel-pass", fo.Password)
				assert.Equal(t, 1, fo.DB)
				return client
			},
		},
		{
			desc:     "redis sentinel without masterName",
			redisURL: "redis+sentinel://sentinel1:26379",
			err:      `missing "masterName" query parameter in Redis Sentinel URL`,
		},
		{
			desc:     "redis sentinel without addresses",
			redisURL: "redis+sentinel://?masterName=mymaster",
			err:      "missing Redis Sentinel addresses",
		},
		{
			desc:     "invalid db number",
			redisURL: "redis+sentinel://sentinel1:26379/foo?masterName=mymaster",
			err:      `invalid Redis database number "foo"`,
		},
		{
			desc:     "unsupported scheme",
			redisURL: "redis-cluster://localhost:6379",
			err:      `unsupported Redis URL scheme "redis-cluster"`,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			_, err := newRedisClient(test.redisURL)
			if test.err != "" {
				require.ErrorContains(t, err, test.err)
				return
			}

			require.NoError(t, err)
			test.client(t)
		})
	}
}

func TestNewRedisStore_ConnectionError(t *testing.T) {
	_, err := NewRedisStore("redis://localhost:1")
	require.Error(t, err)
	assert.ErrorContains(t, err, "unable to connect to Redis")
}

func TestRedisStore_GetAccount(t *testing.T) {
	s := miniredis.RunT(t)

	store, err := NewRedisStore("redis://" + s.Addr())
	require.NoError(t, err)

	// Unknown resolver: an empty account is returned without error.
	account, err := store.GetAccount("unknown")
	require.NoError(t, err)
	assert.Nil(t, account)
}

func TestRedisStore_SaveGetAccount(t *testing.T) {
	s := miniredis.RunT(t)

	store, err := NewRedisStore("redis://" + s.Addr())
	require.NoError(t, err)

	expected := &Account{
		Email:        "foo@bar.com",
		Registration: &Resource{URI: "https://acme-v02.api.letsencrypt.org/acme/acct/123", Body: acme.Account{Status: "valid"}},
		PrivateKey:   []byte("private-key"),
	}

	err = store.SaveAccount("test", expected)
	require.NoError(t, err)

	account, err := store.GetAccount("test")
	require.NoError(t, err)
	assert.Equal(t, expected, account)

	// The stored data must be shared with the JSON serialization used by the LocalStore.
	// Note: miniredis' Lua engine drops null fields (Certificates is absent),
	// while real Redis stores them as null; both unmarshal to the same StoredData.
	raw, err := s.Get("traefik:acme:test")
	require.NoError(t, err)
	assert.JSONEq(t, `{
		"Account": {
			"Email": "foo@bar.com",
			"Registration": {"body": {"status": "valid"}, "uri": "https://acme-v02.api.letsencrypt.org/acme/acct/123"},
			"PrivateKey": "cHJpdmF0ZS1rZXk="
		}
	}`, raw)
}

func TestRedisStore_SaveGetCertificates(t *testing.T) {
	s := miniredis.RunT(t)

	store, err := NewRedisStore("redis://" + s.Addr())
	require.NoError(t, err)

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

	err = store.SaveCertificates("test", expected)
	require.NoError(t, err)

	certificates, err := store.GetCertificates("test")
	require.NoError(t, err)
	assert.Equal(t, expected, certificates)
}

func TestRedisStore_MergeKeepsAccountAndCertificates(t *testing.T) {
	s := miniredis.RunT(t)

	store, err := NewRedisStore("redis://" + s.Addr())
	require.NoError(t, err)

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

	// Save the account first, then the certificates: the account must survive.
	err = store.SaveAccount("test", account)
	require.NoError(t, err)

	err = store.SaveCertificates("test", certificates)
	require.NoError(t, err)

	gotAccount, err := store.GetAccount("test")
	require.NoError(t, err)
	assert.Equal(t, account, gotAccount)

	gotCertificates, err := store.GetCertificates("test")
	require.NoError(t, err)
	assert.Equal(t, certificates, gotCertificates)

	// Save the certificates first, then the account: the certificates must survive.
	err = store.SaveCertificates("test", certificates)
	require.NoError(t, err)

	err = store.SaveAccount("test", account)
	require.NoError(t, err)

	gotCertificates, err = store.GetCertificates("test")
	require.NoError(t, err)
	assert.Equal(t, certificates, gotCertificates)

	gotAccount, err = store.GetAccount("test")
	require.NoError(t, err)
	assert.Equal(t, account, gotAccount)
}

func TestRedisStore_ConcurrentSaves(t *testing.T) {
	s := miniredis.RunT(t)

	store, err := NewRedisStore("redis://" + s.Addr())
	require.NoError(t, err)

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

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for range 50 {
			err := store.SaveAccount("test", account)
			assert.NoError(t, err)
		}
	}()

	go func() {
		defer wg.Done()
		for range 50 {
			err := store.SaveCertificates("test", certificates)
			assert.NoError(t, err)
		}
	}()

	wg.Wait()

	gotAccount, err := store.GetAccount("test")
	require.NoError(t, err)
	assert.Equal(t, account, gotAccount)

	gotCertificates, err := store.GetCertificates("test")
	require.NoError(t, err)
	assert.Equal(t, certificates, gotCertificates)
}

func TestRedisStore_ResolversAreIsolated(t *testing.T) {
	s := miniredis.RunT(t)

	store, err := NewRedisStore("redis://" + s.Addr())
	require.NoError(t, err)

	err = store.SaveAccount("resolver-a", &Account{Email: "a@example.com"})
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

func TestRedisStore_CorruptedData(t *testing.T) {
	s := miniredis.RunT(t)

	store, err := NewRedisStore("redis://" + s.Addr())
	require.NoError(t, err)

	err = s.Set("traefik:acme:test", "not-json")
	require.NoError(t, err)

	_, err = store.GetAccount("test")
	require.Error(t, err)
	assert.ErrorContains(t, err, "unable to unmarshal ACME stored data from Redis")
}

func TestRedisStore_UnionMergeCertificates(t *testing.T) {
	s := miniredis.RunT(t)

	// Two Traefik instances sharing the same storage, each with a stale
	// in-memory view of the certificates.
	storeA, err := NewRedisStore("redis://" + s.Addr())
	require.NoError(t, err)
	storeB, err := NewRedisStore("redis://" + s.Addr())
	require.NoError(t, err)

	err = storeA.SaveCertificates("test", []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.com"}, Certificate: []byte("cert-pem-a"), Key: []byte("key-pem-a")},
			Store:       "default",
		},
	})
	require.NoError(t, err)

	// Instance B renews a different certificate: the union merge must keep
	// instance A's renewal in the shared store.
	err = storeB.SaveCertificates("test", []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.org"}, Certificate: []byte("cert-pem-b"), Key: []byte("key-pem-b")},
			Store:       "default",
		},
	})
	require.NoError(t, err)

	certificates, err := storeA.GetCertificates("test")
	require.NoError(t, err)
	require.Len(t, certificates, 2)

	domains := make([]string, 0, len(certificates))
	for _, cert := range certificates {
		domains = append(domains, cert.Certificate.Domain.Main)
	}
	assert.ElementsMatch(t, []string{"example.com", "example.org"}, domains)
}

func TestRedisStore_UnionMergeReplacesSameCertificate(t *testing.T) {
	s := miniredis.RunT(t)

	storeA, err := NewRedisStore("redis://" + s.Addr())
	require.NoError(t, err)
	storeB, err := NewRedisStore("redis://" + s.Addr())
	require.NoError(t, err)

	err = storeA.SaveCertificates("test", []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.com"}, Certificate: []byte("cert-v1"), Key: []byte("key-v1")},
			Store:       "default",
		},
	})
	require.NoError(t, err)

	// Renewal of the same certificate (same domain and store) replaces it.
	err = storeB.SaveCertificates("test", []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.com"}, Certificate: []byte("cert-v2"), Key: []byte("key-v2")},
			Store:       "default",
		},
	})
	require.NoError(t, err)

	certificates, err := storeA.GetCertificates("test")
	require.NoError(t, err)
	require.Len(t, certificates, 1)

	assert.Equal(t, []byte("cert-v2"), certificates[0].Certificate.Certificate)
	assert.Equal(t, []byte("key-v2"), certificates[0].Key)
}

func TestRedisStore_UnionMergeSameDomainDifferentStores(t *testing.T) {
	s := miniredis.RunT(t)

	store, err := NewRedisStore("redis://" + s.Addr())
	require.NoError(t, err)

	// Same domain served by two TLS stores must result in two certificates.
	err = store.SaveCertificates("test", []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.com"}, Certificate: []byte("cert-default"), Key: []byte("key-default")},
			Store:       "default",
		},
	})
	require.NoError(t, err)

	err = store.SaveCertificates("test", []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.com"}, Certificate: []byte("cert-web"), Key: []byte("key-web")},
			Store:       "web",
		},
	})
	require.NoError(t, err)

	certificates, err := store.GetCertificates("test")
	require.NoError(t, err)
	require.Len(t, certificates, 2)
}

func TestRedisStore_UnionMergeEmptySaveIsNoOp(t *testing.T) {
	s := miniredis.RunT(t)

	store, err := NewRedisStore("redis://" + s.Addr())
	require.NoError(t, err)

	err = store.SaveCertificates("test", []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.com"}, Certificate: []byte("cert-pem"), Key: []byte("key-pem")},
			Store:       "default",
		},
	})
	require.NoError(t, err)

	// Saving an empty list must neither clear the store nor corrupt it.
	err = store.SaveCertificates("test", []*CertAndStore{})
	require.NoError(t, err)

	certificates, err := store.GetCertificates("test")
	require.NoError(t, err)
	require.Len(t, certificates, 1)
	assert.Equal(t, "example.com", certificates[0].Certificate.Domain.Main)
}

func TestRedisStore_UnionMergeKeepsAccount(t *testing.T) {
	s := miniredis.RunT(t)

	storeA, err := NewRedisStore("redis://" + s.Addr())
	require.NoError(t, err)
	storeB, err := NewRedisStore("redis://" + s.Addr())
	require.NoError(t, err)

	account := &Account{Email: "foo@bar.com", PrivateKey: []byte("private-key")}

	err = storeA.SaveAccount("test", account)
	require.NoError(t, err)

	// Instance B renews a certificate: the account must survive the merge.
	err = storeB.SaveCertificates("test", []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.com"}, Certificate: []byte("cert-pem"), Key: []byte("key-pem")},
			Store:       "default",
		},
	})
	require.NoError(t, err)

	gotAccount, err := storeB.GetAccount("test")
	require.NoError(t, err)
	assert.Equal(t, account, gotAccount)
}

func TestRedisStore_Lock(t *testing.T) {
	s := miniredis.RunT(t)

	store, err := NewRedisStore("redis://" + s.Addr())
	require.NoError(t, err)

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

func TestRedisStore_LockExpiry(t *testing.T) {
	s := miniredis.RunT(t)

	store, err := NewRedisStore("redis://" + s.Addr())
	require.NoError(t, err)

	acquired, err := store.Lock(context.Background(), "example.com", "token-1", time.Second)
	require.NoError(t, err)
	assert.True(t, acquired)

	// After the TTL elapses, the lock is released (e.g. an instance that
	// crashed mid-renewal).
	s.FastForward(2 * time.Second)

	acquired, err = store.Lock(context.Background(), "example.com", "token-2", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired)
}

func TestRedisStore_LockPerDomain(t *testing.T) {
	s := miniredis.RunT(t)

	store, err := NewRedisStore("redis://" + s.Addr())
	require.NoError(t, err)

	ctx := context.Background()

	acquired, err := store.Lock(ctx, "example.com", "token-1", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired)

	// A different domain must not be blocked.
	acquired, err = store.Lock(ctx, "example.org", "token-2", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired)
}

func TestNewStore(t *testing.T) {
	redisServer := miniredis.RunT(t)

	redisAddr := redisServer.Addr()
	etcdAddr := sharedTestEtcdAddr(t)

	testCases := []struct {
		desc    string
		storage string
		store   func(t *testing.T, store Store)
		err     string
	}{
		{
			desc:    "local file path",
			storage: "acme.json",
			store: func(t *testing.T, store Store) {
				t.Helper()
				_, ok := store.(*LocalStore)
				require.True(t, ok)
			},
		},
		{
			desc:    "redis url",
			storage: "redis://" + redisAddr,
			store: func(t *testing.T, store Store) {
				t.Helper()
				_, ok := store.(*RedisStore)
				require.True(t, ok)
			},
		},
		{
			desc:    "etcd url",
			storage: "etcd://" + etcdAddr,
			store: func(t *testing.T, store Store) {
				t.Helper()
				_, ok := store.(*EtcdStore)
				require.True(t, ok)
			},
		},
		{
			desc:    "redis url with file fallback",
			storage: "redis://" + redisAddr + "?file=" + filepath.Join(t.TempDir(), "acme.json"),
			store: func(t *testing.T, store Store) {
				t.Helper()
				failover, ok := store.(*FailoverStore)
				require.True(t, ok)

				_, ok = failover.primary.(*RedisStore)
				require.True(t, ok)

				_, ok = failover.fallback.(*LocalStore)
				require.True(t, ok)
			},
		},
		{
			desc:    "etcd url with file fallback",
			storage: "etcd://" + etcdAddr + "?file=" + filepath.Join(t.TempDir(), "acme.json"),
			store: func(t *testing.T, store Store) {
				t.Helper()
				failover, ok := store.(*FailoverStore)
				require.True(t, ok)

				_, ok = failover.primary.(*EtcdStore)
				require.True(t, ok)

				_, ok = failover.fallback.(*LocalStore)
				require.True(t, ok)
			},
		},
		{
			desc:    "unsupported redis scheme",
			storage: "redis-cluster://" + redisAddr,
			err:     `unsupported Redis URL scheme "redis-cluster" for storage "redis-cluster://` + redisAddr + `"`,
		},
		{
			desc:    "unsupported etcd scheme",
			storage: "etcd-cluster://" + etcdAddr,
			err:     `unsupported etcd URL scheme "etcd-cluster" for storage "etcd-cluster://` + etcdAddr + `"`,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			store, err := NewStore(test.storage, safe.NewPool(t.Context()))
			if test.err != "" {
				require.ErrorContains(t, err, test.err)
				return
			}

			require.NoError(t, err)
			test.store(t, store)
		})
	}
}

func TestParseSentinelURL_Examples(t *testing.T) {
	// Documented examples, kept as a canary for the URL format.
	_, err := parseSentinelURL("redis+sentinel://localhost:26379?masterName=mymaster")
	require.NoError(t, err)

	_, err = parseSentinelURL("redis+sentinel://localhost:26379,localhost:26380?masterName=mymaster")
	require.NoError(t, err)
}
