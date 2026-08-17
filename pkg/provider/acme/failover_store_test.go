package acme

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/safe"
	"github.com/traefik/traefik/v3/pkg/types"
)

// stubStore is a scripted Store used to test the failover logic without a
// real primary store.
type stubStore struct {
	account      *Account
	certificates []*CertAndStore

	readErr   error // returned by GetAccount and GetCertificates
	saveErr   error // returned by SaveAccount and SaveCertificates
	lockErr   error // returned by Lock
	unlockErr error // returned by Unlock

	lockResult bool

	lockCount    int
	unlockCount  int
	saveCount    int
	savedAccount *Account
	savedCerts   []*CertAndStore
}

func (s *stubStore) GetAccount(string) (*Account, error) {
	return s.account, s.readErr
}

func (s *stubStore) SaveAccount(_ string, account *Account) error {
	s.saveCount++
	s.savedAccount = account
	if s.saveErr != nil {
		return s.saveErr
	}

	s.account = account
	return nil
}

func (s *stubStore) GetCertificates(string) ([]*CertAndStore, error) {
	return s.certificates, s.readErr
}

func (s *stubStore) SaveCertificates(_ string, certificates []*CertAndStore) error {
	s.saveCount++
	s.savedCerts = certificates
	if s.saveErr != nil {
		return s.saveErr
	}

	s.certificates = certificates
	return nil
}

func (s *stubStore) Lock(_ context.Context, _ string, _ string, _ time.Duration) (bool, error) {
	s.lockCount++
	if s.lockErr != nil {
		return false, s.lockErr
	}

	return s.lockResult, nil
}

func (s *stubStore) Unlock(_ context.Context, _ string, _ string) error {
	s.unlockCount++
	return s.unlockErr
}

func newTestLocalStore(t *testing.T) *LocalStore {
	t.Helper()

	return NewLocalStore(filepath.Join(t.TempDir(), "acme.json"), safe.NewPool(t.Context()))
}

// newFailoverStoreWithEtcd creates a FailoverStore whose primary is a real
// EtcdStore connected to a dedicated embedded etcd server, with a local file
// fallback. The server is stopped and its ports are released by the returned
// function, so a test can simulate an outage (and restart the server).
func newFailoverStoreWithEtcd(t *testing.T) (*FailoverStore, int, int, func()) {
	t.Helper()

	clientPort, err := freePort()
	require.NoError(t, err)

	peerPort, err := freePort()
	require.NoError(t, err)

	addr, stop, err := startEmbeddedEtcd(t.TempDir(), clientPort, peerPort)
	require.NoError(t, err)
	t.Cleanup(stop)

	filePath := filepath.Join(t.TempDir(), "acme.json")

	store, err := NewStore("etcd://"+addr+"?file="+filePath, safe.NewPool(t.Context()))
	require.NoError(t, err)

	failover, ok := store.(*FailoverStore)
	require.True(t, ok)

	return failover, clientPort, peerPort, stop
}

func eventually(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatal("condition not met within", timeout)
}

func TestFailoverStore_DualWrite(t *testing.T) {
	failover, _, _, _ := newFailoverStoreWithEtcd(t)

	account := &Account{Email: "foo@bar.com", PrivateKey: []byte("private-key")}

	err := failover.SaveAccount("test", account)
	require.NoError(t, err)

	// The primary has the account.
	got, err := failover.GetAccount("test")
	require.NoError(t, err)
	assert.Equal(t, account, got)

	// The local fallback file has it too.
	filePath := failover.fallback.(*LocalStore).filename
	eventually(t, 5*time.Second, func() bool {
		raw, err := os.ReadFile(filePath)
		return err == nil && strings.Contains(string(raw), "foo@bar.com")
	})
}

func TestFailoverStore_PrimaryDownReadsFallback(t *testing.T) {
	failover, _, _, stop := newFailoverStoreWithEtcd(t)

	account := &Account{Email: "foo@bar.com", PrivateKey: []byte("private-key")}
	certificates := []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.com"}, Certificate: []byte("cert-pem"), Key: []byte("key-pem")},
			Store:       "default",
		},
	}

	err := failover.SaveAccount("test", account)
	require.NoError(t, err)

	err = failover.SaveCertificates("test", certificates)
	require.NoError(t, err)

	// The primary goes down: reads must come from the local fallback.
	stop()

	gotAccount, err := failover.GetAccount("test")
	require.NoError(t, err)
	assert.Equal(t, account, gotAccount)

	gotCertificates, err := failover.GetCertificates("test")
	require.NoError(t, err)
	assert.Equal(t, certificates, gotCertificates)
}

func TestFailoverStore_RecoveryPushBack(t *testing.T) {
	failover, clientPort, peerPort, stop := newFailoverStoreWithEtcd(t)

	primary := failover.primary.(*EtcdStore)

	err := failover.SaveCertificates("test", []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.com"}, Certificate: []byte("cert-pem"), Key: []byte("key-pem")},
			Store:       "default",
		},
	})
	require.NoError(t, err)

	// The primary goes down: a renewal only reaches the local fallback.
	stop()

	err = failover.SaveCertificates("test", []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.org"}, Certificate: []byte("cert-pem-2"), Key: []byte("key-pem-2")},
			Store:       "default",
		},
	})
	require.NoError(t, err)

	// The primary comes back on the same address: the next read must merge
	// the renewal from the fallback and push it back to the primary.
	_, stop2, err := startEmbeddedEtcd(t.TempDir(), clientPort, peerPort)
	require.NoError(t, err)
	t.Cleanup(stop2)

	eventually(t, 30*time.Second, func() bool {
		certificates, err := failover.GetCertificates("test")
		if err != nil || len(certificates) != 2 {
			return false
		}

		raw, err := rawEtcdValueAt(t, primary.client.Endpoints()[0], primary.key("test"))
		if err != nil {
			return false
		}

		storedData := &StoredData{}
		if err := json.Unmarshal(raw, storedData); err != nil {
			return false
		}

		return len(storedData.Certificates) == 2
	})
}

func TestFailoverStore_StartupWithPrimaryDown(t *testing.T) {
	// Seed the local fallback file.
	seeded := map[string]*StoredData{
		"test": {
			Account: &Account{Email: "foo@bar.com", PrivateKey: []byte("private-key")},
			Certificates: []*CertAndStore{
				{
					Certificate: Certificate{Domain: types.Domain{Main: "example.com"}, Certificate: []byte("cert-pem"), Key: []byte("key-pem")},
					Store:       "default",
				},
			},
		},
	}

	filePath := filepath.Join(t.TempDir(), "acme.json")

	raw, err := json.Marshal(seeded)
	require.NoError(t, err)

	err = os.WriteFile(filePath, raw, 0o600)
	require.NoError(t, err)

	// The primary is unreachable (port 1 refuses connections), but the
	// fallback is configured: the store must be created without a
	// connectivity check.
	store, err := NewStore("etcd://127.0.0.1:1?file="+filePath, safe.NewPool(t.Context()))
	require.NoError(t, err)

	account, err := store.GetAccount("test")
	require.NoError(t, err)
	assert.Equal(t, "foo@bar.com", account.Email)

	certificates, err := store.GetCertificates("test")
	require.NoError(t, err)
	require.Len(t, certificates, 1)
	assert.Equal(t, "example.com", certificates[0].Certificate.Domain.Main)

	// A renewal succeeds through the fallback while the primary is down.
	err = store.SaveCertificates("test", certificates)
	require.NoError(t, err)
}

func TestFailoverStore_GetCertificatesMergesSources(t *testing.T) {
	primary := &stubStore{
		certificates: []*CertAndStore{
			{
				Certificate: Certificate{Domain: types.Domain{Main: "example.com"}, Certificate: []byte("cert-pem-a"), Key: []byte("key-pem-a")},
				Store:       "default",
			},
		},
	}

	fallback := newTestLocalStore(t)
	err := fallback.SaveCertificates("test", []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.org"}, Certificate: []byte("cert-pem-b"), Key: []byte("key-pem-b")},
			Store:       "default",
		},
	})
	require.NoError(t, err)

	store := NewFailoverStore(primary, fallback)

	// The read is the union of both sources, and the primary catches up.
	certificates, err := store.GetCertificates("test")
	require.NoError(t, err)
	require.Len(t, certificates, 2)
	require.Len(t, primary.certificates, 2)

	// A second read must not push the same data again.
	store.GetCertificates("test")
	assert.Equal(t, 1, primary.saveCount)
}

func TestFailoverStore_GetCertificatesPrimaryDown(t *testing.T) {
	primary := &stubStore{readErr: errors.New("primary down")}

	fallback := newTestLocalStore(t)
	err := fallback.SaveCertificates("test", []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.com"}, Certificate: []byte("cert-pem"), Key: []byte("key-pem")},
			Store:       "default",
		},
	})
	require.NoError(t, err)

	store := NewFailoverStore(primary, fallback)

	certificates, err := store.GetCertificates("test")
	require.NoError(t, err)
	require.Len(t, certificates, 1)
	assert.Equal(t, "example.com", certificates[0].Certificate.Domain.Main)

	// The reconciliation with the primary was attempted.
	assert.Equal(t, 1, primary.saveCount)
}

func TestFailoverStore_GetAccountPrimaryEmptyUsesFallback(t *testing.T) {
	primary := &stubStore{}

	fallback := newTestLocalStore(t)
	err := fallback.SaveAccount("test", &Account{Email: "foo@bar.com", PrivateKey: []byte("private-key")})
	require.NoError(t, err)

	store := NewFailoverStore(primary, fallback)

	account, err := store.GetAccount("test")
	require.NoError(t, err)
	assert.Equal(t, "foo@bar.com", account.Email)

	// The primary catches up on recovery.
	assert.Equal(t, "foo@bar.com", primary.savedAccount.Email)
}

func TestFailoverStore_SaveSucceedsWhenPrimaryFails(t *testing.T) {
	primary := &stubStore{saveErr: errors.New("primary down")}
	fallback := newTestLocalStore(t)

	store := NewFailoverStore(primary, fallback)

	err := store.SaveAccount("test", &Account{Email: "foo@bar.com"})
	require.NoError(t, err)

	err = store.SaveCertificates("test", []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.com"}, Certificate: []byte("cert-pem"), Key: []byte("key-pem")},
			Store:       "default",
		},
	})
	require.NoError(t, err)

	gotAccount, err := store.GetAccount("test")
	require.NoError(t, err)
	assert.Equal(t, "foo@bar.com", gotAccount.Email)

	gotCertificates, err := store.GetCertificates("test")
	require.NoError(t, err)
	require.Len(t, gotCertificates, 1)
}

func TestFailoverStore_SaveFailsWhenBothStoresFail(t *testing.T) {
	primary := &stubStore{saveErr: errors.New("primary down")}
	fallback := &stubStore{saveErr: errors.New("disk full")}

	store := NewFailoverStore(primary, fallback)

	err := store.SaveAccount("test", &Account{Email: "foo@bar.com"})
	require.Error(t, err)

	err = store.SaveCertificates("test", []*CertAndStore{
		{
			Certificate: Certificate{Domain: types.Domain{Main: "example.com"}, Certificate: []byte("cert-pem"), Key: []byte("key-pem")},
			Store:       "default",
		},
	})
	require.Error(t, err)
}

func TestFailoverStore_EmptySaveIsNoOp(t *testing.T) {
	primary := &stubStore{}
	fallback := newTestLocalStore(t)

	store := NewFailoverStore(primary, fallback)

	err := store.SaveCertificates("test", nil)
	require.NoError(t, err)
	assert.Zero(t, primary.saveCount)

	certificates, err := fallback.GetCertificates("test")
	require.NoError(t, err)
	assert.Nil(t, certificates)
}

func TestFailoverStore_LockUsesPrimary(t *testing.T) {
	primary := &stubStore{lockResult: true}
	fallback := newTestLocalStore(t)

	store := NewFailoverStore(primary, fallback)

	acquired, err := store.Lock(context.Background(), "example.com", "token-1", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired)
	assert.Equal(t, 1, primary.lockCount)

	err = store.Unlock(context.Background(), "example.com", "token-1")
	require.NoError(t, err)
	assert.Equal(t, 1, primary.unlockCount)
}

func TestFailoverStore_LockFallsBackToLocal(t *testing.T) {
	primary := &stubStore{lockErr: errors.New("primary down"), lockResult: true}
	fallback := newTestLocalStore(t)

	store := NewFailoverStore(primary, fallback)

	ctx := context.Background()

	acquired, err := store.Lock(ctx, "example.com", "token-1", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired)

	// The same instance cannot acquire the lock twice.
	acquired, err = store.Lock(ctx, "example.com", "token-2", time.Minute)
	require.NoError(t, err)
	assert.False(t, acquired)

	// A different name is not blocked.
	acquired, err = store.Lock(ctx, "example.org", "token-3", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired)

	// Unlock releases the local lock and still reaches the primary.
	err = store.Unlock(ctx, "example.com", "token-1")
	require.NoError(t, err)
	assert.Equal(t, 1, primary.unlockCount)

	acquired, err = store.Lock(ctx, "example.com", "token-4", time.Minute)
	require.NoError(t, err)
	assert.True(t, acquired)
}
