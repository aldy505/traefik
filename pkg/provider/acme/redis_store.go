package acme

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	_ Store         = (*RedisStore)(nil)
	_ LockableStore = (*RedisStore)(nil)
)

const (
	// defaultRedisKeyPrefix is the key prefix under which the ACME stored data
	// is kept. Each ACME resolver maps to the key "<prefix>:<resolverName>".
	defaultRedisKeyPrefix = "traefik:acme"

	// redisClientTimeout is the timeout used for the connectivity check
	// performed when the store is created.
	redisClientTimeout = 5 * time.Second
)

// mergeStoredDataScript atomically updates the stored data of a resolver, so
// concurrent saves from several Traefik instances never lose data.
//
// Account saves replace the Account field. Certificates saves merge the
// incoming certificates into the stored ones, keyed by (Store, domain):
// certificates already present are replaced, new ones are appended. This way,
// two instances renewing different certificates at the same time both keep
// their renewal in the shared store.
//
// Saving an empty certificate list is a no-op: it cannot clear the store, and
// it avoids cjson encoding an empty table as {} (which would not unmarshal
// back into a Go slice). The ACME provider never saves an empty list anyway.
var mergeStoredDataScript = redis.NewScript(`
local function certKey(cert)
  local store = cert.Store or ''
  local main = ''
  local sans = {}
  local domain = cert.domain
  if type(domain) == 'table' then
    main = domain.main or ''
    if type(domain.sans) == 'table' then
      for _, s in ipairs(domain.sans) do sans[#sans + 1] = s end
      table.sort(sans)
    end
  end
  return store .. '\0' .. main .. '\0' .. table.concat(sans, ',')
end

local data = cjson.decode(redis.call('GET', KEYS[1]) or '{}')
local incoming = cjson.decode(ARGV[2])

if ARGV[1] == 'Certificates' and type(incoming) == 'table' then
  if next(incoming) ~= nil then
    local existing = data.Certificates
    if type(existing) ~= 'table' then existing = {} end
    local index = {}
    for i, cert in ipairs(existing) do
      index[certKey(cert)] = i
    end
    for _, cert in ipairs(incoming) do
      local key = certKey(cert)
      if index[key] then
        existing[index[key]] = cert
      else
        existing[#existing + 1] = cert
        index[key] = #existing
      end
    end
    data.Certificates = existing
  end
else
  data[ARGV[1]] = incoming
end

return redis.call('SET', KEYS[1], cjson.encode(data))
`)

// unlockScript releases a lock only when it is still held with the expected token.
var unlockScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
`)

// RedisStore is a distributed Store implementation backed by Redis.
// It supports plain Redis (redis://, rediss://) and Redis Sentinel
// (redis+sentinel://) deployments.
type RedisStore struct {
	client    redis.UniversalClient
	keyPrefix string
}

// NewRedisStore initializes a new RedisStore from a Redis URL and fails when
// the server is unreachable.
//
// Supported URL schemes:
//
//	redis://[user:password@]host:port[/db]            plain Redis
//	rediss://[user:password@]host:port[/db]           Redis over TLS
//	redis+sentinel://[user:password@]host1:port1[,host2:port2][/db]?masterName=<name>[&sentinelUsername=<user>&sentinelPassword=<pass>]
func NewRedisStore(redisURL string) (*RedisStore, error) {
	return newRedisStore(redisURL, true)
}

// newRedisStore initializes a new RedisStore from a Redis URL. When
// checkConnection is false, an unreachable server does not prevent the store
// creation: operations then fail and are handled by the caller (used by the
// failover store, so Traefik can start while the primary store is down).
func newRedisStore(redisURL string, checkConnection bool) (*RedisStore, error) {
	client, err := newRedisClient(redisURL)
	if err != nil {
		return nil, err
	}

	if checkConnection {
		ctx, cancel := context.WithTimeout(context.Background(), redisClientTimeout)
		defer cancel()

		if err := client.Ping(ctx).Err(); err != nil {
			_ = client.Close()
			return nil, fmt.Errorf("unable to connect to Redis: %w", err)
		}
	}

	return &RedisStore{client: client, keyPrefix: defaultRedisKeyPrefix}, nil
}

// Close closes the underlying Redis connections.
func (s *RedisStore) Close() error {
	return s.client.Close()
}

// GetAccount returns ACME Account.
func (s *RedisStore) GetAccount(resolverName string) (*Account, error) {
	storedData, err := s.get(resolverName)
	if err != nil {
		return nil, err
	}

	return storedData.Account, nil
}

// SaveAccount stores ACME Account.
func (s *RedisStore) SaveAccount(resolverName string, account *Account) error {
	return s.saveField(resolverName, "Account", account)
}

// GetCertificates returns ACME Certificates list.
func (s *RedisStore) GetCertificates(resolverName string) ([]*CertAndStore, error) {
	storedData, err := s.get(resolverName)
	if err != nil {
		return nil, err
	}

	return storedData.Certificates, nil
}

// SaveCertificates stores ACME Certificates list.
func (s *RedisStore) SaveCertificates(resolverName string, certificates []*CertAndStore) error {
	return s.saveField(resolverName, "Certificates", certificates)
}

func (s *RedisStore) get(resolverName string) (*StoredData, error) {
	data, err := s.client.Get(context.Background(), s.key(resolverName)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return &StoredData{}, nil
		}
		return nil, fmt.Errorf("unable to read ACME stored data from Redis: %w", err)
	}

	if len(data) == 0 {
		return &StoredData{}, nil
	}

	storedData := &StoredData{}
	if err := json.Unmarshal(data, storedData); err != nil {
		return nil, fmt.Errorf("unable to unmarshal ACME stored data from Redis: %w", err)
	}

	return storedData, nil
}

// saveField atomically replaces one field of the resolver stored data in Redis.
func (s *RedisStore) saveField(resolverName, field string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("unable to marshal ACME %s: %w", field, err)
	}

	if err := mergeStoredDataScript.Run(context.Background(), s.client, []string{s.key(resolverName)}, field, string(payload)).Err(); err != nil {
		return fmt.Errorf("unable to write ACME %s to Redis: %w", field, err)
	}

	return nil
}

func (s *RedisStore) key(resolverName string) string {
	return s.keyPrefix + ":" + resolverName
}

// Lock acquires the lock named name if it is not already held.
// It returns true when the lock has been acquired, false when it is already
// held with another token. The lock is automatically released after ttl, or
// sooner when Unlock is called with the same token.
func (s *RedisStore) Lock(ctx context.Context, name, token string, ttl time.Duration) (bool, error) {
	acquired, err := s.client.SetNX(ctx, s.lockKey(name), token, ttl).Result()
	if err != nil {
		return false, fmt.Errorf("unable to acquire Redis lock %q: %w", name, err)
	}

	return acquired, nil
}

// Unlock releases the lock named name if it is still held with the given token.
func (s *RedisStore) Unlock(ctx context.Context, name, token string) error {
	if err := unlockScript.Run(ctx, s.client, []string{s.lockKey(name)}, token).Err(); err != nil {
		return fmt.Errorf("unable to release Redis lock %q: %w", name, err)
	}

	return nil
}

func (s *RedisStore) lockKey(name string) string {
	return s.keyPrefix + ":lock:" + name
}

func newRedisClient(redisURL string) (redis.UniversalClient, error) {
	u, err := url.Parse(redisURL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse Redis URL: %w", err)
	}

	switch u.Scheme {
	case "redis", "rediss":
		opts, err := redis.ParseURL(redisURL)
		if err != nil {
			return nil, fmt.Errorf("unable to parse Redis URL: %w", err)
		}

		return redis.NewClient(opts), nil

	case "redis+sentinel":
		opts, err := parseSentinelURL(redisURL)
		if err != nil {
			return nil, err
		}

		return redis.NewFailoverClient(opts), nil

	default:
		return nil, fmt.Errorf("unsupported Redis URL scheme %q", u.Scheme)
	}
}

// parseSentinelURL parses a redis+sentinel:// URL into FailoverOptions.
//
// The sentinel addresses are comma-separated host:port pairs. The userinfo
// holds the credentials used to authenticate against the Redis master, while
// the sentinel credentials are passed as query parameters.
func parseSentinelURL(redisURL string) (*redis.FailoverOptions, error) {
	u, err := url.Parse(redisURL)
	if err != nil {
		return nil, fmt.Errorf("unable to parse Redis Sentinel URL: %w", err)
	}
	if u.Scheme != "redis+sentinel" {
		return nil, fmt.Errorf("invalid Redis Sentinel URL scheme %q", u.Scheme)
	}

	query := u.Query()

	opts := &redis.FailoverOptions{MasterName: query.Get("masterName")}
	if opts.MasterName == "" {
		return nil, errors.New(`missing "masterName" query parameter in Redis Sentinel URL`)
	}

	for _, addr := range strings.Split(u.Host, ",") {
		if addr = strings.TrimSpace(addr); addr != "" {
			opts.SentinelAddrs = append(opts.SentinelAddrs, addr)
		}
	}
	if len(opts.SentinelAddrs) == 0 {
		return nil, errors.New("missing Redis Sentinel addresses")
	}

	// Credentials for the Redis master come from the URL userinfo.
	if u.User != nil {
		opts.Username = u.User.Username()
		opts.Password, _ = u.User.Password()
	}

	// Credentials for the Sentinel nodes come from query parameters.
	opts.SentinelUsername = query.Get("sentinelUsername")
	opts.SentinelPassword = query.Get("sentinelPassword")

	db, err := dbFromURL(u)
	if err != nil {
		return nil, err
	}
	opts.DB = db

	return opts, nil
}

// dbFromURL returns the Redis database number from the URL path or the "db"
// query parameter (the query parameter takes precedence).
func dbFromURL(u *url.URL) (int, error) {
	db := 0

	if path := strings.TrimPrefix(u.Path, "/"); path != "" {
		parsed, err := strconv.Atoi(path)
		if err != nil {
			return 0, fmt.Errorf("invalid Redis database number %q: %w", path, err)
		}
		db = parsed
	}

	if v := u.Query().Get("db"); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("invalid Redis database number %q: %w", v, err)
		}
		db = parsed
	}

	if db < 0 {
		return 0, fmt.Errorf("invalid Redis database number %d", db)
	}

	return db, nil
}
