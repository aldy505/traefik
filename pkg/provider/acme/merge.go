package acme

import (
	"slices"
	"strings"
)

// certIdentity identifies a certificate in a merged list by the TLS store it
// belongs to and its domain (main + sorted SANs). It mirrors the key used by
// the Redis store's Lua merge script, so all stores agree on what "the same
// certificate" means.
type certIdentity struct {
	store string
	main  string
	sans  string
}

func certIdentityOf(cert *CertAndStore) certIdentity {
	id := certIdentity{}

	if cert == nil {
		return id
	}

	id.store = cert.Store
	id.main = cert.Domain.Main

	sans := slices.Clone(cert.Domain.SANs)
	slices.Sort(sans)
	id.sans = strings.Join(sans, ",")

	return id
}

// mergeCertificates merges the incoming certificates into the existing ones,
// keyed by (Store, domain): certificates already present are replaced, new
// ones are appended. It is used by the stores that cannot replace the whole
// list atomically (etcd, and the local fallback of the failover store), so
// concurrent saves from several Traefik instances never lose data.
func mergeCertificates(existing, incoming []*CertAndStore) []*CertAndStore {
	if len(incoming) == 0 {
		return existing
	}

	merged := slices.Clone(existing)
	index := make(map[certIdentity]int, len(merged))
	for i, cert := range merged {
		index[certIdentityOf(cert)] = i
	}

	for _, cert := range incoming {
		id := certIdentityOf(cert)
		if i, ok := index[id]; ok {
			merged[i] = cert
			continue
		}

		index[id] = len(merged)
		merged = append(merged, cert)
	}

	return merged
}
