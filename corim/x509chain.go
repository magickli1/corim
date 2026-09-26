// Copyright 2021-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package corim

import (
	"crypto/x509"
	"time"

	cose "github.com/veraison/go-cose"
)

// TrustAnchors holds trust material for x5chain validation.
// Prefer building via [LoadTrustAnchors].
//
// Trust sources are Anchors plus, when UseSystemRoots is set, the OS trust
// store. With neither, verification fails with [ErrX5ChainNoTrust]; the zero
// value does not fall back to the OS store.
//
// Revocation is checked only when CRLs is non-empty; RevocationMode selects
// which certificates are checked and CrlPolicy how a missing issuer CRL is
// handled. Every CRL that is used must carry ThisUpdate and NextUpdate,
// regardless of CrlPolicy.
//
// See [SignedCorim.VerifyWithX5Chain].
type TrustAnchors struct {
	// Anchors are custom trust anchors.
	Anchors []*x509.Certificate

	// UseSystemRoots adds the OS trust store as a trust source.
	UseSystemRoots bool

	// CRLs contains revocation data. An empty slice disables revocation checks
	// whatever RevocationMode says.
	CRLs []*x509.RevocationList

	// RevocationMode selects which certificates are checked against CRLs. The
	// zero value is [RevocationFullChain].
	RevocationMode RevocationMode

	// CrlPolicy selects how a missing issuer CRL is handled. The zero value is
	// [CrlPolicyStrict].
	CrlPolicy CrlPolicy

	// CurrentTime overrides the verification time. The zero value uses time.Now.
	CurrentTime time.Time
}

// Sentinel errors from go-cose, re-exported so callers can use errors.Is without
// importing go-cose directly.
var (
	ErrX5ChainNoTrust    = cose.ErrX5ChainNoTrust
	ErrX5ChainCRLMissing = cose.ErrX5ChainCRLMissing
	ErrX5ChainRevoked    = cose.ErrX5ChainRevoked
	ErrX5ChainSignature  = cose.ErrX5ChainSignature
)

// RevocationMode controls the scope of certificate revocation checking.
type RevocationMode = cose.RevocationMode

const (
	// RevocationFullChain checks every non-trust-anchor certificate.
	RevocationFullChain = cose.RevocationFullChain

	// RevocationLeafOnly checks only the signing certificate.
	RevocationLeafOnly = cose.RevocationLeafOnly

	// RevocationDisabled skips all CRL checks.
	RevocationDisabled = cose.RevocationDisabled
)

// CrlPolicy selects how missing issuer CRLs are handled when CRLs is non-empty.
type CrlPolicy = cose.CRLPolicy

const (
	// CrlPolicyStrict requires an applicable CRL for every certificate selected
	// by RevocationMode. This is the default (zero value).
	CrlPolicyStrict = cose.CRLPolicyStrict

	// CrlPolicyPermissive allows a selected certificate to have no applicable CRL
	// when the configured CRL set is non-empty.
	CrlPolicyPermissive = cose.CRLPolicyPermissive
)

// LoadTrustAnchors loads trust anchors and CRLs from files into a [TrustAnchors]
// value via [cose.LoadTrustAnchors].
//
// Files may be DER or PEM. PEM files must contain only CERTIFICATE (anchors) or
// X509 CRL (CRLs) blocks. Whitespace and # comment lines are allowed around
// blocks; other text and block types are rejected.
//
// When trustAnchorPaths is empty, UseSystemRoots is set so verification uses the
// OS trust store; otherwise only the loaded anchors are trusted.
// RevocationMode is left at its zero value, [RevocationFullChain]; revocation is
// checked whenever CRLs are present, including CRLs added after loading.
func LoadTrustAnchors(
	readFile func(string) ([]byte, error),
	trustAnchorPaths, crlPaths []string,
) (TrustAnchors, error) {
	loaded, err := cose.LoadTrustAnchors(readFile, trustAnchorPaths, crlPaths)
	if err != nil {
		return TrustAnchors{}, err
	}

	return TrustAnchors{
		Anchors:        loaded.Anchors,
		UseSystemRoots: len(trustAnchorPaths) == 0,
		CRLs:           loaded.CRLs,
	}, nil
}

// toCOSE converts corim trust settings into go-cose verification inputs.
// Empty CRLs map to [RevocationDisabled], since go-cose otherwise fails when
// revocation is enabled without CRLs.
func (a *TrustAnchors) toCOSE() (cose.TrustAnchors, *cose.X5ChainVerifyOptions) {
	mode := a.RevocationMode
	if len(a.CRLs) == 0 {
		mode = RevocationDisabled
	}

	return cose.TrustAnchors{
			Anchors:        a.Anchors,
			UseSystemRoots: a.UseSystemRoots,
			CRLs:           a.CRLs,
			RevocationMode: mode,
		}, &cose.X5ChainVerifyOptions{
			CRLPolicy:   a.CrlPolicy,
			CurrentTime: a.CurrentTime,
		}
}
