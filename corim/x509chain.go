// Copyright 2021-2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

package corim

import (
	"errors"

	cose "github.com/veraison/go-cose"
)

// TrustAnchors holds trust material for x5chain validation.
// Prefer building via [LoadTrustAnchors].
//
// Pool semantics:
//   - nil — load OS trust store at verify time (used when no trust anchors are
//     supplied via [LoadTrustAnchors])
//   - non-nil pool — verify only against those anchors (explicit override; no
//     system roots)
//
// CRL semantics:
//   - empty CRLs — skip revocation checks
//   - non-empty CRLs — post-PKIX revocation checks; [CrlPolicy] selects strict vs
//     permissive behavior when an in-chain issuer has no matching CRL
//
// See [SignedCorim.VerifyWithX5Chain].
type TrustAnchors = cose.TrustAnchors

// CrlPolicy selects how missing issuer CRLs are handled when CRLs is non-empty.
type CrlPolicy = cose.CrlPolicy

const (
	// CrlPolicyStrict requires every in-chain issuer to have a valid matching CRL
	// (OpenSSL CRL_CHECK_ALL). This is the default (zero value).
	CrlPolicyStrict = cose.CrlPolicyStrict
	// CrlPolicyPermissive skips revocation for in-chain issuers with no matching CRL.
	// When matching CRLs exist but are all invalid, verification still fails.
	CrlPolicyPermissive = cose.CrlPolicyPermissive
)

var corimX5ChainOpts = &cose.X5ChainVerifyOptions{
	RequireNonCALeaf:                true,
	RequireDigitalSignatureKeyUsage: true,
}

// LoadTrustAnchors loads trust anchors and CRLs from files into a [TrustAnchors] value.
// PEM trust-anchor files may bundle multiple certificates
// ([x509.CertPool.AppendCertsFromPEM]); PEM CRL files may contain multiple blocks.
// Duplicate DER anchors in trustAnchorPaths are added once.
//
// When trustAnchorPaths is empty, Pool is nil and verification uses the OS trust
// store. When trustAnchorPaths is non-empty, only those anchors are trusted.
func LoadTrustAnchors(
	readFile func(string) ([]byte, error),
	trustAnchorPaths, crlPaths []string,
) (TrustAnchors, error) {
	return cose.LoadTrustAnchors(readFile, trustAnchorPaths, crlPaths)
}

// VerifyWithX5Chain validates the embedded x5chain and CoRIM COSE signature.
// Call [SignedCorim.FromCOSE] first. For external-key verify without PKIX, use [SignedCorim.Verify].
// Load trust material via [LoadTrustAnchors] when reading anchors/CRLs from files.
func (o *SignedCorim) VerifyWithX5Chain(anchors TrustAnchors) error {
	if o.message == nil {
		return errNoSign1Message
	}

	if o.SigningCert == nil {
		return errors.New("x5chain: header not set in CoRIM")
	}

	return o.message.VerifyWithX5Chain(NoExternalData, anchors, corimX5ChainOpts)
}
