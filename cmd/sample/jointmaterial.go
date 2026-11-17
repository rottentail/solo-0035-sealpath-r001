package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"sealpath/internal/codec"
	"time"
)

// JointSamples extends the base material with two independent endorsing
// institutions. Each institution has a primary/reviewer key pair issued from
// its own intermediate under the same receiver-approved root.
type JointSamples struct {
	Root           string    `json:"root"`
	RootID         string    `json:"root_id"`
	PrimaryCA      string    `json:"primary_ca"`
	PrimaryCAID    string    `json:"primary_ca_id"`
	ReviewerCA     string    `json:"reviewer_ca_pem"`
	ReviewerCAID   string    `json:"reviewer_ca_id"`
	PrimaryCert    string    `json:"primary_cert"`
	PrimaryID      string    `json:"primary_cert_id"`
	ReviewerCert   string    `json:"reviewer_cert"`
	ReviewerID     string    `json:"reviewer_cert_id"`
	Reviewer2Cert  string    `json:"reviewer2_cert"`
	Reviewer2ID    string    `json:"reviewer2_cert_id"`
	PrimaryRenew   string    `json:"primary_renewal_cert"`
	PrimaryRenewID string    `json:"primary_renewal_cert_id"`
	RootCRL        string    `json:"root_crl"`
	PrimaryCRL     string    `json:"primary_crl"`
	ReviewerCRL    string    `json:"reviewer_crl"`
	RevokedPrimary string    `json:"revoked_primary_crl"`
	Content        []byte    `json:"content"`
	PrimarySig     []byte    `json:"primary_signature"`
	ReviewerSig    []byte    `json:"reviewer_signature"`
	Reviewer2Sig   []byte    `json:"reviewer2_signature"`
	RenewalSig     []byte    `json:"renewal_signature"`
	At             time.Time `json:"at"`
}

func generateJoint() (JointSamples, error) {
	var out JointSamples
	at := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	out.At = at
	encode := func(kind string, data []byte) string {
		return string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: data}))
	}
	rootPub, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return out, err
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(900), Subject: pkix.Name{CommonName: "Joint Release Root"}, NotBefore: at.AddDate(-1, 0, 0), NotAfter: at.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 2, SubjectKeyId: []byte("joint-root")}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPub, rootKey)
	if err != nil {
		return out, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return out, err
	}
	out.Root, out.RootID = encode("CERTIFICATE", rootDER), codec.Digest(rootDER)

	makeIssuer := func(serial int64, name, keyID string) (*x509.Certificate, ed25519.PrivateKey, string, error) {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, "", err
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: at.AddDate(-1, 0, 0), NotAfter: at.AddDate(3, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 0, MaxPathLenZero: true, SubjectKeyId: []byte(keyID)}
		der, err := x509.CreateCertificate(rand.Reader, template, root, pub, rootKey)
		if err != nil {
			return nil, nil, "", err
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, "", err
		}
		return parsed, key, encode("CERTIFICATE", der), nil
	}
	primaryCA, primaryCAKey, primaryPEM, err := makeIssuer(901, "Joint Primary Issuer", "joint-primary")
	if err != nil {
		return out, err
	}
	reviewerCA, reviewerCAKey, reviewerPEM, err := makeIssuer(902, "Joint Reviewer Issuer", "joint-reviewer")
	if err != nil {
		return out, err
	}
	out.PrimaryCA, out.PrimaryCAID = primaryPEM, codec.Digest(primaryCA.Raw)
	out.ReviewerCA, out.ReviewerCAID = reviewerPEM, codec.Digest(reviewerCA.Raw)

	makeLeaf := func(serial int64, name string, issuer *x509.Certificate, key ed25519.PrivateKey, issuerKey ed25519.PrivateKey) (ed25519.PrivateKey, string, string, error) {
		pub, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, "", "", err
		}
		if key != nil {
			pub, private = key.Public().(ed25519.PublicKey), key
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: at.AddDate(0, -1, 0), NotAfter: at.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, BasicConstraintsValid: true}
		der, err := x509.CreateCertificate(rand.Reader, template, issuer, pub, issuerKey)
		if err != nil {
			return nil, "", "", err
		}
		return private, encode("CERTIFICATE", der), codec.Digest(der), nil
	}
	primaryKey, primaryCert, primaryID, err := makeLeaf(911, "Joint Primary Signer", primaryCA, nil, primaryCAKey)
	if err != nil {
		return out, err
	}
	reviewerKey, reviewerCert, reviewerID, err := makeLeaf(912, "Joint Reviewer Signer", reviewerCA, nil, reviewerCAKey)
	if err != nil {
		return out, err
	}
	// A renewed certificate for the same primary institution and same key. If a
	// caller could substitute this certificate, one institution would appear to
	// cast two votes.
	_, renewalCert, renewalID, err := makeLeaf(913, "Joint Primary Signer Renewed", primaryCA, primaryKey, primaryCAKey)
	if err != nil {
		return out, err
	}
	reviewer2Key, reviewer2Cert, reviewer2ID, err := makeLeaf(914, "Joint Second Reviewer Signer", reviewerCA, nil, reviewerCAKey)
	if err != nil {
		return out, err
	}
	out.PrimaryCert, out.PrimaryID = primaryCert, primaryID
	out.ReviewerCert, out.ReviewerID = reviewerCert, reviewerID
	out.Reviewer2Cert, out.Reviewer2ID = reviewer2Cert, reviewer2ID
	out.PrimaryRenew, out.PrimaryRenewID = renewalCert, renewalID

	makeCRL := func(issuer *x509.Certificate, key ed25519.PrivateKey) (string, error) {
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: at.Add(-24 * time.Hour), NextUpdate: at.Add(24 * time.Hour)}, issuer, key)
		if err != nil {
			return "", err
		}
		return encode("X509 CRL", der), nil
	}
	rootCRL, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: at.Add(-24 * time.Hour), NextUpdate: at.Add(24 * time.Hour)}, root, rootKey)
	if err != nil {
		return out, err
	}
	out.RootCRL = encode("X509 CRL", rootCRL)
	if out.PrimaryCRL, err = makeCRL(primaryCA, primaryCAKey); err != nil {
		return out, err
	}
	// A later list that explicitly revokes the original primary certificate.
	revoked, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: at.Add(-time.Hour), NextUpdate: at.Add(24 * time.Hour), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(911), RevocationTime: at.Add(-2 * time.Hour)}}}, primaryCA, primaryCAKey)
	if err != nil {
		return out, err
	}
	out.RevokedPrimary = encode("X509 CRL", revoked)
	if out.ReviewerCRL, err = makeCRL(reviewerCA, reviewerCAKey); err != nil {
		return out, err
	}

	out.Content = []byte("sealpath-joint-release\ncomponent=joint-verifier\nrevision=1\n")
	if out.PrimarySig, err = primaryKey.Sign(rand.Reader, out.Content, crypto.Hash(0)); err != nil {
		return out, err
	}
	if out.ReviewerSig, err = reviewerKey.Sign(rand.Reader, out.Content, crypto.Hash(0)); err != nil {
		return out, err
	}
	if out.Reviewer2Sig, err = reviewer2Key.Sign(rand.Reader, out.Content, crypto.Hash(0)); err != nil {
		return out, err
	}
	// The renewal certificate shares the primary key, so the same detached
	// signature is valid under it.
	out.RenewalSig = out.PrimarySig
	return out, nil
}

func jointMaterial(s JointSamples) (map[string]string, error) {
	// A tiny guard used by the walkthrough: all PEM material must be parseable.
	for name, value := range map[string]string{"root": s.Root, "primary_ca": s.PrimaryCA, "reviewer_ca": s.ReviewerCA, "primary": s.PrimaryCert, "reviewer": s.ReviewerCert} {
		if _, err := codec.ParseCertificate([]byte(value)); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil, nil
}
