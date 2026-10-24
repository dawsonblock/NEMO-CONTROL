package witness

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/openclaw/crabbox/internal/evidence"
)

// tlsKey adapts an evidence.Signer to crypto.Signer — the private key
// never leaves the signer; TLS gets signatures, not key material.
type tlsKey struct{ s *evidence.Signer }

func (k tlsKey) Public() crypto.PublicKey { return k.s.PublicKey() }

func (k tlsKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return k.s.SignBytes(digest), nil
}

// Separate-host custody transport: TLS with mutual authentication where
// each peer's certificate carries its custody Ed25519 key — the same
// pinned-key model as every other custody signature, not a second PKI.
// Peer verification pins the certificate's raw public-key fingerprint,
// so a certificate for any other key — however well-formed — is not
// the configured peer.

// SelfSignedCertificate mints a self-signed X.509 certificate binding
// the signer's Ed25519 custody key for use as a TLS identity.
func SelfSignedCertificate(signer *evidence.Signer) (tls.Certificate, error) {
	pub := signer.PublicKey()
	priv := tlsKey{s: signer}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "crabedence-custody-" + signer.Fingerprint()[:16]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("custody tls certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

// pinPeer returns a VerifyPeerCertificate callback that accepts exactly
// one peer: the certificate whose raw subject public key fingerprints
// to expectedFP. CA verification is intentionally bypassed — the pin,
// not a hierarchy, is the trust root.
func pinPeer(expectedFP, who string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("%s presented no certificate", who)
		}
		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("%s certificate does not parse: %w", who, err)
		}
		pub, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("%s certificate key is not Ed25519", who)
		}
		if fp := evidence.Fingerprint(pub); fp != expectedFP {
			return fmt.Errorf("%s authenticated as key %s, expected pinned key %s — refusing unconfigured peer", who, fp, expectedFP)
		}
		return nil
	}
}

// ServerTLSConfig builds the witness's TLS identity: the witness's own
// custody key as its certificate, and a requirement that the client
// present a certificate whose key fingerprints to clientKeyFP — the
// pinned kernel-relay key. clientKeyFP empty refuses the config: an
// unauthenticated separate-host custody peer is not custody.
func ServerTLSConfig(signer *evidence.Signer, clientKeyFP string) (*tls.Config, error) {
	if clientKeyFP == "" {
		return nil, fmt.Errorf("separate-host custody requires a pinned client key fingerprint")
	}
	cert, err := SelfSignedCertificate(signer)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: pinPeer(clientKeyFP, "custody client"),
		MinVersion:            tls.VersionTLS13,
	}, nil
}

// ClientTLSConfig builds the kernel's TLS identity: its kernel-relay
// custody key as its certificate, and a pin on the witness's key
// fingerprint. InsecureSkipVerify is set deliberately — CA-chain
// verification is replaced by the stronger peer-key pin.
func ClientTLSConfig(signer *evidence.Signer, witnessKeyFP string) (*tls.Config, error) {
	if witnessKeyFP == "" {
		return nil, fmt.Errorf("separate-host custody requires a pinned witness key fingerprint")
	}
	cert, err := SelfSignedCertificate(signer)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:          []tls.Certificate{cert},
		InsecureSkipVerify:    true, // replaced by the pinned-key check below
		VerifyPeerCertificate: pinPeer(witnessKeyFP, "custody witness"),
		MinVersion:            tls.VersionTLS13,
	}, nil
}
