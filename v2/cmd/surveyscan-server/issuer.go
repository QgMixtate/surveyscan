package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/bao"
	"github.com/QgMixtate/surveyscan/v2/internal/platform/diskspool"
)

// bootstrapIssuer — операторская dev-команда. Root token не принимается, CA/receipt private keys не экспортируются.
func bootstrapIssuer(args []string) error {
	flags := flag.NewFlagSet("bootstrap-issuer", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	config := flags.String("config", "", "")
	output := flags.String("output-directory", "", "")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *config == "" || *output == "" {
		return errors.New("explicit private OpenBao config and output directory required")
	}
	client, e := bao.Load(*config)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(*output, 0700); e != nil {
		return e
	}
	for _, name := range []string{"ca.pem", "server.pem", "server.key"} {
		if _, e = os.Lstat(filepath.Join(*output, name)); !os.IsNotExist(e) {
			return errors.New("issuer output already exists")
		}
	}
	public, e := client.Public("ca")
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return e
	}
	ca := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "SurveyScan OpenBao root"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(2 * 365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLen: 0, MaxPathLenZero: true}
	signer := bao.Signer{Client: client, Alias: "ca", Context: ctx}
	raw, e := x509.CreateCertificate(rand.Reader, ca, ca, public, signer)
	if e != nil {
		return e
	}
	parsed, e := x509.ParseCertificate(raw)
	if e != nil {
		return e
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	if e = diskspool.Atomic(filepath.Join(*output, "ca.pem"), caPEM); e != nil {
		return e
	}
	serverPublic, serverKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return e
	}
	serial, e = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return e
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "SurveyScan dev loopback"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	raw, e = x509.CreateCertificate(rand.Reader, leaf, parsed, serverPublic, signer)
	if e != nil {
		return e
	}
	if e = diskspool.Atomic(filepath.Join(*output, "server.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})); e != nil {
		return e
	}
	private, e := x509.MarshalPKCS8PrivateKey(serverKey)
	if e != nil {
		return e
	}
	if e = diskspool.Atomic(filepath.Join(*output, "server.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})); e != nil {
		return e
	}
	fmt.Println("loopback issuer files prepared; CA/receipt private keys remain in OpenBao")
	return nil
}
