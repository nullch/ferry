package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func genKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

func writePEM(file, typ string, der []byte, mode os.FileMode) error {
	b := pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
	return os.WriteFile(file, b, mode)
}

func writeKey(file string, k *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return err
	}
	return writePEM(file, "EC PRIVATE KEY", der, 0600)
}

// cmdPKI создаёт мини-CA и два сертификата: серверный (для приёмника) и
// клиентский (для источника). Соединение — взаимный TLS 1.3.
func cmdPKI(args []string) error {
	fl := flag.NewFlagSet("pki", flag.ExitOnError)
	dir := fl.String("dir", "./pki", "каталог для ключей и сертификатов")
	hosts := fl.String("hosts", "", "адреса ПРИЁМНИКА (SAN): IP и/или DNS через запятую (обязательно)")
	days := fl.Int("days", 730, "срок жизни серверного/клиентского сертификата, дней")
	_ = fl.Parse(args)
	if *hosts == "" {
		return errors.New("нужен -hosts: IP или DNS-имя приёмника, как вы будете к нему подключаться")
	}
	if err := os.MkdirAll(*dir, 0700); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(*dir, "ca.crt")); err == nil {
		return fmt.Errorf("%s/ca.crt уже существует — не перезаписываю", *dir)
	}

	var dns []string
	var ips []net.IP
	for _, h := range strings.Split(*hosts, ",") {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, h)
		}
	}

	now := time.Now()
	caKey, err := genKey()
	if err != nil {
		return err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "ferry-ca"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}
	if err := writePEM(filepath.Join(*dir, "ca.crt"), "CERTIFICATE", caDER, 0644); err != nil {
		return err
	}
	if err := writeKey(filepath.Join(*dir, "ca.key"), caKey); err != nil {
		return err
	}

	issue := func(name, cn string, eku x509.ExtKeyUsage, dnsNames []string, ipAddrs []net.IP) error {
		key, err := genKey()
		if err != nil {
			return err
		}
		tmpl := &x509.Certificate{
			SerialNumber: serial(),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    now.Add(-5 * time.Minute),
			NotAfter:     now.AddDate(0, 0, *days),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{eku},
			DNSNames:     dnsNames,
			IPAddresses:  ipAddrs,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			return err
		}
		if err := writePEM(filepath.Join(*dir, name+".crt"), "CERTIFICATE", der, 0644); err != nil {
			return err
		}
		return writeKey(filepath.Join(*dir, name+".key"), key)
	}
	if err := issue("server", "ferry-server", x509.ExtKeyUsageServerAuth, dns, ips); err != nil {
		return err
	}
	if err := issue("client", "ferry-client", x509.ExtKeyUsageClientAuth, nil, nil); err != nil {
		return err
	}

	fmt.Printf(`Ключи созданы в %s

Что куда копировать (каталог на каждой машине: %s, права 0700):
  ПРИЁМНИК (куда переезжаем):  ca.crt  server.crt  server.key
  ИСТОЧНИК (откуда переезжаем): ca.crt  client.crt  client.key

ca.key нужен только для выпуска новых сертификатов — после копирования
уберите его с обоих серверов (храните офлайн) или удалите.
`, *dir, defaultPKI)
	return nil
}

func loadCAPool(file string) (*x509.CertPool, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%s: не удалось разобрать CA", file)
	}
	return pool, nil
}

func serverTLS(dir string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"))
	if err != nil {
		return nil, fmt.Errorf("серверный сертификат: %w", err)
	}
	pool, err := loadCAPool(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func clientTLS(dir, serverName string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key"))
	if err != nil {
		return nil, fmt.Errorf("клиентский сертификат: %w", err)
	}
	pool, err := loadCAPool(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
