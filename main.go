package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"time"
)

func GenerateStartupCert(domain string, caCert *x509.Certificate, caPrivateKey *rsa.PrivateKey) (*tls.Certificate, error) {
	// 1. Generate private key for the server
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// 2. Set up certificate template
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add as Subject Alternative Name (SAN)
	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, domain)
	}

	// 3. Sign with CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &privKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
	}, nil
}

type ProxyRule struct {
	Path        string
	Destination *url.URL
	StaticText  string
}

func (p *ProxyRule) UnmarshalJSON(data []byte) error {
	type proxyRule ProxyRule
	value := struct {
		*proxyRule
		Destination string
	}{proxyRule: (*proxyRule)(p)}
	err := json.Unmarshal(data, &value)
	if err != nil {
		return err
	}
	if len(value.Destination) > 0 {
		p.Destination, err = url.Parse(value.Destination)
	}
	return err
}

func SetupRules(destHandler *http.ServeMux, rulesFile string, verbose bool) error {
	f, err := os.Open(rulesFile)
	if err != nil {
		return fmt.Errorf("could not open rules file: %w", err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	var rules []ProxyRule
	if err = dec.Decode(&rules); err != nil {
		return fmt.Errorf("failure decoding rules json: %w", err)
	}

	proxies := map[string]*httputil.ReverseProxy{}
	if len(rules) == 0 {
		return errors.New("No rules defined")
	}
	if verbose {
		log.Println("Setting up rules")
	}

	for _, rule := range rules {
		if rule.Destination == nil {
			if verbose {
				log.Printf("%s -> %s", rule.Path, strconv.Quote(rule.StaticText))
			}
			staticText := []byte(rule.StaticText)
			destHandler.HandleFunc(rule.Path, func(w http.ResponseWriter, r *http.Request) {
				w.Write(staticText)
			})
			continue
		}
		if verbose {
			log.Printf("%s -> %s", rule.Path, rule.Destination.String())
		}
		proxy := proxies[rule.Destination.String()]
		if proxy == nil {
			proxy = httputil.NewSingleHostReverseProxy(rule.Destination)
			proxies[rule.Destination.String()] = proxy
		}
		destHandler.Handle(rule.Path, proxy)
	}
	return nil
}

func main() {
	hostnameFlag := flag.String("hostname", "", "The host name to server TLS for")
	pemFlag := flag.String("pemfile", "ca.pem", "The file where the certificate and private key is stored for the CA")
	portNumberFlag := flag.Int("port", 443, "The port to listen on")
	rulesFlag := flag.String("rules", "rules.json", "What file to read the proxy rules from")
	verboseFlag := flag.Bool("verbose", false, "Verbose output")
	flag.Parse()
	if *hostnameFlag == "" {
		log.Fatal("No host name set. Use -hostname <whatever>")
	}
	if *verboseFlag {
		log.Print("Generating certificate for ", *hostnameFlag, " using CA in ", *pemFlag)
	}
	caTLS, err := tls.LoadX509KeyPair(*pemFlag, *pemFlag)
	if err != nil {
		log.Fatal("Could not load CA file: ", err)
	}
	caCert, err := x509.ParseCertificate(caTLS.Certificate[0])
	if err != nil {
		log.Fatal("Failed to parse CA certificate: ", err)
	}
	caPrivateKey := caTLS.PrivateKey.(*rsa.PrivateKey)

	serverCert, err := GenerateStartupCert(*hostnameFlag, caCert, caPrivateKey)
	if err != nil {
		log.Fatal("Could not generate certificate for ", *hostnameFlag, ": ", err)
	}

	handler := http.NewServeMux()
	err = SetupRules(handler, *rulesFlag, *verboseFlag)
	if err != nil {
		log.Fatal("Could not set up proxy rules: ", err)
	}

	log.Printf("Listening on port %d", *portNumberFlag)
	server := &http.Server{
		Addr: fmt.Sprintf(":%d", *portNumberFlag),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*serverCert},
		},
		Handler: handler,
	}

	log.Fatal(server.ListenAndServeTLS("", ""))
}
