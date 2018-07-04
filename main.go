package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/providers/dns/cloudflare"
)

type myCFUser struct {
	email        string
	registration *acme.RegistrationResource
	key          crypto.PrivateKey
}

func (u myCFUser) GetEmail() string {
	return u.email
}

func (u myCFUser) GetRegistration() *acme.RegistrationResource {
	return u.registration
}

func (u myCFUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

func configPath() string {
	usr, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}

	return filepath.Join(usr.HomeDir, ".config", "tlsnow", "config.toml")
}

func main() {
	domain := flag.String("domain", "", "name of the domain to fetch")
	config := flag.String("config", configPath(), "where the config is")
	flag.Parse()

	if *domain == "" {
		log.Fatal("You have not given me a domain")
	}
	if *config == "" {
		log.Fatal("You have not given me configuration")
	}

	var cfg struct {
		Directory string
		Domains   []struct {
			Suffix  string
			Email   string
			CFEmail string
			CFKey   string
		}
	}

	cfg.Directory = "https://acme-staging.api.letsencrypt.org/directory"

	if _, err := toml.DecodeFile(*config, &cfg); err != nil {
		log.Fatal("You have failed to configure me")
	}

	sort.Slice(cfg.Domains, func(i, j int) bool { return len(cfg.Domains[i].Suffix) > len(cfg.Domains[j].Suffix) })

	var u *myCFUser
	var p *cloudflare.DNSProvider
	for _, v := range cfg.Domains {
		if strings.HasSuffix(*domain, v.Suffix) {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				log.Fatal(err)
			}
			u = &myCFUser{
				key:   k,
				email: v.Email,
			}

			p, err = cloudflare.NewDNSProviderCredentials(v.CFEmail, v.CFKey)
			if err != nil {
				log.Fatal(err)
			}

			break
		}
	}

	if u == nil {
		log.Fatal("No domain suffix")
	}
	if p == nil {
		log.Fatal("Cloudflare credentials ")
	}

	c, err := acme.NewClient(cfg.Directory, u, acme.RSA2048)
	if err != nil {
		log.Fatal(err)
	}

	u.registration, err = c.Register()
	if err != nil {
		log.Fatal(err)
	}

	err = c.AgreeToTOS()
	if err != nil {
		log.Fatal(err)
	}

	c.ExcludeChallenges([]acme.Challenge{acme.HTTP01, acme.TLSSNI01})

	if err := c.SetChallengeProvider(acme.DNS01, p); err != nil {
		log.Fatal(err)
	}

	certs, failures := c.ObtainCertificate([]string{*domain}, true, nil, false)
	if len(failures) > 0 {
		log.Fatal(failures[*domain])
	}

	keyFile, err := os.OpenFile("private.pem", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer keyFile.Close()

	var privateKey = &pem.Block{
		Type: "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(u.key.(*rsa.PrivateKey)),
	}

	if err := pem.Encode(keyFile, privateKey); err != nil {
		log.Fatal(err)
	}

	certFile, err := os.OpenFile("certificate.pem", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatal(err)
	}
	defer certFile.Close()

	var certificate = &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certs.Certificate,
	}
	if err := pem.Encode(certFile, certificate); err != nil {
		log.Fatal(err)
	}
}
