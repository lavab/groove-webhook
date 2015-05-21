package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/smtp"
	"strings"

	"github.com/alexcesaro/quotedprintable"
	r "github.com/dancannon/gorethink"
	"github.com/dchest/uniuri"
	"github.com/eaigner/dkim"
	"github.com/lavab/api/models"
	man "github.com/lavab/pgp-manifest-go"
	"github.com/namsral/flag"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

var (
	rethinkAddress  = flag.String("rethinkdb_address", "127.0.0.1:28015", "Address of the RethinkDB server")
	rethinkDatabase = flag.String("rethinkdb_database", "dev", "RethinkDB database to use")

	apiURL           = flag.String("api_url", "https://api.lavaboom.com", "URL of the API to use")
	forwardingServer = flag.String("forwarding_server", "127.0.0.1:25", "Address of the forwarding email server")
	dkimKey          = flag.String("dkim_key", "./dkim.key", "Path of the DKIM key")
	grooveAddress    = flag.String("groove_address", "", "Address of the Groove forwarding email")
	privateKey       = flag.String("private_key", "", "Private key to use for decryption")
)

func main() {
	keyFile, err := ioutil.ReadFile(*privateKey)
	if err != nil {
		log.Fatal(err)
	}

	key, err := ioutil.ReadFile(*dkimKey)
	if err != nil {
		log.Fatal(err)
	}

	dc, err := dkim.NewConf("lavaboom.com", "mailer")
	if err != nil {
		log.Fatal(err)
	}

	dk, err := dkim.New(dc, key)
	if err != nil {
		log.Fatal(err)
	}

	session, err := r.Connect(r.ConnectOpts{
		Address:  *rethinkAddress,
		Database: *rethinkDatabase,
	})
	if err != nil {
		log.Fatal(err)
	}

	keyring := openpgp.EntityList{}

	// This is just retarded
	parts := strings.Split(string(keyFile), "-----\n-----")
	for n, part := range parts {
		if n != 0 {
			part = "-----" + part
		}

		if n != len(parts)-1 {
			part += "-----"
		}

		k1, err := openpgp.ReadArmoredKeyRing(strings.NewReader(part))
		if err != nil {
			log.Fatal(err)
		}

		keyring = append(keyring, k1...)
	}

	http.HandleFunc("/incoming", func(w http.ResponseWriter, req *http.Request) {
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			log.Print(err)
			return
		}

		var event struct {
			Email   string `json:"email"`
			Account string `json:"account"`
		}
		if err := json.Unmarshal(body, &event); err != nil {
			http.Error(w, err.Error(), 500)
			log.Print(err)
			return
		}

		cursor, err := r.Table("emails").Get(event.Email).Run(session)
		if err != nil {
			http.Error(w, err.Error(), 500)
			log.Print(err)
			return
		}
		defer cursor.Close()
		var email *models.Email
		if err := cursor.One(&email); err != nil {
			http.Error(w, err.Error(), 500)
			log.Print(err)
			return
		}

		input := strings.NewReader(email.Body)
		result, err := armor.Decode(input)
		if err != nil {
			http.Error(w, err.Error(), 500)
			log.Print(err)
			return
		}
		md, err := openpgp.ReadMessage(result.Body, keyring, nil, nil)
		if err != nil {
			http.Error(w, err.Error(), 500)
			log.Print(err)
			return
		}
		contents, err := ioutil.ReadAll(md.UnverifiedBody)
		if err != nil {
			http.Error(w, err.Error(), 500)
			log.Print(err)
			return
		}

		input = strings.NewReader(email.Manifest)
		result, err = armor.Decode(input)
		if err != nil {
			http.Error(w, err.Error(), 500)
			log.Print(err)
			return
		}
		md, err = openpgp.ReadMessage(result.Body, keyring, nil, nil)
		if err != nil {
			http.Error(w, err.Error(), 500)
			log.Print(err)
			return
		}
		rawman, err := ioutil.ReadAll(md.UnverifiedBody)
		if err != nil {
			http.Error(w, err.Error(), 500)
			log.Print(err)
			return
		}
		manifest, err := man.Parse(rawman)
		if err != nil {
			http.Error(w, err.Error(), 500)
			log.Print(err)
			return
		}

		to := []string{}
		for _, x := range manifest.To {
			to = append(to, x.String())
		}

		var contentType string
		for _, part := range manifest.Parts {
			if part.ID == "body" {
				contentType = part.ContentType
			}
		}
		if contentType == "" {
			contentType = manifest.ContentType
		}

		m1 := strings.Replace(`From: `+manifest.From.String()+`
To: `+*grooveAddress+`
MIME-Version: 1.0
Message-ID: <`+uniuri.NewLen(32)+`@lavaboom.com>
Content-Type: `+contentType+`
Content-Transfer-Encoding: quoted-printable
Subject: `+quotedprintable.EncodeToString([]byte(manifest.Subject))+`

`+quotedprintable.EncodeToString(contents), "\n", "\r\n", -1)

		signed, err := dk.Sign([]byte(m1))
		if err != nil {
			http.Error(w, err.Error(), 500)
			log.Print(err)
			return
		}

		if err := smtp.SendMail(*forwardingServer, nil, manifest.From.Address, []string{*grooveAddress}, signed); err != nil {
			http.Error(w, err.Error(), 500)
			log.Print(err)
			return
		}

		log.Printf("Forwarded email from %s with title %s", manifest.From.String(), manifest.Subject)

	})

	http.ListenAndServe(":8000", nil)
}
