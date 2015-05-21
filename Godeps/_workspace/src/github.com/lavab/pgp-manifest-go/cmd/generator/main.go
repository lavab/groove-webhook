package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/blang/semver"
	"github.com/dchest/uniuri"
	"github.com/lavab/pgp-manifest-go"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

const emailTemplate = `From: {{.From}}
To: {{.To}}{{if ne .CC "" }}
Cc: {{.CC}}{{end}}
Subject: Encrypted message ({{.ID}})
Content-Type: multipart/mixed; boundary="{{.Boundary1}}"

--{{.Boundary1}}
Content-Type: multipart/alternative; boundary="{{.Boundary2}}"

--{{.Boundary2}}
Content-Type: application/pgp-encrypted

{{.Body}}
--{{.Boundary2}}
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body>
<p>This is an encrypted email, <a href="http://example.org/#id">
open it here if you email client doesn't support PGP manifests
</a></p>
</body>
</html>

--{{.Boundary2}}
Content-Type: text/plain; charset="UTF-8"

This is an encrypted email, open it here if your email client
doesn't support PGP manifests:

http://example.org/#id
--{{.Boundary2}}--
{{range .Attachments}}--{{$.Boundary1}}
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="{{.ID}}.pgp"

{{.Body}}
{{end}}
--{{.Boundary1}}
Content-Type: application/x-pgp-manifest+json
Content-Disposition: attachment; filename="manifest.pgp"

{{.Manifest}}
--{{.Boundary1}}--
`

type templateInput struct {
	From        string
	To          string
	CC          string
	ID          string
	Body        string
	Boundary1   string
	Boundary2   string
	Manifest    string
	Attachments []*templateAttachment
}

type templateAttachment struct {
	ID   string
	Body string
}

var (
	publicKey       = flag.String("public-key", "", "Path to the PGP private key")
	from            = flag.String("from", "sender@example.org", "Sender of the email")
	to              = flag.String("to", "recipient@example.org", "Recipient of the email")
	cc              = flag.String("cc", "", "Carbon copy recipient")
	subject         = flag.String("subject", "Very secret email", "Subject of the email")
	bodyPath        = flag.String("body-path", "", "Path to the file containing the body text")
	attachmentPaths = flag.String("attachments", "", "Comma-seperated list of paths to attachments")
)

func encryptAndArmor(input []byte, to []*openpgp.Entity) ([]byte, error) {
	encOutput := &bytes.Buffer{}
	encInput, err := openpgp.Encrypt(encOutput, to, nil, nil, nil)
	if err != nil {
		return nil, err
	}

	if _, err = encInput.Write(input); err != nil {
		return nil, err
	}

	if err = encInput.Close(); err != nil {
		return nil, err
	}

	armOutput := &bytes.Buffer{}
	armInput, err := armor.Encode(armOutput, "PGP MESSAGE", nil)
	if err != nil {
		return nil, err
	}

	if _, err = io.Copy(armInput, encOutput); err != nil {
		return nil, err
	}

	if err = armInput.Close(); err != nil {
		return nil, err
	}

	return armOutput.Bytes(), nil
}

func main() {
	// Parse the flags
	flag.Parse()

	// Put data into the template
	tmpl := template.Must(template.New("email").Parse(emailTemplate))

	// Open the public key
	publicKeyFile, err := os.Open(*publicKey)
	if err != nil {
		log.Fatal(err)
	}

	// Parse it
	entityList, err := openpgp.ReadArmoredKeyRing(publicKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	// Public key should be the first entity
	publicKey := entityList[0]

	// Prepare the template imput
	input := &templateInput{
		ID:        uniuri.New(),
		From:      *from,
		To:        *to,
		CC:        *cc,
		Boundary1: uniuri.New(),
		Boundary2: uniuri.New(),
	}

	// Prepare a new manifest
	man := &manifest.Manifest{
		Version: semver.Version{1, 0, 0, nil, nil},
		From:    *from,
		To:      *to,
		CC:      *cc,
		Subject: *subject,
		Parts:   []*manifest.Part{},
	}

	// Read the body file
	body, err := ioutil.ReadFile(*bodyPath)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt the body
	armoredBody, err := encryptAndArmor(body, []*openpgp.Entity{publicKey})
	if err != nil {
		log.Fatal(err)
	}

	// Calculate the hashsum of the body
	rawBodyHash := sha256.Sum256(body)

	// Hex it
	bodyHash := hex.EncodeToString(rawBodyHash[:])

	// Add body info to the parts
	man.Parts = append(man.Parts, &manifest.Part{
		ID:   "body",
		Hash: bodyHash,
	})

	// Put the body into the template input
	input.Body = string(armoredBody)

	if *attachmentPaths != "" {
		// Prepare the result attachments array
		attachments := []*templateAttachment{}

		// Read and encrypt all attachments
		attachmentParts := strings.Split(*attachmentPaths, ",")
		for _, part := range attachmentParts {
			// Read the file
			file, err := ioutil.ReadFile(part)
			if err != nil {
				log.Fatal(err)
			}

			// Encrypt the file
			armoredFile, err := encryptAndArmor(file, []*openpgp.Entity{publicKey})
			if err != nil {
				log.Fatal(err)
			}

			// Generate a ID for the attachment
			id := uniuri.New()

			// Put the result into the attachments slice
			attachments = append(attachments, &templateAttachment{
				ID:   id,
				Body: string(armoredFile),
			})

			// Calculate the hashsum of the file
			rawHash := sha256.Sum256(file)

			// Hex it
			hash := hex.EncodeToString(rawHash[:])

			// Put the attachment info into the manifest
			man.Parts = append(man.Parts, &manifest.Part{
				ID:          id,
				Hash:        hash,
				Filename:    filepath.Base(part),
				ContentType: mime.TypeByExtension(filepath.Ext(part)),
				Size:        len(file),
			})
		}

		// Put attachments into the template input
		input.Attachments = attachments
	}

	// Encode the manifest
	encodedManifest, err := manifest.Write(man)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt the manifest
	encryptedManifest, err := encryptAndArmor(encodedManifest, []*openpgp.Entity{publicKey})
	input.Manifest = string(encryptedManifest)

	// Execute the template input
	if err = tmpl.Execute(os.Stdout, input); err != nil {
		log.Fatal(err)
	}
}
