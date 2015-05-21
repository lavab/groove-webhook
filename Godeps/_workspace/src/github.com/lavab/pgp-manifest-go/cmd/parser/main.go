package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"path/filepath"
	"strings"

	"github.com/lavab/pgp-manifest-go"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

var (
	privateKey = flag.String("private-key", "", "Path to the PGP private key")
	password   = flag.String("password", "", "Password to the key")
	input      = flag.String("input", "", "Path to the input")
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	// Parse the flags
	flag.Parse()

	// Open the private key file
	privateKeyFile, err := os.Open(*privateKey)
	if err != nil {
		log.Fatal(err)
	}

	// Parse the file
	keyring, err := openpgp.ReadArmoredKeyRing(privateKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	for _, key := range keyring {
		if key.PrivateKey != nil && key.PrivateKey.Encrypted {
			if err := key.PrivateKey.Decrypt([]byte(*password)); err != nil {
				log.Fatal(err)
			}
		}

		if key.Subkeys != nil {
			for _, subkey := range key.Subkeys {
				if err := subkey.PrivateKey.Decrypt([]byte(*password)); err != nil {
					log.Fatal(err)
				}
			}
		}
	}

	// Open the email file
	emailFile, err := os.Open(*input)
	if err != nil {
		log.Fatal(err)
	}

	// Parse the email
	rootEmail, err := mail.ReadMessage(emailFile)
	if err != nil {
		log.Fatal(err)
	}

	// Print some data
	fmt.Print("Original headers:\n")
	for key, values := range rootEmail.Header {
		fmt.Printf("\t%s: %v\n", key, strings.Join(values, ", "))
	}

	// Get the Content-Type
	contentType := rootEmail.Header.Get("content-type")

	// Get the boundary
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		log.Fatal(err)
	}

	// Parse the body
	if !strings.HasPrefix(mediaType, "multipart/") {
		log.Fatal("Email isn't multipart")
	}

	// Find the manifest and decode it
	var man *manifest.Manifest

	rootBody, err := ioutil.ReadAll(rootEmail.Body)
	if err != nil {
		log.Fatal(err)
	}

	// Create a new multipart reader
	rootReader := multipart.NewReader(bytes.NewReader(rootBody), params["boundary"])
	for {
		part, err := rootReader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}

		// Add the header as this library is weird
		header := ""
		for key, values := range part.Header {
			header += key + ": " + strings.Join(values, ", ") + "\n"
		}

		body, err := ioutil.ReadAll(part)
		if err != nil {
			log.Fatal(err)
		}

		body = append([]byte(header+"\n\n"), body...)

		// Parse the email
		email, err := mail.ReadMessage(bytes.NewReader(body))
		if err != nil {
			log.Fatal(err)
		}

		mediaType, _, err := mime.ParseMediaType(email.Header.Get("content-type"))
		if err != nil {
			log.Fatal(err)
		}

		// We found the body
		if mediaType == "application/x-pgp-manifest+json" {
			block, err := armor.Decode(email.Body)
			if err != nil {
				log.Fatal(err)
			}

			body, err := ioutil.ReadAll(block.Body)
			if err != nil {
				log.Fatal(err)
			}

			md, err := openpgp.ReadMessage(bytes.NewReader(body), keyring, nil, nil)
			if err != nil {
				log.Fatal(err)
			}

			cleartext, err := ioutil.ReadAll(md.UnverifiedBody)
			if err != nil {
				log.Fatal(err)
			}

			m, err := manifest.Parse(cleartext)
			if err != nil {
				log.Fatal(err)
			}

			man = m

			// Show manifest data
			fmt.Print("Manifest headers:\n")
			for key, value := range man.Headers {
				fmt.Printf("\t%s: %s\n", key, value)
			}
			fmt.Print("Email parts in the manifest:\n")
			for _, part := range man.Parts {
				fmt.Printf("\t- Hash: %s\n", part.Hash)
				fmt.Printf("\t  ID: %s\n", part.ID)
				if part.Filename != "" {
					fmt.Printf("\t  Filename: %s\n", part.Filename)
				}
			}

			break
		}
	}

	rootReader = multipart.NewReader(bytes.NewReader(rootBody), params["boundary"])
	for {
		part, err := rootReader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}

		// Add the header as this library is weird
		header := ""
		for key, values := range part.Header {
			header += key + ": " + strings.Join(values, ", ") + "\n"
		}

		body, err := ioutil.ReadAll(part)
		if err != nil {
			log.Fatal(err)
		}

		body = append([]byte(header+"\n\n"), body...)

		// Parse the email
		email, err := mail.ReadMessage(bytes.NewReader(body))
		if err != nil {
			log.Fatal(err)
		}

		mediaType, params, err := mime.ParseMediaType(email.Header.Get("content-type"))
		if err != nil {
			log.Print(email.Header.Get("content-type"))
			log.Fatal(err)
		}

		if mediaType == "multipart/alternative" {
			bodyReader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
			for {
				part, err := bodyReader.NextPart()
				if err == io.EOF {
					break
				}
				if err != nil {
					log.Fatal(err)
				}

				// Add the header as this library is weird
				header := ""
				for key, values := range part.Header {
					header += key + ": " + strings.Join(values, ", ")
				}

				body, err := ioutil.ReadAll(part)
				if err != nil {
					log.Fatal(err)
				}

				body = append([]byte(header+"\n\n"), body...)

				// Parse the part
				email, err := mail.ReadMessage(bytes.NewReader(body))
				if err != nil {
					log.Fatal(err)
				}

				// Parse the content type
				mediaType, _, err := mime.ParseMediaType(email.Header.Get("content-type"))
				if err != nil {
					log.Fatal(err)
				}

				if mediaType == "application/pgp-encrypted" {
					block, err := armor.Decode(email.Body)
					if err != nil {
						log.Fatal(err)
					}

					body, err := ioutil.ReadAll(block.Body)
					if err != nil {
						log.Fatal(err)
					}

					md, err := openpgp.ReadMessage(
						bytes.NewReader(body),
						keyring,
						nil,
						nil,
					)
					if err != nil {
						log.Fatal(err)
					}

					cleartext, err := ioutil.ReadAll(md.UnverifiedBody)
					if err != nil {
						log.Fatal(err)
					}

					// Find body definition
					var bodyPart *manifest.Part
					for _, part := range man.Parts {
						if part.ID == "body" {
							bodyPart = part
						}
					}

					bodyHash := sha256.Sum256(cleartext)
					if bodyPart.Hash != hex.EncodeToString(bodyHash[:]) {
						log.Fatal("Email's body has an invalid checksum")
					}

					fmt.Print("Email's body:\n")
					for _, line := range strings.Split(string(cleartext), "\n") {
						fmt.Printf("\t%s\n", line)
					}
				}
			}
		} else if mediaType != "application/x-pgp-manifest+json" {
			contentDisposition := email.Header.Get("Content-Disposition")
			filenameIndex := strings.Index(contentDisposition, `filename="`)
			if filenameIndex == -1 {
				continue
			}

			postFilename := contentDisposition[filenameIndex+10:]
			quoteIndex := strings.Index(postFilename, `"`)
			if quoteIndex == -1 {
				continue
			}

			filename := postFilename[:quoteIndex]
			extension := filepath.Ext(filename)

			if extension != ".pgp" {
				continue
			}

			id := filename[:len(filename)-len(extension)]

			// look up filename against the deps
			var part *manifest.Part
			for _, part2 := range man.Parts {
				if part2.ID == id {
					part = part2
				}
			}

			if part == nil {
				continue
			}

			block, err := armor.Decode(email.Body)
			if err != nil {
				continue
			}

			body, err := ioutil.ReadAll(block.Body)
			if err != nil {
				log.Fatal(err)
			}

			md, err := openpgp.ReadMessage(bytes.NewReader(body), keyring, nil, nil)
			if err != nil {
				log.Fatal(err)
			}

			cleartext, err := ioutil.ReadAll(md.UnverifiedBody)
			if err != nil {
				log.Fatal(err)
			}

			bodyHash := sha256.Sum256(cleartext)
			if part.Hash != hex.EncodeToString(bodyHash[:]) {
				log.Fatal("Attachment's body has an invalid checksum")
			}

			fmt.Printf("Attachment %s:\n", id)
			fmt.Printf("\tFilename: %s\n", part.Filename)
			fmt.Printf("\tContent type: %s\n", part.ContentType)
			fmt.Print("\tBody:\n")
			for _, line := range strings.Split(string(cleartext), "\n") {
				fmt.Printf("\t\t%s\n", line)
			}
		}
	}
}
