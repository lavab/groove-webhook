package manifest

import (
	"github.com/blang/semver"
	"net/mail"
)

type Manifest struct {
	Version semver.Version `json:"version"`

	From        *mail.Address   `json:"-"`
	To          []*mail.Address `json:"-"`
	CC          []*mail.Address `json:"-"`
	Subject     string          `json:"-"`
	ContentType string          `json:"-"`

	Headers map[string]interface{} `json:"headers"`
	Parts   []*Part                `json:"parts,omitempty"`
}

type Part struct {
	Hash        string `json:"hash"`
	Size        int    `json:"size"`
	ID          string `json:"id"`
	ContentType string `json:"content_type"`
	Filename    string `json:"filename,omitempty"`
}
