package manifest

import (
	"encoding/json"
	"net/mail"
	"strings"
)

func Parse(input []byte) (*Manifest, error) {
	// Prepare a new manifest struct
	var manifest Manifest

	// Decode the input
	if err := json.Unmarshal(input, &manifest); err != nil {
		return nil, err
	}

	// Transform headers
	for key, value := range manifest.Headers {
		delete(manifest.Headers, key)
		manifest.Headers[strings.ToLower(key)] = value
	}

	// Move the headers into the main manifest struct
	if val, ok := manifest.Headers["from"]; ok {
		if v2, ok := val.(string); ok && v2 != "" {
			from, err := mail.ParseAddress(v2)
			if err != nil {
				return nil, err
			}

			manifest.From = from
		}
	}
	if val, ok := manifest.Headers["to"]; ok {
		if v2, ok := val.([]interface{}); ok {
			to := []*mail.Address{}

			for _, v3 := range v2 {
				if v4, ok := v3.(string); ok {
					v5, err := mail.ParseAddress(v4)
					if err != nil {
						return nil, err
					}

					to = append(to, v5)
				}
			}

			manifest.To = to
		} else if v2, ok := val.(string); ok && v2 != "" {
			to, err := mail.ParseAddressList(v2)
			if err != nil {
				return nil, err
			}

			manifest.To = to
		}
	}
	if val, ok := manifest.Headers["cc"]; ok {
		if v2, ok := val.([]interface{}); ok {
			cc := []*mail.Address{}

			for _, v3 := range v2 {
				if v4, ok := v3.(string); ok {
					v5, err := mail.ParseAddress(v4)
					if err != nil {
						return nil, err
					}

					cc = append(cc, v5)
				}
			}

			manifest.CC = cc
		} else if v2, ok := val.(string); ok && v2 != "" {
			cc, err := mail.ParseAddressList(v2)
			if err != nil {
				return nil, err
			}

			manifest.CC = cc
		}
	}
	if val, ok := manifest.Headers["subject"]; ok {
		if v2, ok := val.(string); ok {
			manifest.Subject = v2
		}
	}
	if val, ok := manifest.Headers["content-type"]; ok {
		if v2, ok := val.(string); ok {
			manifest.ContentType = v2
		}
	}

	return &manifest, nil
}
