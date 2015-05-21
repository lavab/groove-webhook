# PGP manifest

Implementation of the PGP manifest encrypted email structure based on
[Mailpile's](https://www.mailpile.is/blog/2014-11-21_To_PGP_MIME_Or_Not.html)
article. This project contains two CLI programs to generate and parse sample
emails, that act as areference implementation for the standard.

## Manifest's structure

```js
{
    "version": "v1.0.0", // Manifest's structure version
    "headers": { // Headers to override
        "from": "rcp@example.org",
        "to": "snd@example.org",
        "subject": "Secret subject"
    },
    "parts": [
        // Definition of the body
        {
            "id": "body",
            "hash": "SHA256 hash of the unencrypted body",
            "content-type": "text/plain"
        },
        // Attachment definitions
        {
            "id": "randomstring1",
            "hash": "SHA256 hash of the unencrypted attachment",
            "content-type": "text/html",
            "filename": "test.html"
        }
    ]
}
```

## Email's structure

```
multipart/mixed
 |- multipart/alternative
     |- application/pgp-encrypted - Encrypted email body 
     |- text/html                 - HTML containg a link to a remote email reader
     |- text/plain                - Plaintext variant of the fallback message
 |- application/pgp-encrypted; filename=randomstring1.pgp - PGP-encrypted attachment
 |- application/x-pgp-manifest+json; filename=manifest.pgp - PGP-encrypted manifest
```