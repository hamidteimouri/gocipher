# gocipher

`gocipher` is a Go package for **secure symmetric encryption** designed for production use in backend services, microservices, and fintech applications.

It combines **AES-256-GCM** with **HKDF-SHA256**, and follows the pattern of **salt (public) + pepper (secret)** for key derivation.

---

## Features

* 🔐 AES-256-GCM (authenticated encryption)
* 🧂 Supports a `salt` parameter (public per entity)
* 🌶️ Uses a server-side `pepper` (secret)
* 🔄 Pepper rotation support
* 🧩 Suitable for microservices and multi-tenant systems
* 🏷️ Versioned ciphertext (`prefix`)

---

## Security Notes

> This package is **server-side only**. Never use it in client applications (browser, mobile, or desktop), because `pepper` is a secret.

* `salt` is public and can be stored in a database.
* `pepper` must remain secret and should be injected via environment variables, vault, or CI/CD secrets.
* Security depends on the secrecy of `pepper`, not `salt`.

---

## Installation

```bash
go get github.com/hamidteimouri/gocipher
```

---

## Usage

### Creating a Cipher instance

```go
import (
    "github.com/hamidteimouri/gocipher"
    "os"
    "log"
)

pepper := os.Getenv("GO_CIPHER_PEPPER")
cp, err := gocipher.NewCipher("htsec|", pepper)
if err != nil {
    log.Fatal(err)
}
```

### Encrypt

```go
salt := "user123" // could also be tenantID, uuid, etc.
enc, err := cp.Encrypt("my secret data", salt)
if err != nil {
    log.Fatal(err)
}
```

Output format:

```
htsec|base64(nonce|ciphertext)
```

### Decrypt

```go
plain, err := cp.Decrypt(enc, salt)
if err != nil {
    log.Fatal(err)
}
```

---

## Salt Guidelines

* Salt should be unique per entity.
* Avoid predictable or fixed values.

Recommended examples:

* UUIDv4
* userID or tenantID
* invoiceID
* Random bytes (16-32 bytes)

---

## Pepper Rotation

* Use only the newest pepper for encryption.
* Try all valid peppers for decryption if rotation occurred.

```go
peppers := []string{pepperV2, pepperV1}
```

---

## Versioning

* Ciphertext should include a prefix, e.g., `htsec|v1|` to allow future algorithm updates.

---

## License

MIT

---

## Contribution

Pull requests and issues are welcome. Please provide detailed explanations for security-related changes.
