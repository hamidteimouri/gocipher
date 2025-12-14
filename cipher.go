package gocipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
)

type Cipher struct {
	pepper []byte
	prefix string
}

func NewCipher(prefix, pepper string) (*Cipher, error) {
	if len(pepper) < 16 {
		return nil, errors.New("pepper too short (min 16 chars)")
	}
	if len(pepper) > 64 {
		return nil, errors.New("pepper too large (max 64 chars)")
	}
	if len(prefix) < 1 {
		return nil, errors.New("prefix too short (min 1 chars)")
	}
	if len(prefix) > 32 {
		return nil, errors.New("prefix too large (max 32 chars)")
	}
	return &Cipher{
		pepper: []byte(pepper),
		prefix: prefix,
	}, nil
}

// HKDF(salt || pepper) -> 32 bytes
func (c *Cipher) deriveKey(salt string) ([]byte, error) {
	if salt == "" {
		return nil, errors.New("salt is required")
	}

	// جلوگیری از تغییر salt اصلی
	ikm := make([]byte, 0, len(salt)+len(c.pepper))
	ikm = append(ikm, []byte(salt)...)
	ikm = append(ikm, c.pepper...)

	info := []byte("htsec-v1")

	kdf := hkdf.New(sha256.New, ikm, nil, info)
	key := make([]byte, 32)

	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("hkdf derive error: %w", err)
	}
	return key, nil
}

// Encrypt returns: htsec|base64(nonce|ciphertext)
func (c *Cipher) Encrypt(plain string, salt string) (string, error) {
	key, err := c.deriveKey(salt)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to read nonce: %w", err)
	}

	ct := gcm.Seal(nil, nonce, []byte(plain), nil)
	out := append(nonce, ct...)

	return c.prefix + base64.StdEncoding.EncodeToString(out), nil
}

func (c *Cipher) Decrypt(enc string, salt string) (string, error) {
	if len(enc) <= len(c.prefix) || enc[:len(c.prefix)] != c.prefix {
		return "", errors.New("invalid prefix")
	}

	payload := enc[len(c.prefix):]
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("failed to base64 decode: %w", err)
	}

	key, err := c.deriveKey(salt)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ct := raw[:nonceSize], raw[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}

	return string(plain), nil
}
