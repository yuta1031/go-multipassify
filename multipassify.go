package gomultipassify

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

const BLOCK_SIZE = 16

type Multipassify struct {
	encryptionKey []byte
	signingKey    []byte
	Location      *time.Location
}

// creates a new Multipassify instance with the given secret
func NewMultipassify(secret string, location *time.Location) (*Multipassify, error) {
	if secret == "" {
		return nil, fmt.Errorf("invalid secret: secret must not be empty")
	}

	// Use the Multipass secret to derive two cryptographic keys,
	// one for encryption, one for signing
	hash := sha256.Sum256([]byte(secret))
	encryptionKey := hash[:BLOCK_SIZE]
	signingKey := hash[BLOCK_SIZE:32]

	return &Multipassify{
		encryptionKey: encryptionKey,
		signingKey:    signingKey,
		Location:      location,
	}, nil
}

// encodes the customer object into a Multipass token
func (m *Multipassify) Encode(obj map[string]any) (string, error) {
	if obj == nil {
		return "", fmt.Errorf("object must not be nil")
	}

	// Store the current time in ISO8601 format.
	// The token will only be valid for a small timeframe around this timestamp.
	if m.Location == nil {
		obj["created_at"] = time.Now().In(time.Local).Format(time.RFC3339)
	} else {
		obj["created_at"] = time.Now().In(m.Location).Format(time.RFC3339)
	}

	// Serialize the customer data to JSON and encrypt it
	jsonData, err := json.Marshal(obj)
	if err != nil {
		return "", fmt.Errorf("json marshal error: %w", err)
	}

	cipherText, err := m.encrypt(string(jsonData))
	if err != nil {
		return "", fmt.Errorf("encrypt error: %w", err)
	}

	// Create a signature (message authentication code) of the ciphertext
	// and encode everything using URL-safe Base64 (RFC 4648)
	signature := m.sign(cipherText)
	tokenBytes := append(cipherText, signature...)

	// Standard base64 encode, then convert to URL-safe
	token := base64.StdEncoding.EncodeToString(tokenBytes)
	token = base64URLSafe(token)

	return token, nil
}

// generates the Multipass login URL
func (m *Multipassify) GenerateUrl(obj map[string]any, domain string) (string, error) {
	if domain == "" {
		return "", fmt.Errorf("domain must not be empty")
	}

	token, err := m.Encode(obj)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("https://%s/account/login/multipass/%s", domain, token), nil
}

// creates an HMAC signature of the data
func (m *Multipassify) sign(data []byte) []byte {
	h := hmac.New(sha256.New, m.signingKey)
	h.Write(data)
	return h.Sum(nil)
}

// encrypts plaintext using AES-128-CBC with a random IV
func (m *Multipassify) encrypt(plaintext string) ([]byte, error) {
	// Use a random IV
	iv := make([]byte, BLOCK_SIZE)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("random IV generation error: %w", err)
	}

	block, err := aes.NewCipher(m.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("cipher creation error: %w", err)
	}

	cipher := cipher.NewCBCEncrypter(block, iv)
	plaintextBytes := []byte(plaintext)

	// Pad the plaintext to a multiple of block size (PKCS#7)
	padded := pkcs7Pad(plaintextBytes, BLOCK_SIZE)

	encrypted := make([]byte, len(padded))
	cipher.CryptBlocks(encrypted, padded)

	// Use IV as first block of ciphertext
	return append(iv, encrypted...), nil
}

// pads plaintext to a multiple of blockSize using PKCS#7
func pkcs7Pad(plaintext []byte, blockSize int) []byte {
	padding := blockSize - (len(plaintext) % blockSize)
	padBytes := make([]byte, padding)
	for i := range padding {
		padBytes[i] = byte(padding)
	}
	return append(plaintext, padBytes...)
}

// converts standard base64 to URL-safe base64 (RFC 4648)
func base64URLSafe(s string) string {
	// Replace + with -, / with _, and remove padding
	s = strings.NewReplacer("+", "-", "/", "_").Replace(s)
	// Remove padding (=)
	s = strings.TrimRight(s, "=")
	return s
}
