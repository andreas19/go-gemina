// Package gemina provides an implementation of the Gemina specification
// for data encryption.
//
// See section "Description" in the specification:
// https://github.com/andreas19/gemina-spec#description
package gemina

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

const (
	PackageVersion = "0.2.0"
)

type Version byte

const (
	Version1    Version = 0x8a
	Version2    Version = 0x8b
	Version3    Version = 0x8c
	Version4    Version = 0x8d
	Version5    Version = 0x8e
	block_len           = aes.BlockSize // 16 bytes
	version_len         = 1             // byte
	mac_len             = sha256.Size   // bytes
	salt_len            = 16            // bytes
)

var (
	ErrUnknownVersion = errors.New("gemina: unknown version")
	ErrDecryption     = errors.New("gemina: cannot decrypt data")
)

type prop struct {
	enc_key_len int
	mac_key_len int
	iterations  int
}

var props map[Version]prop

func init() {
	props = make(map[Version]prop, 4)
	props[Version1] = prop{16, 16, 100_000}
	props[Version2] = prop{16, 32, 100_000}
	props[Version3] = prop{24, 32, 100_000}
	props[Version4] = prop{32, 32, 100_000}
	props[Version5] = prop{32, 32, 600_000}
}

// CreateSecretKey creates a secret key that can be used with the
// functions EncryptWithKey(), DecryptWithKey(), and VerifyWithKey().
func CreateSecretKey(version Version) ([]byte, error) {
	p, ok := props[version]
	if !ok {
		return nil, ErrUnknownVersion
	}
	key_len := p.enc_key_len + p.mac_key_len
	b := make([]byte, key_len)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("gemina: %v", err)
	}
	return b, nil
}

// EncryptWithKey encrypts data with the given secret key and version.
func EncryptWithKey(key, data []byte, version Version) ([]byte, error) {
	return encrypt(key, data, []byte{}, version)
}

// DecryptWithKey decrypts data with the given secret key.
func DecryptWithKey(key, data []byte) ([]byte, error) {
	return decrypt(key, data, 0)
}

// VerifyWithKey verifies data with the given secret key.
func VerifyWithKey(key, data []byte) bool {
	return verify(key, data, false)
}

// EncryptWithPassword encrypts data with the given password and version.
func EncryptWithPassword(password, data []byte, version Version) ([]byte, error) {
	key, salt, err := deriveKey(password, nil, version)
	if err != nil {
		return nil, err
	}
	return encrypt(key, data, salt, version)
}

// DecryptWithPassword decrypts data with the given password.
func DecryptWithPassword(password, data []byte) ([]byte, error) {
	key, _, err := deriveKey(password, data[1:1+salt_len], Version(data[0]))
	if err != nil {
		return nil, err
	}
	return decrypt(key, data, salt_len)
}

// VerifyWithPasswordverifies verifies data with the given password.
func VerifyWithPassword(password, data []byte) bool {
	key, _, err := deriveKey(password, data[1:1+salt_len], Version(data[0]))
	if err != nil {
		return false
	}
	return verify(key, data, true)
}

func splitKey(key []byte, version Version) ([]byte, []byte, error) {
	p, ok := props[version]
	if !ok {
		return nil, nil, ErrUnknownVersion
	}
	return key[:p.enc_key_len], key[p.enc_key_len:], nil
}

func encrypt(key, data, salt []byte, version Version) ([]byte, error) {
	enc_key, mac_key, err := splitKey(key, version)
	if err != nil {
		return nil, err
	}
	pad_len := block_len - len(data)%block_len
	if pad_len == 0 {
		pad_len = block_len
	}
	padding := make([]byte, pad_len)
	pad_value := byte(pad_len)
	for i := 0; i < pad_len; i++ {
		padding[i] = pad_value
	}
	data = append(data, padding...)
	cat_data := make([]byte, version_len+len(salt)+block_len+len(data))
	cat_data[0] = byte(version)
	copy(cat_data[1:2+len(salt)], salt)
	iv := cat_data[1+len(salt) : 1+len(salt)+block_len]
	_, err = rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("gemina: %v", err)
	}
	block, err := aes.NewCipher(enc_key)
	if err != nil {
		return nil, fmt.Errorf("gemina: %v", err)
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cat_data[version_len+len(salt)+block_len:], data)
	mac := hmac.New(sha256.New, mac_key)
	mac.Write(cat_data)
	return append(cat_data, mac.Sum(nil)...), nil
}

func decrypt(key, data []byte, salt_len int) ([]byte, error) {
	if !checkData(data, salt_len != 0) {
		return nil, ErrDecryption
	}
	enc_key, mac_key, err := splitKey(key, Version(data[0]))
	if err != nil {
		return nil, err
	}
	mac := data[len(data)-mac_len:]
	new_mac := hmac.New(sha256.New, mac_key)
	new_mac.Write(data[:len(data)-mac_len])
	if !hmac.Equal(mac, new_mac.Sum(nil)) {
		return nil, ErrDecryption
	}
	iv := data[1+salt_len : 1+salt_len+block_len]
	data = data[1+salt_len+block_len : len(data)-mac_len]
	block, err := aes.NewCipher(enc_key)
	if err != nil {
		return nil, fmt.Errorf("gemina: %v", err)
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)
	pad_value := data[len(data)-1]
	if pad_value < 1 || pad_value > 16 {
		return nil, ErrDecryption
	}
	for i := len(data) - 1; i >= len(data)-int(pad_value); i-- {
		if data[i] != pad_value {
			return nil, ErrDecryption
		}
	}
	return data[:len(data)-int(pad_value)], nil
}

func verify(key, data []byte, with_salt bool) bool {
	if !checkData(data, with_salt) {
		return false
	}
	_, mac_key, err := splitKey(key, Version(data[0]))
	if err != nil {
		return false
	}
	mac := data[len(data)-mac_len:]
	new_mac := hmac.New(sha256.New, mac_key)
	new_mac.Write(data[:len(data)-mac_len])
	return hmac.Equal(mac, new_mac.Sum(nil))
}

func deriveKey(password, salt []byte, version Version) ([]byte, []byte, error) {
	p, ok := props[version]
	if !ok {
		return nil, nil, ErrUnknownVersion
	}
	if salt == nil {
		salt = make([]byte, salt_len)
		_, err := rand.Read(salt)
		if err != nil {
			return nil, nil, fmt.Errorf("gemina: %v", err)
		}
	}
	key_len := p.enc_key_len + p.mac_key_len
	key := pbkdf2.Key(password, salt, p.iterations, key_len, sha256.New)
	return key, salt, nil
}

func checkData(data []byte, with_salt bool) bool {
	min_len := version_len + 2*block_len + mac_len
	if with_salt {
		min_len += salt_len
	}
	return min_len <= len(data)
}
