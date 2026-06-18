package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
)

type HashAlgorithm string

const (
	HashMD5    HashAlgorithm = "md5"
	HashSHA1   HashAlgorithm = "sha1"
	HashSHA256 HashAlgorithm = "sha256"
	HashSHA512 HashAlgorithm = "sha512"
)

type FileHashResult struct {
	MD5    string `json:"md5,omitempty"`
	SHA1   string `json:"sha1,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	SHA512 string `json:"sha512,omitempty"`
}

type HashVerifyResult struct {
	Algorithm     HashAlgorithm `json:"algorithm"`
	CurrentHash   string        `json:"current_hash"`
	ExpectedHash  string        `json:"expected_hash"`
	IsMatch       bool          `json:"is_match"`
	IsTampered    bool          `json:"is_tampered"`
}

func computeFileHash(filePath string, algorithm HashAlgorithm) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var hasher hash.Hash
	switch algorithm {
	case HashMD5:
		hasher = md5.New()
	case HashSHA1:
		hasher = sha1.New()
	case HashSHA256:
		hasher = sha256.New()
	case HashSHA512:
		hasher = sha512.New()
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}

	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("failed to compute hash: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func ComputeAllHashes(filePath string) (*FileHashResult, error) {
	result := &FileHashResult{}

	info, err := os.Stat(filePath)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("cannot compute hash for directory")
	}

	md5Hash, err := computeFileHash(filePath, HashMD5)
	if err != nil {
		return nil, err
	}
	result.MD5 = md5Hash

	sha1Hash, err := computeFileHash(filePath, HashSHA1)
	if err != nil {
		return nil, err
	}
	result.SHA1 = sha1Hash

	sha256Hash, err := computeFileHash(filePath, HashSHA256)
	if err != nil {
		return nil, err
	}
	result.SHA256 = sha256Hash

	sha512Hash, err := computeFileHash(filePath, HashSHA512)
	if err != nil {
		return nil, err
	}
	result.SHA512 = sha512Hash

	return result, nil
}

func ComputeFileHash(filePath string, algorithm HashAlgorithm) (string, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("cannot compute hash for directory")
	}
	return computeFileHash(filePath, algorithm)
}

func VerifyFileHash(filePath string, algorithm HashAlgorithm, expectedHash string) (*HashVerifyResult, error) {
	currentHash, err := ComputeFileHash(filePath, algorithm)
	if err != nil {
		return nil, err
	}

	isMatch := currentHash == expectedHash
	return &HashVerifyResult{
		Algorithm:    algorithm,
		CurrentHash:  currentHash,
		ExpectedHash: expectedHash,
		IsMatch:      isMatch,
		IsTampered:   !isMatch,
	}, nil
}

func GetHashByAlgorithm(hashes *FileHashResult, algorithm HashAlgorithm) string {
	switch algorithm {
	case HashMD5:
		return hashes.MD5
	case HashSHA1:
		return hashes.SHA1
	case HashSHA256:
		return hashes.SHA256
	case HashSHA512:
		return hashes.SHA512
	default:
		return ""
	}
}
