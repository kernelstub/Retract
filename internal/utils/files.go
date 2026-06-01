package utils

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func Hashes(data []byte) (string, string, string, string) {
	hMD5 := md5.Sum(data)
	hSHA1 := sha1.Sum(data)
	hSHA256 := sha256.Sum256(data)
	hSHA512 := sha512.Sum512(data)
	return hex.EncodeToString(hMD5[:]), hex.EncodeToString(hSHA1[:]), hex.EncodeToString(hSHA256[:]), hex.EncodeToString(hSHA512[:])
}

func EnsureDir(path string) error {
	return os.MkdirAll(path, 0o755)
}

func SafeJoin(base string, elems ...string) (string, error) {
	joined := filepath.Join(append([]string{base}, elems...)...)
	cleanBase, err := filepath.Abs(base)
	if err != nil {
		return "", err
	}
	cleanJoined, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	if cleanJoined != cleanBase && !strings.HasPrefix(cleanJoined, cleanBase+string(os.PathSeparator)) {
		return "", fmt.Errorf("unsafe output path %q", joined)
	}
	return cleanJoined, nil
}

func Hex32(v uint32) string { return fmt.Sprintf("0x%08x", v) }
func Hex64(v uint64) string { return fmt.Sprintf("0x%016x", v) }
