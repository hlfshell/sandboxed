package sandboxed

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

const (
	headerSize      = 64
	identifierSize  = 16
	formatVersion   = 1
	flagManifestAES = 1
	maxManifestSize = 64 * 1024 * 1024
)

var fileSignature = [9]byte{'S', 'A', 'N', 'D', 'B', 'O', 'X', 'E', 'D'}

type header struct {
	Flags       uint16
	ChunkSize   uint32
	ManifestLen uint64
	Nonce       [12]byte
}

type manifest struct {
	Entries map[string]entry `json:"entries"`
}

type entry struct {
	Directory bool    `json:"directory,omitempty"`
	Size      int64   `json:"size,omitempty"`
	Key       []byte  `json:"key,omitempty"`
	Chunks    []chunk `json:"chunks,omitempty"`
}

type chunk struct {
	Offset int64 `json:"offset"`
	Size   int   `json:"size"`
}

func encodeHeader(value header) []byte {
	buffer := make([]byte, headerSize)
	identifier := encodeIdentifier(value.Flags)
	copy(buffer[:identifierSize], identifier[:])
	binary.BigEndian.PutUint32(buffer[16:20], value.ChunkSize)
	binary.BigEndian.PutUint64(buffer[20:28], value.ManifestLen)
	copy(buffer[28:40], value.Nonce[:])
	return buffer
}

func encodeIdentifier(flags uint16) [identifierSize]byte {
	var identifier [identifierSize]byte
	copy(identifier[:9], fileSignature[:])
	binary.BigEndian.PutUint16(identifier[9:11], flags)
	// Bytes 11 through 13 are reserved for future format configuration.
	binary.BigEndian.PutUint16(identifier[14:16], formatVersion)
	return identifier
}

func decodeHeader(buffer []byte) (header, error) {
	if len(buffer) != headerSize || string(buffer[:9]) != string(fileSignature[:]) {
		return header{}, fmt.Errorf("invalid store header")
	}
	if buffer[11] != 0 || buffer[12] != 0 || buffer[13] != 0 {
		return header{}, fmt.Errorf("unsupported reserved identifier bits")
	}
	if binary.BigEndian.Uint16(buffer[14:16]) != formatVersion {
		return header{}, fmt.Errorf("unsupported store version %d", binary.BigEndian.Uint16(buffer[14:16]))
	}
	value := header{
		Flags:       binary.BigEndian.Uint16(buffer[9:11]),
		ChunkSize:   binary.BigEndian.Uint32(buffer[16:20]),
		ManifestLen: binary.BigEndian.Uint64(buffer[20:28]),
	}
	copy(value.Nonce[:], buffer[28:40])
	if value.Flags & ^uint16(flagManifestAES) != 0 {
		return header{}, fmt.Errorf("unsupported store flags")
	}
	if value.ChunkSize < minimumChunkSize || value.ChunkSize > maximumChunkSize {
		return header{}, fmt.Errorf("invalid chunk size %d", value.ChunkSize)
	}
	return value, nil
}

func marshalManifest(value manifest, key []byte, chunkSize int) (header, []byte, error) {
	plain, err := json.Marshal(value)
	if err != nil {
		return header{}, nil, err
	}
	result := header{ChunkSize: uint32(chunkSize)}
	encoded := plain
	if len(key) != 0 {
		block, err := aes.NewCipher(key)
		if err != nil {
			return header{}, nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return header{}, nil, err
		}
		if _, err := io.ReadFull(rand.Reader, result.Nonce[:]); err != nil {
			return header{}, nil, err
		}
		result.Flags = flagManifestAES
		identifier := encodeIdentifier(result.Flags)
		encoded = aead.Seal(nil, result.Nonce[:], plain, identifier[:])
	}
	result.ManifestLen = uint64(len(encoded))
	return result, encoded, nil
}

func unmarshalManifest(value header, encoded []byte, key []byte) (manifest, error) {
	plain := encoded
	if value.Flags&flagManifestAES != 0 {
		if len(key) != 32 {
			return manifest{}, fmt.Errorf("store is encrypted: a 32-byte key is required")
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return manifest{}, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return manifest{}, err
		}
		identifier := encodeIdentifier(value.Flags)
		plain, err = aead.Open(nil, value.Nonce[:], encoded, identifier[:])
		if err != nil {
			return manifest{}, fmt.Errorf("decrypt store manifest: %w", err)
		}
	}
	var result manifest
	if err := json.Unmarshal(plain, &result); err != nil {
		return manifest{}, fmt.Errorf("decode store manifest: %w", err)
	}
	if result.Entries == nil {
		return manifest{}, fmt.Errorf("store manifest has no entries")
	}
	return result, nil
}

func fileAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func chunkNonce(key []byte, position uint64) []byte {
	hash := hmac.New(sha256.New, key)
	var buffer [8]byte
	binary.BigEndian.PutUint64(buffer[:], position)
	hash.Write(buffer[:])
	return hash.Sum(nil)[:12]
}

func chunkAdditionalData(position uint64, size int) []byte {
	var buffer [16]byte
	binary.BigEndian.PutUint64(buffer[:8], position)
	binary.BigEndian.PutUint64(buffer[8:], uint64(size))
	return buffer[:]
}
