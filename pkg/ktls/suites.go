package ktls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"hash"
	"slices"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/cryptobyte"
)

// Values from include/uapi/linux/tls.h.
const (
	kernelTLS13Version           = 0x0304 // TLS_1_3_VERSION
	kernelCipherAESGCM128        = 51     // TLS_CIPHER_AES_GCM_128
	kernelCipherAESGCM256        = 52     // TLS_CIPHER_AES_GCM_256
	kernelCipherChaCha20Poly1305 = 54     // TLS_CIPHER_CHACHA20_POLY1305
)

// tls13NonceLen is iv_length for every TLS 1.3 suite (RFC 8446 section 5.3).
const tls13NonceLen = 12

// cryptoInfoHeader is struct tls_crypto_info: fields in host byte order.
//
// Byte order, for all crypto_info structs below: they are serialized with
// binary.NativeEndian, which only affects these two uint16 header fields
// (the kernel reads them as native integers, so s390x and other big-endian
// targets work too). Every other field is a byte array copied verbatim;
// RecSeq is filled big-endian on purpose, as it is the on-wire TLS sequence
// number. The structs have no padding (every field after the header is a byte
// array), so binary.Append's packed layout matches the C layout.
type cryptoInfoHeader struct {
	Version    uint16
	CipherType uint16
}

// The kernel splits the 12-byte TLS 1.3 nonce base into "salt" (the leading
// bytes) and "iv" (the rest); ChaCha20-Poly1305 has no salt. RecSeq is the
// big-endian sequence number of the next record.

type cryptoInfoAESGCM128 struct { // struct tls12_crypto_info_aes_gcm_128
	cryptoInfoHeader

	IV     [8]byte
	Key    [16]byte
	Salt   [4]byte
	RecSeq [8]byte
}

type cryptoInfoAESGCM256 struct { // struct tls12_crypto_info_aes_gcm_256
	cryptoInfoHeader

	IV     [8]byte
	Key    [32]byte
	Salt   [4]byte
	RecSeq [8]byte
}

type cryptoInfoChaCha20Poly1305 struct { // struct tls12_crypto_info_chacha20_poly1305
	cryptoInfoHeader

	IV     [12]byte
	Key    [32]byte
	RecSeq [8]byte
}

// suiteSpec describes a TLS 1.3 cipher suite the kernel can take over.
type suiteSpec struct {
	keyLen  int
	hash    func() hash.Hash
	newAEAD func(key []byte) (cipher.AEAD, error)
	// cryptoInfo packs the setsockopt(SOL_TLS, TLS_TX/TLS_RX) argument.
	cryptoInfo func(key, nonceBase []byte, seq uint64) ([]byte, error)
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

// lookupSuite covers every TLS 1.3 suite crypto/tls negotiates.
//
//nolint:mnd // key sizes are fixed by each suite
func lookupSuite(id uint16) (suiteSpec, bool) {
	switch id {
	case tls.TLS_AES_128_GCM_SHA256:
		return suiteSpec{
			keyLen: 16, hash: sha256.New, newAEAD: newAESGCM,
			cryptoInfo: func(key, nonceBase []byte, seq uint64) ([]byte, error) {
				info := cryptoInfoAESGCM128{cryptoInfoHeader: cryptoInfoHeader{kernelTLS13Version, kernelCipherAESGCM128}}
				copy(info.Salt[:], nonceBase[:4])
				copy(info.IV[:], nonceBase[4:])
				copy(info.Key[:], key)
				binary.BigEndian.PutUint64(info.RecSeq[:], seq)

				return binary.Append(nil, binary.NativeEndian, &info)
			},
		}, true
	case tls.TLS_AES_256_GCM_SHA384:
		return suiteSpec{
			keyLen: 32, hash: sha512.New384, newAEAD: newAESGCM,
			cryptoInfo: func(key, nonceBase []byte, seq uint64) ([]byte, error) {
				info := cryptoInfoAESGCM256{cryptoInfoHeader: cryptoInfoHeader{kernelTLS13Version, kernelCipherAESGCM256}}
				copy(info.Salt[:], nonceBase[:4])
				copy(info.IV[:], nonceBase[4:])
				copy(info.Key[:], key)
				binary.BigEndian.PutUint64(info.RecSeq[:], seq)

				return binary.Append(nil, binary.NativeEndian, &info)
			},
		}, true
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		return suiteSpec{
			keyLen: 32, hash: sha256.New, newAEAD: chacha20poly1305.New,
			cryptoInfo: func(key, nonceBase []byte, seq uint64) ([]byte, error) {
				info := cryptoInfoChaCha20Poly1305{
					cryptoInfoHeader: cryptoInfoHeader{kernelTLS13Version, kernelCipherChaCha20Poly1305},
				}
				copy(info.IV[:], nonceBase)
				copy(info.Key[:], key)
				binary.BigEndian.PutUint64(info.RecSeq[:], seq)

				return binary.Append(nil, binary.NativeEndian, &info)
			},
		}, true
	default:
		return suiteSpec{}, false
	}
}

// hkdfExpandLabel is HKDF-Expand-Label (RFC 8446 section 7.1) with an empty
// context, which is all the record key derivation needs.
func hkdfExpandLabel(newHash func() hash.Hash, secret []byte, label string, length int) ([]byte, error) {
	var info cryptobyte.Builder

	info.AddUint16(uint16(length)) //nolint:gosec // key and nonce sizes, at most 32
	info.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 " + label))
	})
	info.AddUint8LengthPrefixed(func(*cryptobyte.Builder) {})

	encoded, err := info.Bytes()
	if err != nil {
		return nil, err
	}

	return hkdf.Expand(newHash, secret, string(encoded), length)
}

// recordKeys are one direction's record protection keys (RFC 8446 section 7.3).
type recordKeys struct {
	key       []byte
	nonceBase []byte
}

func deriveRecordKeys(spec suiteSpec, trafficSecret []byte) (recordKeys, error) {
	key, err := hkdfExpandLabel(spec.hash, trafficSecret, "key", spec.keyLen)
	if err != nil {
		return recordKeys{}, err
	}

	nonceBase, err := hkdfExpandLabel(spec.hash, trafficSecret, "iv", tls13NonceLen)
	if err != nil {
		return recordKeys{}, err
	}

	return recordKeys{key: key, nonceBase: nonceBase}, nil
}

// kernelCryptoInfo derives the keys for trafficSecret and packs them, with
// the sequence number of the next record, for the kernel.
func kernelCryptoInfo(spec suiteSpec, trafficSecret []byte, seq uint64) ([]byte, error) {
	keys, err := deriveRecordKeys(spec, trafficSecret)
	if err != nil {
		return nil, err
	}

	return spec.cryptoInfo(keys.key, keys.nonceBase, seq)
}

// recordOpener checks whether a sealed record authenticates under one
// traffic secret.
type recordOpener struct {
	aead      cipher.AEAD
	nonceBase []byte
}

func newRecordOpener(spec suiteSpec, trafficSecret []byte) (recordOpener, error) {
	keys, err := deriveRecordKeys(spec, trafficSecret)
	if err != nil {
		return recordOpener{}, err
	}

	aead, err := spec.newAEAD(keys.key)
	if err != nil {
		return recordOpener{}, err
	}

	return recordOpener{aead: aead, nonceBase: keys.nonceBase}, nil
}

// opens reports whether record (header included, which is the AEAD's
// additional data) decrypts at sequence number seq. The nonce is the nonce
// base XORed with the sequence number, right-aligned (RFC 8446 section 5.3).
func (ro recordOpener) opens(record []byte, seq uint64) bool {
	nonce := slices.Clone(ro.nonceBase)
	tail := nonce[len(nonce)-8:]

	subtle.XORBytes(tail, tail, binary.BigEndian.AppendUint64(nil, seq))

	_, err := ro.aead.Open(nil, nonce, record[recordHeaderLen:], record[:recordHeaderLen])

	return err == nil
}

// nextServerSeq returns the sequence number the kernel must give the first
// record it encrypts under the server application key.
//
// The server's encrypted handshake messages (under the handshake key) and
// any NewSessionTicket messages crypto/tls sends right after its Finished
// (under the application key) are all application_data records on the wire,
// and each key numbers its records from 0. Only the last of the count such
// records (last) was kept:
//
//   - if it opens under the application key at n, records 0..n used that key
//     and the kernel continues at n+1;
//   - if it opens under the handshake key at count-1, it is the server
//     Finished, no ticket was sent, and the kernel starts at 0.
//
// Anything else means the layout is not what this code expects. Guessing
// would only surface later as bad_record_mac at the client, after an
// irreversible offload, so the connection stays in userspace TLS instead.
func nextServerSeq(spec suiteSpec, secrets sessionSecrets, last []byte, count int) (uint64, error) {
	if count < 1 || len(last) <= recordHeaderLen {
		return 0, errNoHandshakeRecord
	}

	records := uint64(count) //nolint:gosec // count >= 1, checked above

	app, err := newRecordOpener(spec, secrets.serverApp)
	if err != nil {
		return 0, err
	}

	for seq := range records {
		if app.opens(last, seq) {
			return seq + 1, nil
		}
	}

	handshake, err := newRecordOpener(spec, secrets.serverHandshake)
	if err != nil {
		return 0, err
	}

	if handshake.opens(last, records-1) {
		return 0, nil
	}

	return 0, errTXSeqUnknown
}
