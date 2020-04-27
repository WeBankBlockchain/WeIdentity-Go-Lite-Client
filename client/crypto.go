package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"golang.org/x/crypto/sha3"
	"math/big"
	rand2 "math/rand"
	"strconv"
	"time"
)

func GenerateNonce() string {
	rand2.Seed(time.Now().UnixNano())
	nonce := strconv.Itoa(rand2.Int())
	return nonce
}

func GenerateKeyPair() (publicKeyBytes []byte, privateKeyBytes []byte, publicKeyBigInt *big.Int, privateKeyBigInt *big.Int) {
	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	publicKeyBytes = elliptic.Marshal(secp256k1.S256(), key.X, key.Y)
	publicKeyBigInt = new(big.Int).SetBytes(publicKeyBytes[1:])
	privateKeyBytes = ConvertPrivateKeyBigIntToPrivateKeyBytes(key.D)
	return publicKeyBytes, privateKeyBytes, publicKeyBigInt, key.D
}

func ConvertPrivateKeyBigIntToPrivateKeyBytes(privateKeyBigInt *big.Int) []byte {
	privateKeyBytes := make([]byte, 32)
	blob := privateKeyBigInt.Bytes()
	copy(privateKeyBytes[32-len(blob):], blob)
	return privateKeyBytes
}

func SignSignature(hashedMsg []byte, privateKeyBytes []byte) ([]byte, error) {
	signature, err := secp256k1.Sign(hashedMsg, privateKeyBytes)
	return signature, err
}

func Hash(msg []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(msg)
	return h.Sum(nil)
}

func PublicKeyToWeId(publicKeyBytes []byte) string {
	address := common.BytesToAddress(crypto.Keccak256(publicKeyBytes[1:])[12:])
	weid := "did:weid:" + address.String()
	return weid
}
