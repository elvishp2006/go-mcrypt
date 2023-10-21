package rijndael256_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/elvishp2006/go-mcrypt/pkg/rijndael256"
	"github.com/stretchr/testify/assert"
)

func ExampleCipher_Encrypt() {
	r, err := rijndael256.NewCipher([]byte("1234567890123456"))

	if err != nil {
		panic(err)
	}

	encrypted := make([]byte, 32)

	r.Encrypt(encrypted, []byte("123"))

	fmt.Println(base64.StdEncoding.EncodeToString(encrypted))

	// Output:
	// Pd0dwZIwEvgxedRZNxBopvDWg1xbLrAwoh7RA/i1MW0=
}

func ExampleCipher_Decrypt() {
	r, err := rijndael256.NewCipher([]byte("1234567890123456"))

	if err != nil {
		panic(err)
	}

	encrypted := make([]byte, 32)

	r.Encrypt(encrypted, []byte("123"))

	decrypted := make([]byte, 32)

	r.Decrypt(decrypted, encrypted)

	fmt.Println(string(bytes.Trim(decrypted, "\x00")))

	// Output:
	// 123
}

func TestRijndael256(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		plaintext string
		result    string
	}{
		{
			name:      "Encrypting with valid key with size 16",
			key:       "1234567890123456",
			plaintext: "26147368",
			result:    "xy5WtslgZ7up7Fb2g+/F9XY1htilE74tVdjamnwlCBM=",
		},
		{
			name:      "Encrypting with valid key with size 24",
			key:       "123456789012345678901234",
			plaintext: "26147368",
			result:    "snoFT+U4A24MiX+IxzPQbbdNfG+3sPFwGxtQWvi+8vc=",
		},
		{
			name:      "Encrypting with valid key with size 32",
			key:       "12345678901234567890123456789012",
			plaintext: "26147368",
			result:    "hP79tLWK8PxnQrE6ZMbCN1aUILow7TykJgJ1uObTKLU=",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := []byte(test.key)
			plaintext := []byte(test.plaintext)

			r, err := rijndael256.NewCipher(key)

			if err != nil {
				t.Fatal(err)
			}

			encrypted := make([]byte, 32)

			r.Encrypt(encrypted, plaintext)

			decrypt := make([]byte, 32)

			r.Decrypt(decrypt, encrypted)

			assert.Equal(t, test.result, base64.StdEncoding.EncodeToString(encrypted))
			assert.Equal(t, plaintext, bytes.Trim(decrypt, "\x00"))
		})
	}

	t.Run("Encrypting with invalid key size", func(t *testing.T) {
		_, err := rijndael256.NewCipher([]byte("123456789012345678901234567890123"))

		assert.Equal(t, err, rijndael256.ErrInvalidKeySize)
	})
}
