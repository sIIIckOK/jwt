package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
)

func CreateToken(header Header, payload any, secret []byte) (string, error) {
    var data []byte

    headerData, err := json.Marshal(header)
    if err != nil {
        return "", err
    }
    headerData = []byte(base64.RawURLEncoding.EncodeToString(headerData))

    payloadData, err := json.Marshal(payload)
    if err != nil {
        return "", err
    }
    payloadData = []byte(base64.RawURLEncoding.EncodeToString(payloadData))

    data = append(data, headerData...)
    data = append(data, '.')
    data = append(data, payloadData...)

    if header.Alg != "HS256" { 
        return "", errors.New("Hashing of `%v` is not supported") 
    }

    h := hmac.New(sha256.New, secret)
    _, err = h.Write(data)
    if err != nil {
        return "", err
    }
    hashed := h.Sum(nil)

    data = append(data, '.')
    data = append(data, []byte(base64.RawURLEncoding.EncodeToString(hashed))...)

	return string(data), nil
}

func DefHS356Header() Header {
	return Header{
		Type: "JWT",
		Alg:  "HS256",
	}
}
