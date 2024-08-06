package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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
        err := fmt.Sprintf("Hashing of `%v` is not supported", header.Alg)
        return "", errors.New(err) 
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

func CreateTokenFromJSON(header Header, jsonPayload []byte, secret []byte) (string, error) {
    var data []byte

    headerData, err := json.Marshal(header)
    if err != nil {
        return "", err
    }
    headerData = []byte(base64.RawURLEncoding.EncodeToString(headerData))

    payloadData := []byte(base64.RawURLEncoding.EncodeToString(payload))

    data = append(data, headerData...)
    data = append(data, '.')
    data = append(data, payloadData...)

    if header.Alg != "HS256" { 
        err := fmt.Sprintf("Hashing of `%v` is not supported", header.Alg)
        return "", errors.New(err) 
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
