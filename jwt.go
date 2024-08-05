package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

type Token struct {
    Header      Header
    body        string
    signature   string
    payloadStr  string
}

type Header struct {
	Type string `json:"typ"`
	Alg  string `json:"alg"`
}


func DecodeToken(strToken string) (Token, error) {
    var t Token

    var headerLen uint32
    for i, v := range strToken {
        if v == '.' {
            headerLen = uint32(i)
            break
        }
    }
    header, err := decodeHeader(strToken[:headerLen])
    if err != nil {
        return t, err
    }
    t.Header = header

    var payloadLen uint32
    for i, v := range strToken[headerLen+1:] {
        if v == '.' {
            payloadLen = uint32(i)
            break
        }
    }
    t.body = strToken[:headerLen+payloadLen+1]

    pStr := strToken[headerLen+1 : headerLen+1 + payloadLen]
    p, err := base64.RawURLEncoding.DecodeString(pStr)
    if err != nil { 
        return t, err 
    }
    t.payloadStr = string(p)

    sig := strToken[headerLen + payloadLen + 2:]
    t.signature = string(sig)
    return t, nil
}

func (t Token) VerifySecret(secret []byte) (bool, error) {
    //@TODO: Implement RS256
    if t.Header.Alg != "HS256" {
        err := fmt.Sprintf("Hashing of `%v` is not supported", t.Header.Alg)
        return false, errors.New(err)
    }

    enc := hs256ThenBase64([]byte(t.body), secret)

    if enc == t.signature {
        return true, nil
    }

    return false, nil
}

func hs256ThenBase64(data []byte, secret []byte) string {
    h := hmac.New(sha256.New, secret)
    h.Write(data)
    hashed := h.Sum(nil)

    s := base64.RawURLEncoding.EncodeToString(hashed)

    return s
}

func (t Token) DecodePayload(v any) error {
    return json.Unmarshal([]byte(t.payloadStr), v)
}

func decodeHeader(h string) (Header, error) {
    var j Header

    hDec, err := base64.RawURLEncoding.DecodeString(h)
    if err != nil { return j, err }

    if err := json.Unmarshal(hDec, &j); err != nil {
        return j, err
    }

    return j, nil
}


