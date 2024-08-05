package jwt

import (
	"encoding/base64"
	"encoding/json"
)

// @TODO: Implement secret later
type Token struct {
    Header     Header
    // secret     string
    payloadStr string
}

func (t *Token) DecodePayload(v any) error {
    return json.Unmarshal([]byte(t.payloadStr), v)
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
    _ = payloadLen
    for i, v := range strToken[headerLen+1:] {
        if v == '.' {
            payloadLen = uint32(i)
            break
        }
    }

    p, err := base64.RawURLEncoding.DecodeString(strToken[headerLen+1 : headerLen+1 + payloadLen])
    if err != nil { 
        return t, err 
    }
    t.payloadStr = string(p)

    return t, nil
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


