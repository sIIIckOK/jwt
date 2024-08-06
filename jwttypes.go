package jwt

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

func DefHS256Header() Header {
	return Header{
		Type: "JWT",
		Alg:  "HS256",
	}
}
