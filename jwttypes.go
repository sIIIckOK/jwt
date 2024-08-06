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

