package openrpc

type OpenRPC struct {
	OpenRPC      string                  `json:"open_rpc"`
	Info         Info                    `json:"info"`
	Servers      []Server                `json:"servers"`
	Methods      []Reference             `json:"methods"`
	Components   []Component             `json:"components"`
	ExternalDocs []ExternalDocumentation `json:"externalDocs"`
}
