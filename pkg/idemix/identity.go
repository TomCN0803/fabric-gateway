package idemix

type Identity struct {
	mspID       string
	certificate []byte
}

func (id *Identity) MspID() string {
	return id.mspID
}

func (id *Identity) Credentials() []byte {
	return id.certificate
}

func NewIdemixIdentity(mspID string, certificate []byte) *Identity {
	return &Identity{
		mspID:       mspID,
		certificate: certificate,
	}
}
