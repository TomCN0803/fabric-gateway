package identity

import (
	"github.com/hyperledger/fabric-gateway/pkg/idemix"
)

func NewIdemixNymKeySign(userSKByte, issuerPKByte []byte) Sign {
	return func(digest []byte) ([]byte, error) {
		csp, err := idemix.NewIdemixCSP()
		if err != nil {
			return nil, err
		}

		issuerPK, err := csp.GetIssuerPK(issuerPKByte)
		if err != nil {
			return nil, err
		}

		userSK, err := csp.GetUserSK(userSKByte)
		if err != nil {
			return nil, err
		}

		userNymSK, err := csp.DerivUserNymKey(userSK, issuerPK)
		if err != nil {
			return nil, err
		}

		sig, err := csp.NymSign(userSK, userNymSK, issuerPK, digest)
		if err != nil {
			return nil, err
		}

		return sig, nil
	}
}

func NewIdemixSign(userSKByte, issuerPKByte, credential, cri []byte) Sign {
	return func(digest []byte) ([]byte, error) {
		csp, err := idemix.NewIdemixCSP()
		if err != nil {
			return nil, err
		}

		issuerPK, err := csp.GetIssuerPK(issuerPKByte)
		if err != nil {
			return nil, err
		}

		userSK, err := csp.GetUserSK(userSKByte)
		if err != nil {
			return nil, err
		}

		userNymSK, err := csp.DerivUserNymKey(userSK, issuerPK)
		if err != nil {
			return nil, err
		}

		sig, err := csp.Sign(userSK, userNymSK, issuerPK, credential, cri, digest)
		if err != nil {
			return nil, err
		}

		return sig, nil
	}
}
