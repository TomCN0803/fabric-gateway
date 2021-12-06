package identity

import (
	"fmt"

	schemes "github.com/IBM/idemix/bccsp/schemes"
	"github.com/IBM/idemix/bccsp/schemes/dlog/handlers"
	"github.com/hyperledger/fabric-gateway/pkg/idemix"
)

func NewIdemixNymKeySign(userSK, userNymSK, issuerPK schemes.Key) (Sign, error) {
	_, ok := userSK.(*handlers.UserSecretKey)
	if !ok {
		return nil, fmt.Errorf("unsupported user secret key type")
	}

	_, ok = userNymSK.(*handlers.NymSecretKey)
	if !ok {
		return nil, fmt.Errorf("unsupported user pseudonymous secret key type")
	}

	return idemixNymKeySign(userSK, userNymSK, issuerPK), nil
}

func idemixNymKeySign(userSK, userNymSk, issuerPK schemes.Key) Sign {
	return func(digest []byte) ([]byte, error) {
		csp, err := idemix.NewIdemixCSP()
		if err != nil {
			return nil, err
		}

		sig, err := csp.NymSign(userSK, userNymSk, issuerPK, digest)
		if err != nil {
			return nil, err
		}

		return sig, nil
	}
}

func NewIdemixSign(userSK, userNymSK, issuerPK schemes.Key, credential, cri []byte) (Sign, error) {
	_, ok := userSK.(*handlers.UserSecretKey)
	if !ok {
		return nil, fmt.Errorf("unsupported user secret key type")
	}

	_, ok = userNymSK.(*handlers.NymSecretKey)
	if !ok {
		return nil, fmt.Errorf("unsupported user pseudonymous secret key type")
	}

	return idemixSign(userSK, userNymSK, issuerPK, credential, cri), nil
}

func idemixSign(userSK, userNymSK, issuerPK schemes.Key, credential, cri []byte) Sign {
	return func(digest []byte) ([]byte, error) {
		csp, err := idemix.NewIdemixCSP()
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
