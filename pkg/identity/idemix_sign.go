package identity

import (
	"fmt"

	schemes "github.com/IBM/idemix/bccsp/schemes"
	"github.com/IBM/idemix/bccsp/schemes/dlog/handlers"
	"github.com/hyperledger/fabric-gateway/pkg/idemix"
)

func NewIdemixNymKeySign(userSK, userNymSk, issuerPK schemes.Key) (Sign, error) {
	_, ok := userSK.(*handlers.UserSecretKey)
	if !ok {
		return nil, fmt.Errorf("unsupported user secret key type")
	}

	_, ok = userNymSk.(*handlers.NymSecretKey)
	if !ok {
		return nil, fmt.Errorf("unsupported user pseudonymous secret key type")
	}

	return idemixNymKeySign(userSK, userNymSk, issuerPK), nil
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
