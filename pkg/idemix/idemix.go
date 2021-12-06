package idemix

import (
	bccsp "github.com/IBM/idemix/bccsp"
	schemes "github.com/IBM/idemix/bccsp/schemes"
	"github.com/IBM/idemix/bccsp/schemes/dlog/crypto/translator/amcl"
	math "github.com/IBM/mathlib"
)

// CSPWrapper wraps the idemix BCCSP implementation.
type CSPWrapper struct {
	csp schemes.BCCSP
}

func NewIdemixCSP() (*CSPWrapper, error) {
	curve := math.Curves[math.FP256BN_AMCL]
	translator := &amcl.Fp256bn{C: curve}

	csp, err := bccsp.New(NewDummyKeyStore(), curve, translator, true)
	if err != nil {
		return nil, err
	}

	return &CSPWrapper{csp: csp}, nil
}

func (c *CSPWrapper) NymSign(userSK, userNymSK, issuerPK schemes.Key, digest []byte) ([]byte, error) {
	sig, err := c.csp.Sign(userSK, digest, &schemes.IdemixNymSignerOpts{
		Nym:      userNymSK,
		IssuerPK: issuerPK,
	})
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func (c *CSPWrapper) Sign(userSK, userNymSK, issuerPK schemes.Key, credential, cri, digest []byte) ([]byte, error) {
	attrMask := []schemes.IdemixAttribute{
		{Type: schemes.IdemixBytesAttribute},
		{Type: schemes.IdemixIntAttribute},
		{Type: schemes.IdemixHiddenAttribute},
		{Type: schemes.IdemixHiddenAttribute},
	}

	sig, err := c.csp.Sign(
		userSK,
		digest,
		&schemes.IdemixSignerOpts{
			Credential: credential,
			Nym:        userNymSK,
			IssuerPK:   issuerPK,
			Attributes: attrMask,
			RhIndex:    3,
			EidIndex:   2,
			Epoch:      0,
			CRI:        cri,
		},
	)
	if err != nil {
		return nil, err
	}

	return sig, nil
}
