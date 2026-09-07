package sshsign

import (
	"errors"
	"fmt"

	"github.com/amber-store/core/reference"
)

// DecodeVerifiedReference decodes raw and verifies its embedded signature;
// unsigned records are rejected. It is the one-call validation used
// wherever a record crosses a trust boundary (remote pull, embedded
// publish). It lives here rather than in core's reference package because
// signature verification, and the ssh dependencies it needs, are this
// repository's concern.
func DecodeVerifiedReference(raw []byte) (reference.Reference, error) {
	rec, err := reference.Decode(raw)
	if err != nil {
		return reference.Reference{}, err
	}
	if len(rec.Signature) == 0 || len(rec.PublicKey) == 0 {
		return reference.Reference{}, errors.New("reference record is not signed")
	}
	payload, err := rec.SignaturePayload()
	if err != nil {
		return reference.Reference{}, err
	}
	if _, err := Verify(payload, rec.Signature, rec.PublicKey); err != nil {
		return reference.Reference{}, fmt.Errorf("reference signature does not verify: %w", err)
	}
	return rec, nil
}
