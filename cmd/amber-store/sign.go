package main

import (
	"github.com/amber-store/amber-store/reference"
	"github.com/amber-store/amber-store/sshsign"
)

// signReference signs rec with the key at keyPath: it records the signer's
// public key first — the signature payload covers it — then attaches the
// SSHSIG blob. Used by every command that creates references.
func signReference(rec *reference.Reference, keyPath string) error {
	signer, closeSigner, err := sshsign.Signer(keyPath, sshsign.TTYPrompt)
	if err != nil {
		return err
	}
	defer closeSigner()
	rec.PublicKey = signer.PublicKey().Marshal()
	payload, err := rec.SignaturePayload()
	if err != nil {
		return err
	}
	sig, err := sshsign.SignWith(signer, payload)
	if err != nil {
		return err
	}
	rec.Signature = sig
	return nil
}
