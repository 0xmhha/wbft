package main

import (
	"encoding/json"
	"fmt"

	"github.com/0xmhha/wbft/chain/header"
	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/ecdsa"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/0xmhha/wbft/types"
)

// Handlers of the runner "crypto" (A-02).

func hKeccak256(_ string, input json.RawMessage) (any, error) {
	var in struct {
		Data Hex `json:"data"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	h := keccak.Sum256(in.Data)
	return obj{"hash": hexOut(h[:])}, nil
}

func hEcdsaSign(_ string, input json.RawMessage) (any, error) {
	var in struct {
		PrivateKey Hex `json:"private_key"`
		Data       Hex `json:"data"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	k, err := ecdsa.PrivateKeyFromBytes(in.PrivateKey)
	if err != nil {
		return nil, err
	}
	sig, err := ecdsa.SignData(in.Data, k)
	if err != nil {
		return nil, err
	}
	return obj{"signature": hexOut(sig), "address": addrOut(ecdsa.Address(k))}, nil
}

func hEcdsaRecover(_ string, input json.RawMessage) (any, error) {
	var in struct {
		Data      Hex `json:"data"`
		Signature Hex `json:"signature"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	a, err := ecdsa.RecoverDataSigner(in.Data, in.Signature)
	if err != nil {
		return nil, err
	}
	return obj{"address": addrOut(a)}, nil
}

func hBLSDerive(_ string, input json.RawMessage) (any, error) {
	var in struct {
		PrivateKey Hex `json:"private_key"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	k, err := ecdsa.PrivateKeyFromBytes(in.PrivateKey)
	if err != nil {
		return nil, err
	}
	sk, err := bls.DeriveSecretKey(ecdsa.PrivateKeyBytes(k))
	if err != nil {
		return nil, err
	}
	return obj{"secret_key": hexOut(sk.Bytes()), "public_key": hexOut(sk.PublicKey().Bytes())}, nil
}

func hBLSSign(_ string, input json.RawMessage) (any, error) {
	var in struct {
		SecretKey Hex `json:"secret_key"`
		Message   Hex `json:"message"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	sk, err := bls.SecretKeyFromBytes(in.SecretKey)
	if err != nil {
		return nil, err
	}
	return obj{"signature": hexOut(sk.Sign(in.Message).Bytes())}, nil
}

func hexBytes(hs []Hex) [][]byte {
	out := make([][]byte, len(hs))
	for i, h := range hs {
		out[i] = h
	}
	return out
}

func hBLSVerify(_ string, input json.RawMessage) (any, error) {
	var in struct {
		PublicKeys []Hex `json:"public_keys"`
		Message    Hex   `json:"message"`
		Signature  Hex   `json:"signature"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	apk, err := bls.AggregatePublicKeys(hexBytes(in.PublicKeys))
	if err != nil {
		return nil, err
	}
	sig, err := bls.DecodeSignature(in.Signature)
	if err != nil {
		return nil, err
	}
	return obj{"valid": bls.Verify(apk, in.Message, sig)}, nil
}

func hBLSAggregate(_ string, input json.RawMessage) (any, error) {
	var in struct {
		Signatures []Hex `json:"signatures"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	s, err := bls.AggregateSignatures(hexBytes(in.Signatures))
	if err != nil {
		return nil, err
	}
	return obj{"signature": hexOut(s.Bytes())}, nil
}

func hAggregatePublicKeys(_ string, input json.RawMessage) (any, error) {
	var in struct {
		PublicKeys []Hex `json:"public_keys"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	pk, err := bls.AggregatePublicKeys(hexBytes(in.PublicKeys))
	if err != nil {
		return nil, err
	}
	return obj{"public_key": hexOut(pk.Bytes())}, nil
}

func hSealData(_ string, input json.RawMessage) (any, error) {
	var in struct {
		Header   Hex `json:"header"`
		Round    Dec `json:"round"`
		SealType Dec `json:"seal_type"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	h, err := codec.DecodeHeader(in.Header)
	if err != nil {
		return nil, err
	}
	round, err := toUint32(in.Round)
	if err != nil {
		return nil, err
	}
	st, err := in.SealType.Uint64Checked()
	if err != nil || st > 1 {
		return nil, fmt.Errorf("%w: seal type %s", errInput, in.SealType.String())
	}
	return obj{"seal_data": hexOut(codec.SealData(h, round, types.SealType(st)))}, nil
}

func hRandaoData(_ string, input json.RawMessage) (any, error) {
	var in struct {
		ChainID Dec `json:"chain_id"`
		Number  Dec `json:"number"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	n, err := types.HeightFromBig(&in.Number.Int)
	if err != nil {
		return nil, err
	}
	return obj{"randao_data": hexOut(codec.RandaoData(&in.ChainID.Int, n))}, nil
}

func hRandaoMix(_ string, input json.RawMessage) (any, error) {
	var in struct {
		ParentMix Hex `json:"parent_mix"`
		Reveal    Hex `json:"reveal"`
	}
	if err := decode(input, &in); err != nil {
		return nil, err
	}
	pm, err := toHash(in.ParentMix)
	if err != nil {
		return nil, err
	}
	mix := header.RandaoMix(pm, in.Reveal)
	return obj{"mix": hexOut(mix[:])}, nil
}
