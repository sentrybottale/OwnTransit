package pki

import (
	"bytes"
	"encoding/pem"
	"fmt"
)

func decodeExactPEM(encoded []byte, blockType string) (*pem.Block, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != blockType || len(block.Headers) != 0 || len(rest) != 0 ||
		!bytes.Equal(encoded, pem.EncodeToMemory(block)) {
		return nil, fmt.Errorf("pki: value must be exactly one canonical headerless %s PEM block", blockType)
	}
	return block, nil
}
