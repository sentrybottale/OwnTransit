package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/sentrybottale/owntransit/internal/packagetxn"
)

const maxDarwinReaderReceipt = 4096

type darwinReaderIdentity struct {
	clientUser       string
	clientUID        uint32
	clientPrimaryGID uint32
	clientUUID       string
	readerGID        uint32
}

func renderDarwinLauncherBinding(receipt []byte, runtimeIdentity packagetxn.RuntimeIdentity) ([]byte, int, error) {
	identity, err := parseDarwinReaderIdentity(receipt)
	if err != nil {
		return nil, 0, err
	}
	if runtimeIdentity.Role != "client" || runtimeIdentity.OS != "darwin" || runtimeIdentity.Arch != "arm64" ||
		!validPackageReleaseID(runtimeIdentity.ReleaseID) || runtimeIdentity.ReleaseSequence == 0 ||
		!validPackageDigest(runtimeIdentity.ArtifactSHA256) || !validPackageDigest(runtimeIdentity.LauncherSHA256) {
		return nil, 0, errors.New("Darwin launcher activation requires one authenticated current client runtime")
	}
	encoded := []byte(fmt.Sprintf(
		"schema=owntransit.macos-client-launcher.v1\nclient_uid=%d\nclient_uuid=%s\nreader_gid=%d\nrelease_id=%s\nclient_sha256=%s\n",
		identity.clientUID, identity.clientUUID, identity.readerGID, runtimeIdentity.ReleaseID, runtimeIdentity.ArtifactSHA256,
	))
	return encoded, int(identity.readerGID), nil
}

func parseDarwinReaderIdentity(encoded []byte) (darwinReaderIdentity, error) {
	if len(encoded) == 0 || len(encoded) > maxDarwinReaderReceipt || encoded[len(encoded)-1] != '\n' || bytes.IndexByte(encoded, 0) >= 0 {
		return darwinReaderIdentity{}, errors.New("Darwin reader identity receipt has an invalid size or encoding")
	}
	lines := strings.Split(string(encoded), "\n")
	if len(lines) != 9 || lines[8] != "" || lines[0] != "schema=owntransit.macos-client-reader.v1" {
		return darwinReaderIdentity{}, errors.New("Darwin reader identity receipt has the wrong schema or field count")
	}
	clientUser, ok := strings.CutPrefix(lines[1], "client_user=")
	if !ok || !validDarwinLocalName(clientUser) || clientUser == "_owntransit" {
		return darwinReaderIdentity{}, errors.New("Darwin reader identity receipt has an invalid client user")
	}
	clientUID, err := parseCanonicalPackageID(lines[2], "client_uid")
	if err != nil {
		return darwinReaderIdentity{}, err
	}
	clientPrimaryGID, err := parseCanonicalPackageID(lines[3], "client_primary_gid")
	if err != nil {
		return darwinReaderIdentity{}, err
	}
	clientUUID, ok := strings.CutPrefix(lines[4], "client_uuid=")
	if !ok || !validDarwinUUID(clientUUID) {
		return darwinReaderIdentity{}, errors.New("Darwin reader identity receipt has an invalid client UUID")
	}
	if lines[5] != "reader_group=_owntransit" {
		return darwinReaderIdentity{}, errors.New("Darwin reader identity receipt has an invalid reader group")
	}
	readerGID, err := parseCanonicalPackageID(lines[6], "reader_gid")
	if err != nil || readerGID < 5000 || readerGID > 59999 {
		return darwinReaderIdentity{}, errors.New("Darwin reader identity receipt has an invalid reader GID")
	}
	readerUUID, ok := strings.CutPrefix(lines[7], "reader_group_uuid=")
	if !ok || !validDarwinUUID(readerUUID) {
		return darwinReaderIdentity{}, errors.New("Darwin reader identity receipt has an invalid reader group UUID")
	}
	if clientPrimaryGID == readerGID {
		return darwinReaderIdentity{}, errors.New("Darwin reader identity receipt uses the reader GID as the client primary GID")
	}
	return darwinReaderIdentity{clientUser: clientUser, clientUID: clientUID, clientPrimaryGID: clientPrimaryGID, clientUUID: clientUUID, readerGID: readerGID}, nil
}

func parseCanonicalPackageID(line, key string) (uint32, error) {
	text, ok := strings.CutPrefix(line, key+"=")
	if !ok || text == "" || text[0] == '0' {
		return 0, fmt.Errorf("Darwin reader identity receipt has an invalid %s", key)
	}
	value, err := strconv.ParseUint(text, 10, 32)
	if err != nil || value == 0 || value == uint64(^uint32(0)) || strconv.FormatUint(value, 10) != text {
		return 0, fmt.Errorf("Darwin reader identity receipt has an invalid %s", key)
	}
	return uint32(value), nil
}

func validDarwinLocalName(value string) bool {
	if value == "" || len(value) > 64 || value[0] == '-' {
		return false
	}
	for _, character := range value {
		if (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func validDarwinUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	decoded, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil && len(decoded) == 16 && !bytes.Equal(decoded, make([]byte, 16))
}

func validPackageReleaseID(value string) bool {
	if len(value) != 52 || value == strings.Repeat("a", 52) || (value[51] != 'a' && value[51] != 'q') {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '2' || character > '7') {
			return false
		}
	}
	return true
}

func validPackageDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}
