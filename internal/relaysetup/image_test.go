package relaysetup

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"testing"
)

func TestDockerConversionPreservesAuthenticatedBytesAndRejectsTamper(t *testing.T) {
	config := []byte(`{"architecture":"arm64","os":"linux"}`)
	layer := []byte("relay layer fixture")
	type descriptor struct {
		Digest string `json:"digest"`
		Size   int    `json:"size"`
	}
	desc := func(b []byte) descriptor {
		h := sha256.Sum256(b)
		return descriptor{"sha256:" + hex.EncodeToString(h[:]), len(b)}
	}
	cd, ld := desc(config), desc(layer)
	manifest, _ := json.Marshal(struct {
		Config descriptor   `json:"config"`
		Layers []descriptor `json:"layers"`
	}{cd, []descriptor{ld}})
	md := desc(manifest)
	index, _ := json.Marshal(struct {
		Manifests []descriptor `json:"manifests"`
	}{[]descriptor{md}})
	for _, tamper := range []bool{false, true} {
		var input bytes.Buffer
		w := tar.NewWriter(&input)
		for _, entry := range []struct {
			name string
			data []byte
		}{{"index.json", index}, {"blobs/sha256/" + md.Digest[7:], manifest}, {"blobs/sha256/" + cd.Digest[7:], config}, {"blobs/sha256/" + ld.Digest[7:], layer}} {
			data := entry.data
			if tamper && entry.name == "blobs/sha256/"+ld.Digest[7:] {
				data = []byte("wrong layer fixture")
			}
			if err := w.WriteHeader(&tar.Header{Name: entry.name, Mode: 0644, Typeflag: tar.TypeReg, Size: int64(len(data))}); err != nil {
				t.Fatal(err)
			}
			w.Write(data)
		}
		w.Close()
		var output bytes.Buffer
		err := DockerArchive(&input, &output, "owntransit-relay-pair:0.1.3")
		if tamper {
			if err == nil {
				t.Fatal("tampered OCI blob converted")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		reader := tar.NewReader(&output)
		var gotConfig, gotLayer []byte
		for {
			h, e := reader.Next()
			if e == io.EOF {
				break
			}
			if e != nil {
				t.Fatal(e)
			}
			data, _ := io.ReadAll(reader)
			if h.Name == cd.Digest[7:]+".json" {
				gotConfig = data
			}
			if h.Name == ld.Digest[7:]+"/layer.tar" {
				gotLayer = data
			}
		}
		if !bytes.Equal(config, gotConfig) || !bytes.Equal(layer, gotLayer) {
			t.Fatal("conversion changed image content")
		}
	}
}
