package relaysetup

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// DockerArchive converts the already authenticated single-platform OCI archive
// to Docker's portable load format. Image config and layer bytes are unchanged;
// every referenced OCI digest/size is checked before a load archive is emitted.
// This also supports Docker installations using the classic image store.
func DockerArchive(input io.Reader, output io.Writer, tag string) error {
	if tag != "owntransit-relay-pair:0.1.3" {
		return errors.New("unexpected relay image tag")
	}
	files := map[string][]byte{}
	reader := tar.NewReader(io.LimitReader(input, 128<<20))
	total := int64(0)
	for count := 0; ; count++ {
		h, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if count >= 32 {
			return errors.New("image inventory too large")
		}
		name := strings.TrimSuffix(h.Name, "/")
		if h.Typeflag == tar.TypeDir {
			if name != "blobs" && name != "blobs/sha256" {
				return errors.New("unexpected image directory")
			}
			continue
		}
		if h.Typeflag != tar.TypeReg || h.Size < 0 || h.Size > 128<<20 || total+h.Size > 128<<20 {
			return errors.New("invalid image member")
		}
		if _, ok := files[name]; ok {
			return errors.New("duplicate image member")
		}
		if name != "index.json" && name != "oci-layout" && !strings.HasPrefix(name, "blobs/sha256/") {
			return errors.New("unexpected image member")
		}
		body, err := io.ReadAll(io.LimitReader(reader, h.Size+1))
		if err != nil || int64(len(body)) != h.Size {
			return errors.New("truncated image member")
		}
		files[name] = body
		total += h.Size
	}
	type descriptor struct {
		Digest string `json:"digest"`
		Size   int64  `json:"size"`
	}
	get := func(d descriptor) ([]byte, error) {
		if !validDigest(d.Digest) || d.Size < 1 {
			return nil, errors.New("invalid OCI descriptor")
		}
		b, ok := files["blobs/sha256/"+d.Digest[7:]]
		if !ok || int64(len(b)) != d.Size {
			return nil, errors.New("missing OCI blob")
		}
		digest := sha256.Sum256(b)
		if hex.EncodeToString(digest[:]) != d.Digest[7:] {
			return nil, errors.New("OCI digest mismatch")
		}
		return b, nil
	}
	var index struct {
		Manifests []descriptor `json:"manifests"`
	}
	if json.Unmarshal(files["index.json"], &index) != nil || len(index.Manifests) != 1 {
		return errors.New("one platform image is required")
	}
	manifestBytes, err := get(index.Manifests[0])
	if err != nil {
		return err
	}
	var manifest struct {
		Config descriptor   `json:"config"`
		Layers []descriptor `json:"layers"`
	}
	if json.Unmarshal(manifestBytes, &manifest) != nil || len(manifest.Layers) != 1 {
		return errors.New("one relay layer is required")
	}
	config, err := get(manifest.Config)
	if err != nil {
		return err
	}
	layer, err := get(manifest.Layers[0])
	if err != nil {
		return err
	}
	configName := manifest.Config.Digest[7:] + ".json"
	layerName := manifest.Layers[0].Digest[7:] + "/layer.tar"
	dockerManifest, err := json.Marshal([]struct {
		Config   string
		RepoTags []string
		Layers   []string
	}{{configName, []string{tag}, []string{layerName}}})
	if err != nil {
		return err
	}
	w := tar.NewWriter(output)
	for _, entry := range []struct {
		name string
		data []byte
	}{{configName, config}, {layerName, layer}, {"manifest.json", dockerManifest}} {
		if err := w.WriteHeader(&tar.Header{Name: entry.name, Mode: 0644, Size: int64(len(entry.data)), Typeflag: tar.TypeReg}); err != nil {
			return err
		}
		if _, err := io.Copy(w, bytes.NewReader(entry.data)); err != nil {
			return err
		}
	}
	return w.Close()
}

func validDigest(d string) bool {
	if len(d) != 71 || !strings.HasPrefix(d, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(d[7:])
	return err == nil && d == strings.ToLower(d)
}
