package basebump

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Source reads a tag's digest and release from the public ECR gallery, and
// the release's package versions from Amazon Linux's repository. Every
// manifest and blob is checked against its digest, the repository's package
// list against the checksum its repomd.xml names.
type Source struct {
	Client *http.Client
	// Gallery is the registry's root URL; Repository the image's name in it.
	Gallery, Repository string
	// Mirrors is the root of the releases' mirror lists, Arch the
	// repository's architecture. The image is the gallery's linux/arm64 one.
	Mirrors, Arch string
	// MirrorHosts are the only hosts, host[:port], a mirror list or
	// repomd.xml may send it to.
	MirrorHosts []string
}

// mirrorHosts are AL2023's: what its mirror lists name today.
var mirrorHosts = []string{"cdn.amazonlinux.com"}

// ErrRefused says a URL is not one Source fetches: not https, a host not on
// its list, or a redirect.
var ErrRefused = errors.New("refused")

// Public is the Source the Dockerfile's base comes from: the
// lambda/microvms gallery image for arm64, and AL2023's core repository.
func Public() Source {
	return Source{
		Client:      &http.Client{Timeout: 2 * time.Minute},
		Gallery:     "https://public.ecr.aws",
		Repository:  "lambda/microvms",
		Mirrors:     "https://cdn.amazonlinux.com/al2023/core/mirrors",
		Arch:        "aarch64",
		MirrorHosts: mirrorHosts,
	}
}

const (
	listTypes     = "application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.oci.image.index.v1+json"
	manifestTypes = "application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json"
	// maxBody bounds what one response may hold: the compressed package
	// list is some 8 MiB.
	maxBody = 64 << 20
)

// The release, in the history line that added the base's root file system.
var historyRE = regexp.MustCompile(`^ADD al2023-container-minimal-(2023\.\d+\.\d{8})\.\d+-arm64v8\.tar\.xz `)

// Image reads the tag's manifest list digest, and the release its arm64
// image was built from.
func (s Source) Image(ctx context.Context, tag string) (digest, release string, err error) {
	var token struct {
		Token string `json:"token"`
	}
	body, err := s.get(ctx, s.Gallery+"/token/?scope=repository:"+s.Repository+":pull", "", "", false)
	if err != nil {
		return "", "", err
	}
	if err := json.Unmarshal(body, &token); err != nil || token.Token == "" {
		return "", "", fmt.Errorf("read the gallery's token: %w", errors.Join(err, errors.New("no token")))
	}
	body, err = s.get(ctx, s.Gallery+"/v2/"+s.Repository+"/manifests/"+url.PathEscape(tag), listTypes, token.Token, false)
	if err != nil {
		return "", "", err
	}
	digest = sha256Digest(body)
	var list struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				Architecture string `json:"architecture"`
				OS           string `json:"os"`
			} `json:"platform"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return "", "", fmt.Errorf("read %s's manifest list: %w", tag, err)
	}
	arm := ""
	for _, m := range list.Manifests {
		if m.Platform.OS == "linux" && m.Platform.Architecture == "arm64" {
			arm = m.Digest
		}
	}
	if arm == "" {
		return "", "", fmt.Errorf("%s has no linux/arm64 image", tag)
	}
	var manifest struct {
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if err := s.blob(ctx, "manifests", arm, manifestTypes, token.Token, &manifest); err != nil {
		return "", "", err
	}
	var config struct {
		History []struct {
			CreatedBy string `json:"created_by"`
		} `json:"history"`
	}
	if err := s.blob(ctx, "blobs", manifest.Config.Digest, "", token.Token, &config); err != nil {
		return "", "", err
	}
	for _, h := range config.History {
		if m := historyRE.FindStringSubmatch(h.CreatedBy); m != nil {
			return digest, m[1], nil
		}
	}
	return "", "", fmt.Errorf("%s's arm64 image names no AL2023 release in its history", tag)
}

// blob reads a manifest or blob by digest, checks it holds that digest, and
// decodes its JSON into v.
func (s Source) blob(ctx context.Context, kind, digest, accept, token string, v any) error {
	if !digestRE.MatchString(digest) {
		return fmt.Errorf("%s digest %q: not a sha256 digest", kind, digest)
	}
	// Only a blob may redirect (the gallery serves them from a CDN): its
	// bytes are checked against the digest below.
	body, err := s.get(ctx, s.Gallery+"/v2/"+s.Repository+"/"+kind+"/"+digest, accept, token, kind == "blobs")
	if err != nil {
		return err
	}
	if got := sha256Digest(body); got != digest {
		return fmt.Errorf("%s %s: the gallery sent %s", kind, digest, got)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("read %s %s: %w", kind, digest, err)
	}
	return nil
}

// Packages reads the newest version of each named package in the
// release's repository.
func (s Source) Packages(ctx context.Context, release string, names []string) (map[string]string, error) {
	mirrorList := s.Mirrors + "/" + release + "/" + s.Arch + "/mirror.list"
	body, err := s.mirror(ctx, mirrorList)
	if err != nil {
		return nil, err
	}
	line, _, _ := strings.Cut(string(body), "\n")
	repo, err := resolve(mirrorList, strings.TrimSpace(line))
	if err != nil {
		return nil, err
	}
	body, err = s.mirror(ctx, repo+"repodata/repomd.xml")
	if err != nil {
		return nil, err
	}
	var repomd struct {
		Data []struct {
			Type     string `xml:"type,attr"`
			Checksum struct {
				Type  string `xml:"type,attr"`
				Value string `xml:",chardata"`
			} `xml:"checksum"`
			Location struct {
				Href string `xml:"href,attr"`
			} `xml:"location"`
		} `xml:"data"`
	}
	if err := xml.Unmarshal(body, &repomd); err != nil {
		return nil, fmt.Errorf("read %srepodata/repomd.xml: %w", repo, err)
	}
	for _, d := range repomd.Data {
		if d.Type != "primary" {
			continue
		}
		primary, err := resolve(repo, d.Location.Href)
		if err != nil {
			return nil, err
		}
		gz, err := s.mirror(ctx, primary)
		if err != nil {
			return nil, err
		}
		if want := "sha256:" + strings.TrimSpace(d.Checksum.Value); d.Checksum.Type != "sha256" || sha256Digest(gz) != want {
			return nil, fmt.Errorf("%s: not the %s checksum %s names", primary, d.Checksum.Type, want)
		}
		r, err := gzip.NewReader(bytes.NewReader(gz))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", primary, err)
		}
		return Newest(bufio.NewReader(r), s.Arch, names)
	}
	return nil, fmt.Errorf("%srepodata/repomd.xml names no primary package list", repo)
}

// resolve is ref, read relative to base.
func resolve(base, ref string) (string, error) {
	b, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", base, err)
	}
	r, err := url.Parse(ref)
	if err != nil || ref == "" {
		return "", fmt.Errorf("parse %q, from %s: %w", ref, base, errors.Join(err, errors.New("no URL")))
	}
	return b.ResolveReference(r).String(), nil
}

// mirror reads a URL on one of the mirror hosts, without redirects.
func (s Source) mirror(ctx context.Context, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", rawURL, err)
	}
	if !slices.Contains(s.MirrorHosts, u.Host) {
		return nil, fmt.Errorf("get %s: %s is not an AL2023 mirror host: %w", rawURL, u.Host, ErrRefused)
	}
	return s.get(ctx, rawURL, "", "", false)
}

// get reads an https URL's body, failing on any status but 200. It follows
// a redirect, to https only, when follow says so, and refuses one otherwise.
func (s Source) get(ctx context.Context, rawURL, accept, token string, follow bool) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", rawURL, err)
	}
	if req.URL.Scheme != "https" {
		return nil, fmt.Errorf("get %s: not https: %w", rawURL, ErrRefused)
	}
	client := *s.Client
	client.CheckRedirect = func(next *http.Request, _ []*http.Request) error {
		if !follow || next.URL.Scheme != "https" {
			return fmt.Errorf("a redirect to %s: %w", next.URL, ErrRefused)
		}
		return nil
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get %s: %s", rawURL, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("get %s: %w", rawURL, err)
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("get %s: more than %d bytes", rawURL, maxBody)
	}
	return body, nil
}

// sha256Digest is data's digest, as a registry writes it.
func sha256Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
