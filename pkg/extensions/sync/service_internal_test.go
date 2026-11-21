//go:build sync

package sync

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	syncconf "zotregistry.dev/zot/v2/pkg/extensions/config/sync"
)

func TestStripPort(t *testing.T) {
	Convey("stripPort drops the port and keeps everything else", t, func() {
		testCases := []struct {
			name string
			host string
			want string
		}{
			{name: "host without port", host: "ghcr.io", want: "ghcr.io"},
			{name: "host with port", host: "registry.example.com:5000", want: "registry.example.com"},
			{name: "default https port", host: "docker.io:443", want: "docker.io"},
			{name: "case is preserved", host: "GHCR.IO:443", want: "GHCR.IO"},
			{name: "empty host", host: "", want: ""},
		}

		for _, testCase := range testCases {
			Convey(testCase.name, func() {
				So(stripPort(testCase.host), ShouldEqual, testCase.want)
			})
		}
	})
}

func TestIsDockerHubHost(t *testing.T) {
	Convey("isDockerHubHost recognizes only Docker Hub aliases", t, func() {
		testCases := []struct {
			host string
			want bool
		}{
			{host: "docker.io", want: true},
			{host: "registry-1.docker.io", want: true},
			{host: "index.docker.io", want: true},
			{host: "DOCKER.IO", want: true},
			{host: "Registry-1.Docker.Io", want: true},
			{host: "ghcr.io", want: false},
			{host: "registry.k8s.io", want: false},
			{host: "docker.io.example.com", want: false},
			{host: "notdocker.io", want: false},
			{host: "", want: false},
		}

		for _, testCase := range testCases {
			Convey("isDockerHubHost("+testCase.host+")", func() {
				So(isDockerHubHost(testCase.host), ShouldEqual, testCase.want)
			})
		}
	})
}

func TestNormalizeRegistryName(t *testing.T) {
	Convey("normalizeRegistryName lowercases, strips the port and folds Docker Hub aliases", t, func() {
		testCases := []struct {
			host string
			want string
		}{
			{host: "docker.io", want: "docker.io"},
			{host: "registry-1.docker.io", want: "docker.io"},
			{host: "index.docker.io", want: "docker.io"},
			{host: "REGISTRY-1.DOCKER.IO", want: "docker.io"},
			{host: "docker.io:443", want: "docker.io"},
			{host: "GHCR.IO", want: "ghcr.io"},
			{host: "GHCR.IO:443", want: "ghcr.io"},
			{host: "registry.example.com:5000", want: "registry.example.com"},
			{host: "", want: ""},
		}

		for _, testCase := range testCases {
			Convey("normalizeRegistryName("+testCase.host+")", func() {
				So(normalizeRegistryName(testCase.host), ShouldEqual, testCase.want)
			})
		}
	})
}

func TestMatchesRegistry(t *testing.T) {
	newService := func(urls ...string) *BaseService {
		return &BaseService{config: syncconf.RegistryConfig{URLs: urls}}
	}

	Convey("MatchesRegistry", t, func() {
		testCases := []struct {
			name string
			urls []string
			ns   string
			want bool
		}{
			{
				name: "empty ns matches a service without URLs",
				ns:   "",
				want: true,
			},
			{
				name: "empty ns matches a configured service",
				urls: []string{"https://ghcr.io"},
				want: true,
			},
			{
				name: "empty ns matches even when the URL is invalid",
				urls: []string{"http://bad-registry-url]"},
				want: true,
			},
			{
				name: "non-empty ns does not match a service without URLs",
				ns:   "ghcr.io",
				want: false,
			},
			{
				name: "exact host match",
				urls: []string{"https://ghcr.io"},
				ns:   "ghcr.io",
				want: true,
			},
			{
				name: "host match is case-insensitive against the configured URL",
				urls: []string{"https://GHCR.IO"},
				ns:   "ghcr.io",
				want: true,
			},
			{
				name: "host match is case-insensitive against ns",
				urls: []string{"https://ghcr.io"},
				ns:   "GHCR.IO",
				want: true,
			},
			{
				name: "matching host with a configured path",
				urls: []string{"https://ghcr.io/v2/"},
				ns:   "ghcr.io",
				want: true,
			},
			{
				name: "different host does not match",
				urls: []string{"https://ghcr.io"},
				ns:   "docker.io",
				want: false,
			},
			{
				name: "explicit port must match exactly",
				urls: []string{"https://registry.example.com:5000"},
				ns:   "registry.example.com:5000",
				want: true,
			},
			{
				name: "portless ns does not match a registry using an explicit port",
				urls: []string{"https://registry.example.com:5000"},
				ns:   "registry.example.com",
				want: false,
			},
			{
				name: "ns with a port does not match a portless registry",
				urls: []string{"https://registry.example.com"},
				ns:   "registry.example.com:5000",
				want: false,
			},
			{
				name: "matches any of the configured URLs",
				urls: []string{"https://mirror.example.com", "https://ghcr.io"},
				ns:   "ghcr.io",
				want: true,
			},
			{
				name: "skips an invalid URL and matches the next one",
				urls: []string{"http://bad-registry-url]", "https://ghcr.io"},
				ns:   "ghcr.io",
				want: true,
			},
			{
				name: "all URLs invalid does not match",
				urls: []string{"http://bad-registry-url]"},
				ns:   "ghcr.io",
				want: false,
			},
			{
				name: "skips a URL that fails to parse and matches the next one",
				urls: []string{"http://[::1", "https://ghcr.io"},
				ns:   "ghcr.io",
				want: true,
			},
			{
				name: "a URL that fails to parse does not match",
				urls: []string{"http://[::1"},
				ns:   "ghcr.io",
				want: false,
			},
			{
				name: "docker.io alias matches registry-1.docker.io",
				urls: []string{"https://docker.io"},
				ns:   "registry-1.docker.io",
				want: true,
			},
			{
				name: "docker.io alias matches index.docker.io",
				urls: []string{"https://docker.io"},
				ns:   "index.docker.io",
				want: true,
			},
			{
				name: "registry-1.docker.io matches the docker.io alias",
				urls: []string{"https://registry-1.docker.io"},
				ns:   "docker.io",
				want: true,
			},
			{
				name: "Docker Hub matching is port-insensitive on the configured URL",
				urls: []string{"https://registry-1.docker.io:443"},
				ns:   "docker.io",
				want: true,
			},
			{
				name: "Docker Hub matching is port-insensitive on ns",
				urls: []string{"https://index.docker.io"},
				ns:   "docker.io:443",
				want: true,
			},
			{
				name: "uppercase Docker Hub alias matches",
				urls: []string{"https://docker.io"},
				ns:   "INDEX.DOCKER.IO",
				want: true,
			},
			{
				name: "docker.io does not match a non-Hub registry",
				urls: []string{"https://docker.io"},
				ns:   "ghcr.io",
				want: false,
			},
			{
				name: "a non-Hub registry does not match docker.io",
				urls: []string{"https://ghcr.io"},
				ns:   "docker.io",
				want: false,
			},
		}

		for _, testCase := range testCases {
			Convey(testCase.name, func() {
				So(newService(testCase.urls...).MatchesRegistry(testCase.ns), ShouldEqual, testCase.want)
			})
		}
	})
}
