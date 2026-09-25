package server //nolint:testpackage // white-box tests for URL helpers

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api/config"
)

func TestBuildHealthcheckURL(t *testing.T) {
	Convey("override url appends endpoint when path missing", t, func() {
		got, err := buildHealthcheckURL(nil, "readyz", "http://127.0.0.1:5000")
		So(err, ShouldBeNil)
		So(got, ShouldEqual, "http://127.0.0.1:5000/readyz")
	})

	Convey("override url keeps explicit path", t, func() {
		got, err := buildHealthcheckURL(nil, "readyz", "http://127.0.0.1:5000/livez")
		So(err, ShouldBeNil)
		So(got, ShouldEqual, "http://127.0.0.1:5000/livez")
	})

	Convey("config rewrites 0.0.0.0 and enables https", t, func() {
		conf := config.New()
		conf.HTTP.Address = "0.0.0.0"
		conf.HTTP.Port = "8443"
		conf.HTTP.TLS = &config.TLSConfig{Cert: "/cert", Key: "/key"}

		got, err := buildHealthcheckURL(conf, "livez", "")
		So(err, ShouldBeNil)
		So(got, ShouldEqual, "https://127.0.0.1:8443/livez")
	})

	Convey("nil config falls back to config.New() defaults", t, func() {
		got, err := buildHealthcheckURL(nil, "readyz", "")
		So(err, ShouldBeNil)
		So(got, ShouldEqual, "http://127.0.0.1:8080/readyz")
	})

	Convey("config.New() defaults are used when no file is loaded", t, func() {
		conf := config.New()
		got, err := buildHealthcheckURL(conf, "readyz", "")
		So(err, ShouldBeNil)
		So(got, ShouldEqual, "http://127.0.0.1:8080/readyz")
	})

	Convey("ipv6 unspecified address maps to loopback", t, func() {
		conf := config.New()
		conf.HTTP.Address = "::"
		conf.HTTP.Port = "5000"

		got, err := buildHealthcheckURL(conf, "readyz", "")
		So(err, ShouldBeNil)
		So(got, ShouldEqual, "http://[::1]:5000/readyz")
	})

	Convey("invalid override url is rejected", t, func() {
		_, err := buildHealthcheckURL(nil, "readyz", "://bad")
		So(err, ShouldNotBeNil)

		_, err = buildHealthcheckURL(nil, "readyz", "/readyz")
		So(err, ShouldNotBeNil)
	})
}

func TestResolveHealthcheckHost(t *testing.T) {
	Convey("rewrites unspecified addresses", t, func() {
		So(resolveHealthcheckHost(""), ShouldEqual, "127.0.0.1")
		So(resolveHealthcheckHost("0.0.0.0"), ShouldEqual, "127.0.0.1")
		So(resolveHealthcheckHost("::"), ShouldEqual, "::1")
		So(resolveHealthcheckHost("[::]"), ShouldEqual, "::1")
		So(resolveHealthcheckHost("192.168.1.10"), ShouldEqual, "192.168.1.10")
	})

	Convey("strips brackets from IPv6 literals", t, func() {
		So(resolveHealthcheckHost("[::1]"), ShouldEqual, "::1")
		So(resolveHealthcheckHost("[2001:db8::1]"), ShouldEqual, "2001:db8::1")
	})
}

func TestValidateHealthcheckEndpoint(t *testing.T) {
	Convey("allows known endpoints", t, func() {
		So(validateHealthcheckEndpoint("livez"), ShouldBeNil)
		So(validateHealthcheckEndpoint("readyz"), ShouldBeNil)
		So(validateHealthcheckEndpoint("startupz"), ShouldBeNil)
	})

	Convey("rejects unknown endpoints", t, func() {
		So(validateHealthcheckEndpoint("healthz"), ShouldNotBeNil)
		So(validateHealthcheckEndpoint(""), ShouldNotBeNil)
	})
}
