package api

import (
	goerrors "errors"
	"fmt"
	"net"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	zoterrors "zotregistry.dev/zot/v2/errors"
	"zotregistry.dev/zot/v2/pkg/api/config"
	"zotregistry.dev/zot/v2/pkg/log"
)

type nonTCPAddr struct{}

func (nonTCPAddr) Network() string { return "unix" }
func (nonTCPAddr) String() string  { return "/tmp/zot.sock" }

type nonTCPListener struct{}

func (nonTCPListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (nonTCPListener) Close() error              { return nil }
func (nonTCPListener) Addr() net.Addr            { return nonTCPAddr{} }

func withMockActivation(t *testing.T, fn func() ([]net.Listener, error)) {
	t.Helper()

	original := systemdActivationListeners
	t.Cleanup(func() { systemdActivationListeners = original })

	systemdActivationListeners = fn
}

func TestCreateListener(t *testing.T) {
	Convey("createListener", t, func() {
		conf := config.New()
		ctlr := &Controller{
			Config: conf,
			Log:    log.NewLogger("debug", ""),
		}

		Convey("uses systemd socket activation listener", func() {
			activated, err := net.Listen("tcp", "127.0.0.1:0")
			So(err, ShouldBeNil)

			withMockActivation(t, func() ([]net.Listener, error) {
				return []net.Listener{activated}, nil
			})

			// port "0" means unspecified -- any activated port is accepted
			conf.HTTP.Port = "0"
			listener, addr, err := ctlr.createListener("127.0.0.1:0", conf.GetHTTPPort())
			So(err, ShouldBeNil)
			So(listener, ShouldNotBeNil)

			defer listener.Close()

			wantPort := activated.Addr().(*net.TCPAddr).Port
			So(ctlr.GetPort(), ShouldEqual, wantPort)
			So(addr, ShouldEqual, activated.Addr().String())
		})

		Convey("rejects multiple systemd listeners", func() {
			first, err := net.Listen("tcp", "127.0.0.1:0")
			So(err, ShouldBeNil)

			defer first.Close()

			second, err := net.Listen("tcp", "127.0.0.1:0")
			So(err, ShouldBeNil)

			defer second.Close()

			withMockActivation(t, func() ([]net.Listener, error) {
				return []net.Listener{first, second, nil}, nil
			})

			_, _, err = ctlr.createListener("127.0.0.1:0", conf.GetHTTPPort())
			So(err, ShouldNotBeNil)
			So(goerrors.Is(err, zoterrors.ErrExpectedOneSystemdListener), ShouldBeTrue)
		})

		Convey("wraps activation.Listeners error with sentinel", func() {
			withMockActivation(t, func() ([]net.Listener, error) {
				return nil, goerrors.New("sd_listen_fds failed")
			})

			_, _, err := ctlr.createListener("127.0.0.1:0", conf.GetHTTPPort())
			So(err, ShouldNotBeNil)
			So(goerrors.Is(err, zoterrors.ErrFailedSystemdActivationListeners), ShouldBeTrue)
		})

		Convey("rejects nil listener in activation slice", func() {
			withMockActivation(t, func() ([]net.Listener, error) {
				return []net.Listener{nil}, nil
			})

			_, _, err := ctlr.createListener("127.0.0.1:0", conf.GetHTTPPort())
			So(err, ShouldNotBeNil)
			So(goerrors.Is(err, zoterrors.ErrSystemdListenerNotStream), ShouldBeTrue)
		})

		Convey("rejects non-TCP listener with wrapped ErrBadType", func() {
			withMockActivation(t, func() ([]net.Listener, error) {
				return []net.Listener{nonTCPListener{}}, nil
			})

			_, _, err := ctlr.createListener("127.0.0.1:0", conf.GetHTTPPort())
			So(err, ShouldNotBeNil)
			So(goerrors.Is(err, zoterrors.ErrBadType), ShouldBeTrue)
		})

		Convey("fails when activated port mismatches configured port", func() {
			activated, err := net.Listen("tcp", "127.0.0.1:0")
			So(err, ShouldBeNil)

			defer activated.Close()

			withMockActivation(t, func() ([]net.Listener, error) {
				return []net.Listener{activated}, nil
			})

			// set config to a port that differs from the activated one
			conf.HTTP.Port = "9999"
			_, _, err = ctlr.createListener("127.0.0.1:9999", conf.GetHTTPPort())
			So(err, ShouldNotBeNil)
			So(goerrors.Is(err, zoterrors.ErrSystemdActivationPortMismatch), ShouldBeTrue)
		})

		Convey("accepts activated port when config port matches", func() {
			activated, err := net.Listen("tcp", "127.0.0.1:0")
			So(err, ShouldBeNil)

			actualPort := activated.Addr().(*net.TCPAddr).Port

			withMockActivation(t, func() ([]net.Listener, error) {
				return []net.Listener{activated}, nil
			})

			conf.HTTP.Port = fmt.Sprintf("%d", actualPort)
			listener, _, err := ctlr.createListener("127.0.0.1:0", conf.GetHTTPPort())
			So(err, ShouldBeNil)
			So(listener, ShouldNotBeNil)

			defer listener.Close()

			So(ctlr.GetPort(), ShouldEqual, actualPort)
		})

		Convey("falls back to configured address when no activation", func() {
			withMockActivation(t, func() ([]net.Listener, error) {
				return nil, nil
			})

			conf.HTTP.Port = "0"
			listener, addr, err := ctlr.createListener("127.0.0.1:0", conf.GetHTTPPort())
			So(err, ShouldBeNil)
			So(listener, ShouldNotBeNil)

			defer listener.Close()

			So(ctlr.GetPort(), ShouldBeGreaterThan, 0)
			So(addr, ShouldEqual, "127.0.0.1:0")
		})

		Convey("returns error for invalid fallback address", func() {
			withMockActivation(t, func() ([]net.Listener, error) {
				return nil, nil
			})

			_, _, err := ctlr.createListener("invalid-host:99999", conf.GetHTTPPort())
			So(err, ShouldNotBeNil)
		})
	})
}

func TestSetChosenPortBadType(t *testing.T) {
	Convey("setChosenPort rejects non-TCP listener", t, func() {
		ctlr := &Controller{
			Log: log.NewLogger("debug", ""),
		}

		err := ctlr.setChosenPort(nonTCPListener{}, "8080", false)
		So(err, ShouldNotBeNil)
		So(goerrors.Is(err, zoterrors.ErrBadType), ShouldBeTrue)
	})
}
