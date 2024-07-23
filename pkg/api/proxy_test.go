//go:build sync && scrub && metrics && search && lint && userprefs && mgmt && imagetrust && ui
// +build sync,scrub,metrics,search,lint,userprefs,mgmt,imagetrust,ui

package api_test

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
	"zotregistry.dev/zot/pkg/api"
)

func TestGetLocalMemberClusterSocket(t *testing.T) {
	Convey("Should return an error if a domain name doesn't exist", t, func() {
		localSockets := []string{"127.0.0.1:9000", "172.16.0.1:9000"}
		members := []string{"127.0.0.1:9001", "thisdoesnotexist:9000", "127.0.0.1:9000"}
		index, socket, err := api.GetLocalMemberClusterSocket(members, localSockets)
		So(err.Error(), ShouldContainSubstring, "lookup thisdoesnotexist")
		So(index, ShouldEqual, -1)
		So(socket, ShouldEqual, "")
	})

	Convey("Should return an error if a local socket is missing a port", t, func() {
		localSockets := []string{"127.0.0.1", "172.16.0.1:9000"}
		members := []string{"127.0.0.1:9001", "www.github.com:443", "127.0.0.1:9000"}
		index, socket, err := api.GetLocalMemberClusterSocket(members, localSockets)
		So(err.Error(), ShouldEqual, "address 127.0.0.1: missing port in address")
		So(index, ShouldEqual, -1)
		So(socket, ShouldEqual, "")
	})

	Convey("Should return an error if a member socket is missing a port", t, func() {
		localSockets := []string{"127.0.0.1:9000", "172.16.0.1:9000"}
		members := []string{"127.0.0.1:9001", "www.github.com", "127.0.0.1:9000"}
		index, socket, err := api.GetLocalMemberClusterSocket(members, localSockets)
		So(err.Error(), ShouldEqual, "address www.github.com: missing port in address")
		So(index, ShouldEqual, -1)
		So(socket, ShouldEqual, "")
	})

	Convey("Should return the right socket when a local socket is part of members", t, func() {
		localSockets := []string{"127.0.0.1:9000", "172.16.0.1:9000"}
		members := []string{"127.0.0.1:9001", "www.github.com:443", "127.0.0.1:9000"}
		index, socket, err := api.GetLocalMemberClusterSocket(members, localSockets)
		So(err, ShouldBeNil)
		So(index, ShouldEqual, 2)
		So(socket, ShouldEqual, "127.0.0.1:9000")
	})

	Convey("Should return empty when no local socket is part of members", t, func() {
		localSockets := []string{"127.0.0.1:9000", "172.16.0.1:9000"}
		members := []string{"127.0.0.1:9002", "127.0.0.1:9001", "www.github.com:443"}
		index, socket, err := api.GetLocalMemberClusterSocket(members, localSockets)
		So(err, ShouldBeNil)
		So(index, ShouldEqual, -1)
		So(socket, ShouldBeEmpty)
	})
}
