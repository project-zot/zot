//go:build dev
// +build dev

// This file should be linked only in **development** mode.

package inject_test

import (
	"errors"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/pkg/test/inject"
)

var (
	errKey1    = errors.New("key1 not found")
	errKey2    = errors.New("key2 not found")
	errNotZero = errors.New("not zero")
	errCall1   = errors.New("call1 error")
	errCall2   = errors.New("call2 error")
)

func foo() error {
	fmap := map[string]string{"key1": "val1", "key2": "val2"}

	_, ok := fmap["key1"] // should never fail
	if !inject.Ok(ok) {
		return errKey1
	}

	_, ok = fmap["key2"] // should never fail
	if !inject.Ok(ok) {
		return errKey2
	}

	return nil
}

func errgen(i int) error {
	if i != 0 {
		return errNotZero
	}

	return nil
}

func bar() error {
	err := errgen(0) // should never fail
	if inject.Error(err) != nil {
		return errCall1
	}

	err = errgen(0) // should never fail
	if inject.Error(err) != nil {
		return errCall2
	}

	return nil
}

func baz() error {
	if inject.ErrStatusCode(0) != 0 {
		return errCall1
	}

	if inject.ErrStatusCode(0) != 0 {
		return errCall2
	}

	return nil
}

func alwaysErr() error {
	return errNotZero
}

func alwaysNotOk() bool {
	return false
}

func TestInject(t *testing.T) {
	Convey("Injected failure", t, func(c C) {
		// should be success without injection
		err := foo()
		So(err, ShouldBeNil)

		Convey("Check Ok", func() {
			Convey("Without skipping", func() {
				inject.InjectFailure(0) // inject a failure
				err := foo()            // should be a failure
				So(err, ShouldNotBeNil) // should be a failure
				So(errors.Is(err, errKey1), ShouldBeTrue)
			})

			Convey("With skipping", func() {
				inject.InjectFailure(1) // inject a failure but skip first one
				err := foo()            // should be a failure
				So(errors.Is(err, errKey1), ShouldBeFalse)
				So(errors.Is(err, errKey2), ShouldBeTrue)
			})
		})

		// should be success without injection
		err = bar()
		So(err, ShouldBeNil)

		Convey("Check Err", func() {
			Convey("Without skipping", func() {
				inject.InjectFailure(0) // inject a failure
				err := bar()            // should be a failure
				So(err, ShouldNotBeNil) // should be a failure
				So(errors.Is(err, errCall1), ShouldBeTrue)
			})

			Convey("With skipping", func() {
				inject.InjectFailure(1) // inject a failure but skip first one
				err := bar()            // should be a failure
				So(errors.Is(err, errCall1), ShouldBeFalse)
				So(errors.Is(err, errCall2), ShouldBeTrue)
			})
		})

		Convey("Check ErrStatusCode", func() {
			Convey("Without skipping", func() {
				inject.InjectFailure(0) // inject a failure
				err := baz()            // should be a failure
				So(err, ShouldNotBeNil) // should be a failure
				So(errors.Is(err, errCall1), ShouldBeTrue)
			})

			Convey("With skipping", func() {
				inject.InjectFailure(1) // inject a failure but skip first one
				err := baz()            // should be a failure
				So(errors.Is(err, errCall1), ShouldBeFalse)
				So(errors.Is(err, errCall2), ShouldBeTrue)
			})
		})
	})

	Convey("Without injected failure", t, func(c C) {
		err := alwaysErr()
		So(inject.Error(err), ShouldNotBeNil)

		ok := alwaysNotOk()
		So(inject.Ok(ok), ShouldBeFalse)
	})

	Convey("Incomplete injected failure", t, func(c C) {
		inject.InjectFailure(0) // inject a failure
		So(func() { inject.InjectFailure(0) }, ShouldPanic)
	})
}
