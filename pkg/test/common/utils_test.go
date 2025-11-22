package common_test

import (
	"os"
	"path"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/api/config"
	tcommon "zotregistry.dev/zot/v2/pkg/test/common"
)

func TestWaitTillTrivyDBDownloadStarted(t *testing.T) {
	Convey("finishes successfully", t, func() {
		tempDir := t.TempDir()

		go func() {
			tcommon.WaitTillTrivyDBDownloadStarted(tempDir)
		}()

		time.Sleep(tcommon.SleepTime)

		_, err := os.Create(path.Join(tempDir, "trivy.db"))
		So(err, ShouldBeNil)
	})
}

func TestControllerManager(t *testing.T) {
	Convey("Test StartServer Init() panic", t, func() {
		port := tcommon.GetFreePort()

		conf := config.New()
		conf.HTTP.Port = port

		ctlr := api.NewController(conf)
		ctlrManager := tcommon.NewControllerManager(ctlr)

		// No storage configured
		So(func() { ctlrManager.StartServer() }, ShouldPanic)
	})

	Convey("Test RunServer panic", t, func() {
		tempDir := t.TempDir()

		// Invalid port
		conf := config.New()
		conf.HTTP.Port = "999999"
		conf.Storage.RootDirectory = tempDir

		ctlr := api.NewController(conf)
		ctlrManager := tcommon.NewControllerManager(ctlr)

		err := ctlr.Init()
		So(err, ShouldBeNil)

		So(func() { ctlrManager.RunServer() }, ShouldPanic)
	})
}

func TestWaitForLogMessages(t *testing.T) {
	Convey("Test WaitForLogMessages", t, func() {
		Convey("should return true when message count reaches minimum", func() {
			logBuffer := tcommon.NewThreadSafeLogBuffer()

			// Write some log messages
			_, _ = logBuffer.Write([]byte("Starting server\n"))
			_, _ = logBuffer.Write([]byte("Server started successfully\n"))
			_, _ = logBuffer.Write([]byte("Starting server\n"))
			_, _ = logBuffer.Write([]byte("Processing request\n"))
			_, _ = logBuffer.Write([]byte("Starting server\n"))

			// Wait for "Starting server" message to appear at least 3 times
			result := tcommon.WaitForLogMessages(logBuffer, "Starting server", 3, 100*time.Millisecond)

			So(result, ShouldBeTrue)
		})

		Convey("should return false when message count never reaches minimum", func() {
			logBuffer := tcommon.NewThreadSafeLogBuffer()

			// Write some log messages (only 1 occurrence of target message)
			_, _ = logBuffer.Write([]byte("Starting server\n"))
			_, _ = logBuffer.Write([]byte("Server started successfully\n"))
			_, _ = logBuffer.Write([]byte("Processing request\n"))

			// Wait for "Starting server" message to appear at least 3 times
			result := tcommon.WaitForLogMessages(logBuffer, "Starting server", 3, 50*time.Millisecond)

			So(result, ShouldBeFalse)
		})

		Convey("should return true immediately when count already meets requirement", func() {
			logBuffer := tcommon.NewThreadSafeLogBuffer()

			// Write messages before calling WaitForLogMessages
			_, _ = logBuffer.Write([]byte("Starting server\n"))
			_, _ = logBuffer.Write([]byte("Starting server\n"))
			_, _ = logBuffer.Write([]byte("Starting server\n"))

			// Wait for "Starting server" message to appear at least 3 times
			result := tcommon.WaitForLogMessages(logBuffer, "Starting server", 3, 100*time.Millisecond)

			So(result, ShouldBeTrue)
		})

		Convey("should handle empty log buffer", func() {
			logBuffer := tcommon.NewThreadSafeLogBuffer()

			// Wait for any message in empty buffer
			result := tcommon.WaitForLogMessages(logBuffer, "Starting server", 1, 50*time.Millisecond)

			So(result, ShouldBeFalse)
		})

		Convey("should handle partial message matches", func() {
			logBuffer := tcommon.NewThreadSafeLogBuffer()

			// Write messages with partial matches
			_, _ = logBuffer.Write([]byte("Starting server process\n"))
			_, _ = logBuffer.Write([]byte("Starting server\n"))
			_, _ = logBuffer.Write([]byte("Starting server instance\n"))

			// Wait for exact "Starting server" message (not partial matches)
			result := tcommon.WaitForLogMessages(logBuffer, "Starting server", 2, 100*time.Millisecond)

			So(result, ShouldBeTrue)
		})

		Convey("should timeout after specified duration", func() {
			logBuffer := tcommon.NewThreadSafeLogBuffer()

			// Write only one message
			_, _ = logBuffer.Write([]byte("Starting server\n"))

			// Wait for 3 occurrences with short timeout
			start := time.Now()
			result := tcommon.WaitForLogMessages(logBuffer, "Starting server", 3, 10*time.Millisecond)
			duration := time.Since(start)

			So(result, ShouldBeFalse)
			So(duration, ShouldBeGreaterThanOrEqualTo, 10*time.Millisecond)
			So(duration, ShouldBeLessThan, 50*time.Millisecond) // Should timeout quickly
		})

		Convey("should handle concurrent writes", func() {
			logBuffer := tcommon.NewThreadSafeLogBuffer()

			// Simulate concurrent writes
			go func() {
				for range 5 {
					_, _ = logBuffer.Write([]byte("Starting server\n"))

					time.Sleep(5 * time.Millisecond)
				}
			}()

			// Wait for messages to appear
			result := tcommon.WaitForLogMessages(logBuffer, "Starting server", 3, 100*time.Millisecond)

			So(result, ShouldBeTrue)
		})

		Convey("should handle case-sensitive message matching", func() {
			logBuffer := tcommon.NewThreadSafeLogBuffer()

			// Write messages with different cases
			_, _ = logBuffer.Write([]byte("Starting server\n"))
			_, _ = logBuffer.Write([]byte("starting server\n"))
			_, _ = logBuffer.Write([]byte("STARTING SERVER\n"))

			// Wait for exact case match
			result := tcommon.WaitForLogMessages(logBuffer, "Starting server", 2, 100*time.Millisecond)

			So(result, ShouldBeFalse) // Only 1 exact match
		})

		Convey("should handle zero minimum count", func() {
			logBuffer := tcommon.NewThreadSafeLogBuffer()

			// Wait for 0 occurrences (should always return true)
			result := tcommon.WaitForLogMessages(logBuffer, "Starting server", 0, 100*time.Millisecond)

			So(result, ShouldBeTrue)
		})

		Convey("should handle very short timeout", func() {
			logBuffer := tcommon.NewThreadSafeLogBuffer()

			// Write a message
			_, _ = logBuffer.Write([]byte("Starting server\n"))

			// Wait with very short timeout
			result := tcommon.WaitForLogMessages(logBuffer, "Starting server", 1, 1*time.Millisecond)

			So(result, ShouldBeTrue) // Should find it immediately
		})
	})
}
