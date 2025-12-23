package api_test

import (
	"os"
	"strings"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"

	"zotregistry.dev/zot/v2/pkg/api"
	"zotregistry.dev/zot/v2/pkg/log"
	test "zotregistry.dev/zot/v2/pkg/test/common"
)

func TestHTPasswdWatcherOriginal(t *testing.T) {
	logger := log.NewLogger("DEBUG", "")

	Convey("reload htpasswd", t, func(c C) {
		username, _ := test.GenerateRandomString()
		password1, _ := test.GenerateRandomString()
		password2, _ := test.GenerateRandomString()
		htpasswdPath := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username, password1))

		htp := api.NewHTPasswd(logger)

		htw, err := api.NewHTPasswdWatcher(htp, "")
		So(err, ShouldBeNil)

		// Start the watcher goroutine
		htw.Run()

		defer htw.Close() //nolint: errcheck

		_, present := htp.Get(username)
		So(present, ShouldBeFalse)

		err = htw.ChangeFile(htpasswdPath)
		So(err, ShouldBeNil)

		// 1. Check user present and it has password1
		ok, present := htp.Authenticate(username, password1)
		So(ok, ShouldBeTrue)
		So(present, ShouldBeTrue)

		ok, present = htp.Authenticate(username, password2)
		So(ok, ShouldBeFalse)
		So(present, ShouldBeTrue)

		// 2. Change file
		err = os.WriteFile(htpasswdPath, []byte(test.GetBcryptCredString(username, password2)), 0o600)
		So(err, ShouldBeNil)

		// 3. Give some time for the background task
		time.Sleep(10 * time.Millisecond)

		// 4. Check user present and now has password2
		ok, present = htp.Authenticate(username, password1)
		So(ok, ShouldBeFalse)
		So(present, ShouldBeTrue)

		ok, present = htp.Authenticate(username, password2)
		So(ok, ShouldBeTrue)
		So(present, ShouldBeTrue)
	})
}

func TestHTPasswdWatcher(t *testing.T) {
	logger := log.NewLogger("DEBUG", "")

	Convey("Test HTPasswdWatcher comprehensive functionality", t, func() {
		Convey("Test basic operations and lifecycle", func() {
			// Create a buffer to capture log output
			logBuffer, multiWriter := test.CreateLogCapturingWriter(os.Stdout)
			capturingLogger := log.NewLoggerWithWriter("debug", multiWriter)

			htp := api.NewHTPasswd(capturingLogger)
			htw, err := api.NewHTPasswdWatcher(htp, "")
			So(err, ShouldBeNil)

			// Test Run() and Close() operations
			So(func() { htw.Run() }, ShouldNotPanic)
			time.Sleep(10 * time.Millisecond)
			So(func() { htw.Run() }, ShouldNotPanic) // Idempotent
			time.Sleep(10 * time.Millisecond)
			So(func() { htw.Close() }, ShouldNotPanic)
			time.Sleep(10 * time.Millisecond)
			So(htw.Close(), ShouldBeNil) // Idempotent

			// Verify goroutine termination
			So(test.WaitForLogMessages(logBuffer, "htpasswd watcher terminating...", 1, 5*time.Second), ShouldBeTrue)
		})

		Convey("Test ChangeFile() operations and file watching", func() {
			username1, _ := test.GenerateRandomString()
			password1, _ := test.GenerateRandomString()
			username2, _ := test.GenerateRandomString()
			password2, _ := test.GenerateRandomString()

			htpasswdPath1 := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username1, password1))
			htpasswdPath2 := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username2, password2))

			htp := api.NewHTPasswd(logger)
			htw, err := api.NewHTPasswdWatcher(htp, "")
			So(err, ShouldBeNil)

			// Test ChangeFile() when not running
			err = htw.ChangeFile(htpasswdPath1)
			So(err, ShouldBeNil)
			ok, present := htp.Authenticate(username1, password1)
			So(ok, ShouldBeTrue)
			So(present, ShouldBeTrue)

			// Start watcher and test ChangeFile() when running
			htw.Run()
			defer htw.Close()
			time.Sleep(10 * time.Millisecond)

			// Change to second file
			err = htw.ChangeFile(htpasswdPath2)
			So(err, ShouldBeNil)
			time.Sleep(10 * time.Millisecond)
			ok, present = htp.Authenticate(username2, password2)
			So(ok, ShouldBeTrue)
			So(present, ShouldBeTrue)
			_, present = htp.Authenticate(username1, password1)
			So(present, ShouldBeFalse)

			// Test ChangeFile() to empty string (clear store)
			err = htw.ChangeFile("")
			So(err, ShouldBeNil)
			time.Sleep(10 * time.Millisecond)
			_, present = htp.Authenticate(username2, password2)
			So(present, ShouldBeFalse)

			// Test ChangeFile() with non-existent file
			err = htw.ChangeFile("/non/existent/path")
			So(err, ShouldNotBeNil)

			// Test file change detection and reload
			err = htw.ChangeFile(htpasswdPath1)
			So(err, ShouldBeNil)
			time.Sleep(10 * time.Millisecond)
			ok, present = htp.Authenticate(username1, password1)
			So(ok, ShouldBeTrue)
			So(present, ShouldBeTrue)

			// Change file content and verify automatic reload
			err = os.WriteFile(htpasswdPath1, []byte(test.GetBcryptCredString(username1, password2)), 0o600)
			So(err, ShouldBeNil)
			time.Sleep(100 * time.Millisecond)
			ok, present = htp.Authenticate(username1, password2)
			So(ok, ShouldBeTrue)
			So(present, ShouldBeTrue)

			// Test multiple users
			multiUserContent := test.GetBcryptCredString(username1, password1) +
				"\n" + test.GetBcryptCredString(username2, password2)
			err = os.WriteFile(htpasswdPath1, []byte(multiUserContent), 0o600)
			So(err, ShouldBeNil)
			time.Sleep(100 * time.Millisecond)
			ok, present = htp.Authenticate(username1, password1)
			So(ok, ShouldBeTrue)
			So(present, ShouldBeTrue)
			ok, present = htp.Authenticate(username2, password2)
			So(ok, ShouldBeTrue)
			So(present, ShouldBeTrue)

			// Test invalid content (clears store)
			err = os.WriteFile(htpasswdPath1, []byte("invalid-content"), 0o600)
			So(err, ShouldBeNil)
			time.Sleep(100 * time.Millisecond)
			_, present = htp.Authenticate(username1, password1)
			So(present, ShouldBeFalse)

			// Test empty file (clears store)
			err = os.WriteFile(htpasswdPath1, []byte(""), 0o600)
			So(err, ShouldBeNil)
			time.Sleep(100 * time.Millisecond)
			_, present = htp.Authenticate(username2, password2)
			So(present, ShouldBeFalse)
		})

		Convey("Test restart capability, edge cases, and file operations", func() {
			// Create a buffer to capture log output
			logBuffer, multiWriter := test.CreateLogCapturingWriter(os.Stdout)
			capturingLogger := log.NewLoggerWithWriter("debug", multiWriter)

			username1, _ := test.GenerateRandomString()
			password1, _ := test.GenerateRandomString()
			username2, _ := test.GenerateRandomString()
			password2, _ := test.GenerateRandomString()

			htpasswdPath1 := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username1, password1))
			htpasswdPath2 := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username2, password2))

			htp := api.NewHTPasswd(capturingLogger)
			htw, err := api.NewHTPasswdWatcher(htp, htpasswdPath1)
			So(err, ShouldBeNil)

			// Test restart capability
			htw.Run()
			time.Sleep(10 * time.Millisecond)
			err = htw.ChangeFile(htpasswdPath1)
			So(err, ShouldBeNil)
			time.Sleep(10 * time.Millisecond)
			ok, present := htp.Authenticate(username1, password1)
			So(ok, ShouldBeTrue)
			So(present, ShouldBeTrue)

			// Close and restart
			So(htw.Close(), ShouldBeNil)
			So(test.WaitForLogMessages(logBuffer, "htpasswd watcher terminating...", 1, 5*time.Second), ShouldBeTrue)
			htw.Run()
			time.Sleep(10 * time.Millisecond)

			// Change file after restart
			err = htw.ChangeFile(htpasswdPath2)
			So(err, ShouldBeNil)
			time.Sleep(10 * time.Millisecond)
			ok, present = htp.Authenticate(username2, password2)
			So(ok, ShouldBeTrue)
			So(present, ShouldBeTrue)

			// Test file becomes inaccessible
			os.Remove(htpasswdPath2)
			time.Sleep(100 * time.Millisecond)
			ok, present = htp.Authenticate(username2, password2)
			So(ok, ShouldBeTrue) // User should still be present
			So(present, ShouldBeTrue)

			// Test file rename (should not trigger reload)
			htpasswdPath3 := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username1, password1))
			err = htw.ChangeFile(htpasswdPath3)
			So(err, ShouldBeNil)
			time.Sleep(10 * time.Millisecond)
			ok, present = htp.Authenticate(username1, password1)
			So(ok, ShouldBeTrue)
			So(present, ShouldBeTrue)

			newPath := htpasswdPath3 + ".new"
			err = os.Rename(htpasswdPath3, newPath)
			So(err, ShouldBeNil)

			defer os.Remove(newPath)
			time.Sleep(100 * time.Millisecond)
			ok, _ = htp.Authenticate(username1, password1)
			So(ok, ShouldBeTrue) // User should still be present

			// Test file permission change (should not trigger reload)
			err = os.Chmod(newPath, 0o000)
			So(err, ShouldBeNil)

			defer func() { _ = os.Chmod(newPath, 0o644) }()
			time.Sleep(100 * time.Millisecond)
			ok, _ = htp.Authenticate(username1, password1)
			So(ok, ShouldBeTrue) // User should still be present

			// Test with non-existent directory
			htw2, err := api.NewHTPasswdWatcher(htp, "/non/existent/dir/htpasswd")
			So(err, ShouldBeNil)
			So(func() { htw2.Run() }, ShouldNotPanic)
			time.Sleep(10 * time.Millisecond)
			So(htw2.Close(), ShouldBeNil)
			// 1 termination message
			So(test.WaitForLogMessages(logBuffer, "htpasswd watcher terminating...", 1, 5*time.Second), ShouldBeTrue)

			// Test with very long file path
			var longPathBuilder strings.Builder
			longPathBuilder.WriteString("/tmp/")

			for range 100 {
				longPathBuilder.WriteString("verylongdirname")
			}
			longPathBuilder.WriteString("/htpasswd")
			longPath := longPathBuilder.String()
			htw3, err := api.NewHTPasswdWatcher(htp, longPath)
			So(err, ShouldBeNil)
			So(func() { htw3.Run() }, ShouldNotPanic)
			time.Sleep(10 * time.Millisecond)
			So(htw3.Close(), ShouldBeNil)
			// 1 termination message
			So(test.WaitForLogMessages(logBuffer, "htpasswd watcher terminating...", 1, 5*time.Second), ShouldBeTrue)

			// Clean up
			So(htw.Close(), ShouldBeNil)
			// 1 termination message
			So(test.WaitForLogMessages(logBuffer, "htpasswd watcher terminating...", 1, 5*time.Second), ShouldBeTrue)
		})

		Convey("Test concurrent operations and goroutine cleanup", func() {
			// Create a buffer to capture log output
			logBuffer, multiWriter := test.CreateLogCapturingWriter(os.Stdout)
			capturingLogger := log.NewLoggerWithWriter("debug", multiWriter)

			username1, _ := test.GenerateRandomString()
			password1, _ := test.GenerateRandomString()
			username2, _ := test.GenerateRandomString()
			password2, _ := test.GenerateRandomString()

			htpasswdPath1 := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username1, password1))
			htpasswdPath2 := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username2, password2))

			htp := api.NewHTPasswd(capturingLogger)
			htw, err := api.NewHTPasswdWatcher(htp, "")
			So(err, ShouldBeNil)

			// Test concurrent Run() and Close()
			go func() {
				for range 5 {
					htw.Run()
					time.Sleep(1 * time.Millisecond)
				}
			}()

			go func() {
				for range 5 {
					htw.Close()
					time.Sleep(1 * time.Millisecond)
				}
			}()

			time.Sleep(50 * time.Millisecond)
			So(func() { htw.Close() }, ShouldNotPanic)
			So(test.WaitForLogMessages(logBuffer, "htpasswd watcher terminating...", 1, 5*time.Second), ShouldBeTrue)

			// Test concurrent ChangeFile() operations
			htw.Run()
			defer htw.Close()

			go func() {
				for range 3 {
					_ = htw.ChangeFile(htpasswdPath1)

					time.Sleep(1 * time.Millisecond)
				}
			}()

			go func() {
				for range 3 {
					_ = htw.ChangeFile(htpasswdPath2)

					time.Sleep(1 * time.Millisecond)
				}
			}()

			time.Sleep(50 * time.Millisecond)

			// At least one user should be present
			ok1, present1 := htp.Authenticate(username1, password1)
			ok2, present2 := htp.Authenticate(username2, password2)
			So(present1 || present2, ShouldBeTrue)
			So(ok1 || ok2, ShouldBeTrue)

			// Test goroutine cleanup with multiple verification methods
			htw2, err := api.NewHTPasswdWatcher(htp, "")
			So(err, ShouldBeNil)

			// Start watcher
			htw2.Run()
			time.Sleep(10 * time.Millisecond)

			// Close watcher
			So(htw2.Close(), ShouldBeNil)

			// Wait for goroutine to terminate (check log messages)
			// 1 termination message
			So(test.WaitForLogMessages(logBuffer, "htpasswd watcher terminating...", 1, 5*time.Second), ShouldBeTrue)

			// Verify we can restart the watcher (indicates proper cleanup)
			htw2.Run()
			time.Sleep(10 * time.Millisecond)
			So(htw2.Close(), ShouldBeNil)
			// 1 termination message
			So(test.WaitForLogMessages(logBuffer, "htpasswd watcher terminating...", 1, 5*time.Second), ShouldBeTrue)

			// Test multiple Run/Close cycles
			for range 3 {
				htw2.Run()
				time.Sleep(10 * time.Millisecond)
				So(htw2.Close(), ShouldBeNil)
				time.Sleep(50 * time.Millisecond) // Give time for termination
			}
		})

		Convey("Test goroutine termination with comprehensive log verification", func() {
			// Create a buffer to capture log output
			logBuffer, multiWriter := test.CreateLogCapturingWriter(os.Stdout)
			capturingLogger := log.NewLoggerWithWriter("debug", multiWriter)

			// Test 1: Basic termination verification (no file watching)
			htp1 := api.NewHTPasswd(capturingLogger)
			htw1, err := api.NewHTPasswdWatcher(htp1, "")
			So(err, ShouldBeNil)

			htw1.Run()
			time.Sleep(10 * time.Millisecond)
			So(htw1.Close(), ShouldBeNil)
			So(test.WaitForLogMessages(logBuffer, "htpasswd watcher terminating...", 1, 5*time.Second), ShouldBeTrue)

			// Test 2: File watching with fsnotify resources cleanup
			username, _ := test.GenerateRandomString()
			password, _ := test.GenerateRandomString()
			htpasswdPath := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username, password))

			htp2 := api.NewHTPasswd(capturingLogger)
			htw2, err := api.NewHTPasswdWatcher(htp2, htpasswdPath)
			So(err, ShouldBeNil)

			// Start watcher with file
			htw2.Run()
			time.Sleep(10 * time.Millisecond)

			// Load file to ensure watcher is active
			err = htw2.ChangeFile(htpasswdPath)
			So(err, ShouldBeNil)
			time.Sleep(10 * time.Millisecond)

			// Close watcher and verify termination
			So(htw2.Close(), ShouldBeNil)
			// 1 + 1 = 2
			So(test.WaitForLogMessages(logBuffer, "htpasswd watcher terminating...", 2, 5*time.Second), ShouldBeTrue)

			// Test 3: Multiple termination cycles with file watching
			for range 3 {
				htw2.Run()
				time.Sleep(10 * time.Millisecond)
				So(htw2.Close(), ShouldBeNil)
				time.Sleep(50 * time.Millisecond) // Give time for termination
			}

			// Verify we have at least 3 termination messages so far (2 previous + 1 cycle = 3)
			So(test.WaitForLogMessages(logBuffer, "htpasswd watcher terminating...", 3, 5*time.Second), ShouldBeTrue)

			// Test 4: Stress test with rapid cycles
			for range 5 {
				htw2.Run()
				time.Sleep(5 * time.Millisecond)
				So(htw2.Close(), ShouldBeNil)
				time.Sleep(20 * time.Millisecond) // Give time for termination
			}

			// Verify we have at least 8 termination messages so far (3+5 = 8)
			So(test.WaitForLogMessages(logBuffer, "htpasswd watcher terminating...", 8, 5*time.Second), ShouldBeTrue)

			// Final verification: watcher should still work after all cycles
			htw2.Run()
			time.Sleep(10 * time.Millisecond)
			So(htw2.Close(), ShouldBeNil)

			// Final verification of all termination messages with timeout
			So(test.WaitForLogMessages(logBuffer, "htpasswd watcher terminating...", 9, 5*time.Second), ShouldBeTrue) // 8+1 = 9
		})

		Convey("Test malformed htpasswd files", func() {
			// Create a buffer to capture log output
			logBuffer, multiWriter := test.CreateLogCapturingWriter(os.Stdout)
			capturingLogger := log.NewLoggerWithWriter("debug", multiWriter)

			username, _ := test.GenerateRandomString()
			password, _ := test.GenerateRandomString()

			htp := api.NewHTPasswd(capturingLogger)

			// Test file with only colons (malformed)
			colonPath := test.MakeHtpasswdFileFromString(t, ":::")
			htw1, err := api.NewHTPasswdWatcher(htp, colonPath)
			So(err, ShouldBeNil)
			htw1.Run()
			time.Sleep(10 * time.Millisecond)
			_ = htw1.ChangeFile(colonPath)

			time.Sleep(10 * time.Millisecond)
			// The malformed file creates an entry with empty username, so test that
			_, present := htp.Authenticate("", "anything")
			So(present, ShouldBeTrue) // Empty username entry exists but auth fails
			ok, _ := htp.Authenticate("", "anything")
			So(ok, ShouldBeFalse) // But authentication should fail
			So(htw1.Close(), ShouldBeNil)
			So(test.WaitForLogMessages(logBuffer, "htpasswd watcher terminating...", 1, 5*time.Second), ShouldBeTrue)

			// Test file with empty lines and comments
			content := "\n\n" + test.GetBcryptCredString(username, password) + "\n# comment\n"
			commentedPath := test.MakeHtpasswdFileFromString(t, content)
			htw2, err := api.NewHTPasswdWatcher(htp, commentedPath)
			So(err, ShouldBeNil)
			htw2.Run()
			time.Sleep(10 * time.Millisecond)
			_ = htw2.ChangeFile(commentedPath)

			time.Sleep(10 * time.Millisecond)
			ok, _ = htp.Authenticate(username, password)
			So(ok, ShouldBeTrue) // User should be loaded (comments/empty lines ignored)
			So(htw2.Close(), ShouldBeNil)
			// 1 termination message
			So(test.WaitForLogMessages(logBuffer, "htpasswd watcher terminating...", 1, 5*time.Second), ShouldBeTrue)
		})

		Convey("Test ChangeFile with nil watcher and empty filepath", func() {
			// Create a logger (no need for log capture since we're not testing goroutine termination)
			capturingLogger := log.NewLogger("debug", "")

			username, _ := test.GenerateRandomString()
			password, _ := test.GenerateRandomString()

			htp := api.NewHTPasswd(capturingLogger)
			htw, err := api.NewHTPasswdWatcher(htp, "")
			So(err, ShouldBeNil)

			// Load some initial data
			htpasswdPath := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username, password))

			// Load initial file (this will populate the store)
			err = htw.ChangeFile(htpasswdPath)
			So(err, ShouldBeNil)

			// Verify user is loaded
			ok, present := htp.Authenticate(username, password)
			So(ok, ShouldBeTrue)
			So(present, ShouldBeTrue)

			// Now test the edge case: ChangeFile with empty string when watcher is nil
			// (watcher is nil because we haven't called Run() yet)
			err = htw.ChangeFile("")
			So(err, ShouldBeNil) // Should not return an error

			// Verify that the store was cleared
			ok, present = htp.Authenticate(username, password)
			So(ok, ShouldBeFalse)      // Authentication should fail
			So(present, ShouldBeFalse) // User should not be present

			// Test that we can still load a file after clearing
			err = htw.ChangeFile(htpasswdPath)
			So(err, ShouldBeNil)

			// Verify user is loaded again
			ok, present = htp.Authenticate(username, password)
			So(ok, ShouldBeTrue)
			So(present, ShouldBeTrue)
		})

		Convey("Test htpasswd file with zero users warning", func() {
			// Create a buffer to capture log output
			logBuffer, multiWriter := test.CreateLogCapturingWriter(os.Stdout)
			capturingLogger := log.NewLoggerWithWriter("debug", multiWriter)

			username, _ := test.GenerateRandomString()
			password, _ := test.GenerateRandomString()

			htp := api.NewHTPasswd(capturingLogger)

			// Create an empty htpasswd file (zero users)
			emptyPath := test.MakeHtpasswdFileFromString(t, "")

			// Reload the empty file
			err := htp.Reload(emptyPath)
			So(err, ShouldBeNil)

			// Verify the warning message is logged
			So(test.WaitForLogMessages(logBuffer, "loaded htpasswd file appears to have zero users", 1, 5*time.Second),
				ShouldBeTrue)

			// Verify store is empty
			_, present := htp.Get(username)
			So(present, ShouldBeFalse)

			// Now load a file with a user and verify the info message instead
			userPath := test.MakeHtpasswdFileFromString(t, test.GetBcryptCredString(username, password))

			err = htp.Reload(userPath)
			So(err, ShouldBeNil)

			// Verify the info message is logged
			So(test.WaitForLogMessages(logBuffer, "loaded htpasswd file", 1, 5*time.Second), ShouldBeTrue)

			// Verify user is present
			ok, present := htp.Authenticate(username, password)
			So(ok, ShouldBeTrue)
			So(present, ShouldBeTrue)
		})
	})
}
