package api

import (
	"encoding/json"
	"net/http"
	"runtime"

	"github.com/gorilla/mux"

	"zotregistry.dev/zot/pkg/log"
)

type Stack struct {
	Frames []Frame `json:"stack"`
}

type Frame struct {
	Name string `json:"function"`
	File string `json:"file"`
	Line int    `json:"line"`
}

// RecoveryHandler is a HTTP middleware that recovers from a panic.
// It logs the panic and its traceback in json format, writes http.StatusInternalServerError
// and continues to the next handler.
func RecoveryHandler(log log.Logger) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					response.WriteHeader(http.StatusInternalServerError)

					stack := Stack{
						Frames: getStacktrace(),
					}

					recoveredErr, ok := err.(error)
					if ok {
						buf, err := json.Marshal(stack)
						if err == nil {
							log.Error().Err(recoveredErr).RawJSON("traceback", buf).Msg("panic recovered") //nolint: check-logs
						}
					}
				}
			}()

			// Process request
			next.ServeHTTP(response, request)
		})
	}
}

func getStacktrace() []Frame {
	stack := []Frame{}
	//nolint: varnamelen
	pc := make([]uintptr, 64)

	n := runtime.Callers(0, pc)
	if n == 0 {
		return []Frame{}
	}

	// first three frames are from this file, don't need them.
	pc = pc[3:]
	frames := runtime.CallersFrames(pc)

	// loop to get frames.
	for {
		frame, more := frames.Next()

		// store this frame
		stack = append(stack, Frame{
			Name: frame.Function,
			File: frame.File,
			Line: frame.Line,
		})

		// check whether there are more frames to process after this one.
		if !more {
			break
		}
	}

	return stack
}
