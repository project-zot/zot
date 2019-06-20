package api

import (
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
)

func NewLogger(config *Config) zerolog.Logger {
	zerolog.TimeFieldFormat = time.RFC3339Nano
	lvl, err := zerolog.ParseLevel(config.Log.Level)
	if err != nil {
		panic(err)
	}
	zerolog.SetGlobalLevel(lvl)
	var log zerolog.Logger
	if config.Log.Output == "" {
		log = zerolog.New(os.Stdout)
	} else {
		file, err := os.OpenFile(config.Log.Output, os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			panic(err)
		}
		log = zerolog.New(file)
	}
	return log.With().Timestamp().Logger()
}

func Logger(log zerolog.Logger) gin.HandlerFunc {
	l := log.With().Str("module", "http").Logger()
	return func(ginCtx *gin.Context) {
		// Start timer
		start := time.Now()
		path := ginCtx.Request.URL.Path
		raw := ginCtx.Request.URL.RawQuery

		// Process request
		ginCtx.Next()

		// Stop timer
		end := time.Now()
		latency := end.Sub(start)
		if latency > time.Minute {
			// Truncate in a golang < 1.8 safe way
			latency -= latency % time.Second
		}
		clientIP := ginCtx.ClientIP()
		method := ginCtx.Request.Method
		headers := ginCtx.Request.Header
		statusCode := ginCtx.Writer.Status()
		errMsg := ginCtx.Errors.ByType(gin.ErrorTypePrivate).String()
		bodySize := ginCtx.Writer.Size()
		if raw != "" {
			path = path + "?" + raw
		}

		l.Info().
			Str("clientIP", clientIP).
			Str("method", method).
			Str("path", path).
			Int("statusCode", statusCode).
			Str("errMsg", errMsg).
			Str("latency", latency.String()).
			Int("bodySize", bodySize).
			Interface("headers", headers).
			Msg("HTTP API")
	}
}
