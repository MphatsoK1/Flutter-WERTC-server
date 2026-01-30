package logger

import (
	"os"
	"time"

	"github.com/rs/zerolog"
)

var (
	log      zerolog.Logger
	logLevel = zerolog.DebugLevel // Default
)

// Level defines log levels matching zerolog constants
type Level int8

const (
	DebugLevel Level = iota
	InfoLevel
	WarnLevel
	ErrorLevel
	FatalLevel
	PanicLevel
	NoLevel
	Disabled Level = -1
)

func init() {
	// Set default output to console with color for development
	output := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
		NoColor:    false,
	}
	
	log = zerolog.New(output).With().Timestamp().Logger()
	
	// Set level from environment variable if present
	if levelStr := os.Getenv("LOG_LEVEL"); levelStr != "" {
		if level, err := zerolog.ParseLevel(levelStr); err == nil {
			SetLevel(Level(level))
		}
	} else {
		SetLevel(DebugLevel)
	}
}

// SetLevel sets the global log level
func SetLevel(l Level) {
	level := zerolog.Level(l)
	zerolog.SetGlobalLevel(level)
	logLevel = level
	log.Info().Int8("level", int8(l)).Msg("Log level changed")
}

// WithContext returns a new logger with structured fields
func WithContext(fields map[string]interface{}) zerolog.Logger {
	logCtx := log.With()
	for k, v := range fields {
		logCtx = logCtx.Interface(k, v)
	}
	return logCtx.Logger()
}

// Infof logs at Info level
func Infof(format string, v ...interface{}) {
	if logLevel <= zerolog.InfoLevel {
		log.Info().Msgf(format, v...)
	}
}

// Debugf logs at Debug level
func Debugf(format string, v ...interface{}) {
	if logLevel <= zerolog.DebugLevel {
		log.Debug().Msgf(format, v...)
	}
}

// Warnf logs at Warn level
func Warnf(format string, v ...interface{}) {
	if logLevel <= zerolog.WarnLevel {
		log.Warn().Msgf(format, v...)
	}
}

// Errorf logs at Error level
func Errorf(format string, v ...interface{}) {
	if logLevel <= zerolog.ErrorLevel {
		log.Error().Msgf(format, v...)
	}
}

// Panicf logs at Panic level
func Panicf(format string, v ...interface{}) {
	if logLevel <= zerolog.PanicLevel {
		log.Panic().Msgf(format, v...)
	}
}

// Fatalf logs at Fatal level
func Fatalf(format string, v ...interface{}) {
	if logLevel <= zerolog.FatalLevel {
		log.Fatal().Msgf(format, v...)
	}
}