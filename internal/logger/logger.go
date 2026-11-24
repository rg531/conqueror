// Copyright 2026 Florian Krutzler
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"log/slog"
	"os"
	"github.com/mattn/go-isatty"
	"github.com/lmittmann/tint"
)

func init() {
	var handler slog.Handler

	if isatty.IsTerminal(os.Stdout.Fd()) {
		handler = tint.NewHandler(os.Stdout, nil)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, nil)
	}

	slog.SetDefault(slog.New(handler))
}

