// Copyright 2026 The OpenSandbox Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Outputs owns the canonical physical destinations for one output worker.
// Only that worker may write, sync or close them after ownership is transferred.
// Audit is info-level and unsampled; ordinary encoding uses NewWithWriter.
type Outputs struct {
	Out, Errors zapcore.WriteSyncer
	Audit       *zap.Logger
	closers     []io.Closer
}

func (o *Outputs) Close() error {
	var result error
	for _, closer := range o.closers {
		if err := closer.Close(); result == nil {
			result = err
		}
	}
	return result
}

// OpenOutputs shares rotation and deduplicates canonical destinations. Legacy
// New deliberately retains its synchronous output multiplicity instead.
func OpenOutputs(cfg Config) (*Outputs, error) {
	cfg = applyEnvOutputs(cfg)
	// Match the legacy empty-core stdout fallback without changing its empty
	// default error route, which was resolved before this fallback.
	if len(cfg.OutputPaths) == 0 {
		cfg.OutputPaths = []string{"stdout"}
	}
	if cfg.Rotate == nil {
		cfg.Rotate = &RotateConfig{}
	}
	cfg.Rotate.applyDefaults()
	outputs := &Outputs{}
	ready := false
	defer func() {
		if !ready {
			for _, closer := range outputs.closers {
				_ = closer.Close()
			}
		}
	}()
	writers := make(map[string]zapcore.WriteSyncer)
	identities := make(map[string]os.FileInfo)
	var opaque map[string]*os.File
	canonical := func(paths []string) ([]string, error) {
		keys := make([]string, 0, len(paths))
		seen := make(map[string]bool)
		for _, path := range paths {
			if err := validateOutputPath(path); err != nil {
				return nil, fmt.Errorf("invalid output path %q: %w", path, err)
			}
			key := path
			var info os.FileInfo
			switch path {
			case "stdout":
				info, _ = os.Stdout.Stat() // Identity is optional for legacy console paths.
			case "stderr":
				info, _ = os.Stderr.Stat()
			default:
				var err error
				info, err = os.Stat(path)
				if err != nil {
					return nil, fmt.Errorf("invalid output path %q: %w", path, err)
				}
				key, err = filepath.Abs(path)
				if err != nil {
					return nil, err
				}
			}
			shared := false
			for existing, identity := range identities {
				if info != nil && identity != nil && os.SameFile(info, identity) {
					key, shared = existing, true
					break
				}
			}
			// Kernel identity works for stream aliases even when a procfs magic
			// link's displayed target (pipe:[inode], for example) is not a path.
			// Regular files rotate only when they also have a usable filename.
			if !shared && path != "stdout" && path != "stderr" && info.Mode().IsRegular() {
				resolved, err := filepath.EvalSymlinks(key)
				if err == nil {
					key = resolved
				} else {
					if !os.IsNotExist(err) {
						return nil, err
					}
					// An opaque descriptor may still be kernel-openable after its
					// regular file was unlinked. Prove that without creating a path
					// or accepting an object different from the one we inspected.
					file, openErr := os.OpenFile(key, os.O_WRONLY|os.O_APPEND, 0644)
					if openErr != nil {
						return nil, fmt.Errorf("open output path %q: %w", path, openErr)
					}
					opened, statErr := file.Stat()
					if statErr != nil {
						_ = file.Close()
						return nil, statErr
					}
					if !os.SameFile(info, opened) {
						_ = file.Close()
						return nil, err
					}
					if opaque == nil {
						opaque = make(map[string]*os.File)
					}
					opaque[key] = file
					outputs.closers = append(outputs.closers, file)
				}
			}
			identities[key] = info
			if !seen[key] {
				keys = append(keys, key)
				seen[key] = true
			}
		}
		return keys, nil
	}
	paths, err := canonical(cfg.OutputPaths)
	if err != nil {
		return nil, err
	}
	errors, err := canonical(cfg.ErrorOutputPaths)
	if err != nil {
		return nil, err
	}
	for path, info := range identities {
		var stream *os.File
		switch path {
		case "stdout":
			stream = os.Stdout
		case "stderr":
			stream = os.Stderr
		default:
			if stream = opaque[path]; stream != nil {
				break
			}
			if info.Mode().IsRegular() {
				file := rotatingFile(path, cfg.Rotate)
				writers[path] = zapcore.AddSync(file)
				outputs.closers = append(outputs.closers, file)
				continue
			}
			stream, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				return nil, fmt.Errorf("open output path %q: %w", path, err)
			}
			outputs.closers = append(outputs.closers, stream)
		}
		// os.File serializes complete writes. Streams have no durability Sync
		// and must never be rotated, truncated or closed before the output worker exits.
		writers[path] = zapcore.AddSync(struct{ io.Writer }{stream})
	}
	destination := func(paths []string) zapcore.WriteSyncer {
		sinks := make([]zapcore.WriteSyncer, 0, len(paths))
		for _, path := range paths {
			sinks = append(sinks, writers[path])
		}
		return zapcore.NewMultiWriteSyncer(sinks...)
	}
	outputs.Out, outputs.Errors = destination(paths), destination(errors)
	outputs.Audit = zap.New(zapcore.NewCore(productionEncoder(), outputs.Out, zapcore.InfoLevel), zap.ErrorOutput(outputs.Errors))
	ready = true
	return outputs, nil
}

// NewWithWriter applies ordinary level, sampling and encoding before Write.
// The supplied writers own admission, flushing and destination lifetime.
func NewWithWriter(cfg Config, out, errs zapcore.WriteSyncer) Logger {
	level := parseLevel(cfg.Level)
	if len(applyEnvOutputs(cfg).OutputPaths) == 0 {
		level = zapcore.InfoLevel // Legacy empty-core fallback ignores configured level.
	}
	return buildLogger(zapcore.NewCore(productionEncoder(), out, level), errs)
}
