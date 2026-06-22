package core

import (
	"context"

	"github.com/vigolium/vigolium/pkg/work"
)

// InputSource is the minimal pull-based input contract the executor needs.
// Packages such as pkg/input/source implement this interface without core
// importing their heavier parsing/discovery dependencies.
type InputSource interface {
	Next(ctx context.Context) (*work.WorkItem, error)
	Close() error
}

// CountableInputSource is implemented by input sources with a known total size.
type CountableInputSource interface {
	Count() int64
}
