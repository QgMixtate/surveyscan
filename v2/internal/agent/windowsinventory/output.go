package windowsinventory

import (
	"bytes"
	"context"
	"errors"
)

// Deliberately do not embed bytes.Buffer: its promoted io.ReaderFrom method
// lets io.Copy bypass Write and its limit when copying a child's stdout pipe.
type workerOutput struct {
	buffer bytes.Buffer
	limit  int
	over   bool
	cancel context.CancelFunc
}

func (w *workerOutput) Write(b []byte) (int, error) {
	if len(b) > w.limit-w.buffer.Len() {
		w.over = true
		w.cancel()
		return 0, errors.New("worker output limit")
	}
	return w.buffer.Write(b)
}
