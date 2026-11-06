package windowsinventory

import (
	"context"
	"io"
	"strings"
	"testing"
)

type readerOnly struct{ io.Reader }

func TestWorkerOutputCannotBypassLimitThroughIOCopy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &workerOutput{limit: 1 << 20, cancel: cancel}
	if _, bypass := any(out).(io.ReaderFrom); bypass {
		t.Fatal("destination fast path can bypass Write")
	}
	_, err := io.Copy(out, readerOnly{strings.NewReader(strings.Repeat("x", 2<<20))})
	if err == nil || !out.over || out.buffer.Len() > out.limit || ctx.Err() != context.Canceled {
		t.Fatal("child pipe output bypassed the bound or did not cancel execution")
	}
}
