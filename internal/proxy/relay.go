package proxy

import (
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
)

// relayBufferSize is per direction per connection. 32 KiB is a compromise:
// large enough that a fast download is not syscall-bound, small enough that a
// pool serving hundreds of concurrent connections does not balloon.
const relayBufferSize = 32 * 1024

// relayResult reports what a completed relay transferred and whether the
// transport failed.
type relayResult struct {
	BytesUp   int64 // client → target
	BytesDown int64 // target → client
	Err       error
}

// relay copies bytes both ways until either side finishes, then returns totals.
//
// A normal proxy connection ends with one side closing, so an EOF or a "use of
// closed connection" is success, not failure. Only a genuine transport error —
// a reset, an unreachable network — counts against the instance, because
// misclassifying here would quarantine healthy instances for doing their job.
func relay(client, upstream net.Conn) relayResult {
	var (
		wg   sync.WaitGroup
		up   int64
		down int64
		errs [2]error
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		up, errs[0] = copyStream(upstream, client)
		// Half-close so the target sees the client's EOF and can respond,
		// instead of waiting for a full close that may never come.
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		down, errs[1] = copyStream(client, upstream)
		closeWrite(client)
	}()
	wg.Wait()

	return relayResult{BytesUp: up, BytesDown: down, Err: errors.Join(errs[0], errs[1])}
}

func copyStream(dst, src net.Conn) (int64, error) {
	buf := make([]byte, relayBufferSize)
	n, err := io.CopyBuffer(dst, src, buf)
	if isExpectedClose(err) {
		return n, nil
	}
	return n, err
}

// closeWrite half-closes a TCP connection when possible.
func closeWrite(conn net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = conn.Close()
}

// isExpectedClose reports whether an error is the ordinary end of a proxied
// connection rather than a fault worth scoring.
func isExpectedClose(err error) bool {
	switch {
	case err == nil,
		errors.Is(err, io.EOF),
		errors.Is(err, net.ErrClosed),
		errors.Is(err, syscall.EPIPE),
		// A client that navigates away resets rather than closing cleanly.
		// That is the client's business, not the instance's fault.
		errors.Is(err, syscall.ECONNRESET):
		return true
	default:
		return false
	}
}
