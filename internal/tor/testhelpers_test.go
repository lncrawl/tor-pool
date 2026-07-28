package tor

import (
	"io"
	"net"
	"strings"
	"time"
)

// discardConn is a net.Conn that swallows writes, letting tests drive command()
// against a canned reply reader without a real socket.
type discardConn struct{}

func (discardConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (discardConn) Write(b []byte) (int, error)      { return len(b), nil }
func (discardConn) Close() error                     { return nil }
func (discardConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (discardConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (discardConn) SetDeadline(time.Time) error      { return nil }
func (discardConn) SetReadDeadline(time.Time) error  { return nil }
func (discardConn) SetWriteDeadline(time.Time) error { return nil }

// recordConn is a discardConn that keeps what was written to it, for tests that
// care about the exact command sent.
type recordConn struct{ sb *strings.Builder }

func (c recordConn) Read([]byte) (int, error)       { return 0, io.EOF }
func (c recordConn) Write(b []byte) (int, error)    { return c.sb.Write(b) }
func (recordConn) Close() error                     { return nil }
func (recordConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (recordConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (recordConn) SetDeadline(time.Time) error      { return nil }
func (recordConn) SetReadDeadline(time.Time) error  { return nil }
func (recordConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "127.0.0.1:0" }
