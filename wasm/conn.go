package main

import (
	"errors"
	"io"
	"net"
	"sync"
	"syscall/js"
	"time"
)

// wsConn 将浏览器 JavaScript 的 WebSocket 包装为 Go 标准库的 net.Conn 接口
// 使得 golang.org/x/crypto/ssh 可以直接在浏览器内部通过 WebSocket 隧道进行握手与传输
type wsConn struct {
	ws        js.Value
	recvCh    chan []byte
	doneCh    chan struct{}
	closeOnce sync.Once
	buf       []byte
	closed    bool
	closeMu   sync.Mutex
	onMessage js.Func
	onClose   js.Func
}

func newWSConn(ws js.Value) *wsConn {
	c := &wsConn{
		ws:     ws,
		recvCh: make(chan []byte, 2048),
		doneCh: make(chan struct{}),
	}

	// 设定 WebSocket 二进制类型为 arraybuffer
	ws.Set("binaryType", "arraybuffer")

	// 注册消息接收处理器
	c.onMessage = js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) == 0 {
			return nil
		}
		data := args[0].Get("data")
		if data.InstanceOf(js.Global().Get("ArrayBuffer")) {
			u8 := js.Global().Get("Uint8Array").New(data)
			length := u8.Get("byteLength").Int()
			b := make([]byte, length)
			js.CopyBytesToGo(b, u8)
			
			c.closeMu.Lock()
			closed := c.closed
			c.closeMu.Unlock()

			if !closed {
				select {
				case c.recvCh <- b:
				case <-c.doneCh:
				default:
					// 缓冲区溢出保护：严禁阻塞 JS 主线程，触发安全断开
					_ = c.Close()
				}
			}
		}
		return nil
	})
	ws.Set("onmessage", c.onMessage)

	c.onClose = js.FuncOf(func(this js.Value, args []js.Value) any {
		_ = c.Close()
		return nil
	})
	ws.Set("onclose", c.onClose)

	return c
}

func (c *wsConn) Read(b []byte) (n int, err error) {
	if len(c.buf) > 0 {
		n = copy(b, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}

	select {
	case data, ok := <-c.recvCh:
		if !ok {
			return 0, io.EOF
		}
		n = copy(b, data)
		if n < len(data) {
			c.buf = data[n:]
		}
		return n, nil
	case <-c.doneCh:
		return 0, io.EOF
	}
}

func (c *wsConn) Write(b []byte) (n int, err error) {
	select {
	case <-c.doneCh:
		return 0, errors.New("websocket connection closed")
	default:
	}

	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return 0, errors.New("websocket connection closed")
	}

	u8 := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(u8, b)
	c.ws.Call("send", u8)
	return len(b), nil
}

func (c *wsConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeMu.Lock()
		c.closed = true
		c.closeMu.Unlock()

		close(c.doneCh)
		c.ws.Call("close")

		// 释放 JS 导出回调，彻底杜绝 WebAssembly 句柄泄漏
		c.onMessage.Release()
		c.onClose.Release()
	})
	return nil
}

func (c *wsConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *wsConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *wsConn) SetDeadline(t time.Time) error      { return nil }
func (c *wsConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *wsConn) SetWriteDeadline(t time.Time) error { return nil }
