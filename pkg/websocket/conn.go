package websocket

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/chuckpreslar/emission"
	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/logger"
	"github.com/gorilla/websocket"
)

const (
	// Connection timeouts
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10 // Send pings more frequently than pong timeout
	maxMessageSize = 512 * 1024          // 512KB max message size
)

type WebSocketConn struct {
	emission.Emitter
	socket    *websocket.Conn
	mutex     *sync.RWMutex
	closed    bool
	closeOnce sync.Once
	ctx       context.Context
	cancel    context.CancelFunc
}

func NewWebSocketConn(socket *websocket.Conn) *WebSocketConn {
	ctx, cancel := context.WithCancel(context.Background())
	
	conn := &WebSocketConn{
		Emitter: *emission.NewEmitter(),
		socket:  socket,
		mutex:   new(sync.RWMutex),
		closed:  false,
		ctx:     ctx,
		cancel:  cancel,
	}
	
	// Configure WebSocket connection
	conn.socket.SetReadLimit(maxMessageSize)
	conn.socket.SetReadDeadline(time.Now().Add(pongWait))
	
	// Set proper WebSocket ping/pong handlers (CRITICAL for cross-network)
	conn.socket.SetPongHandler(func(string) error {
		conn.socket.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})
	
	// Set close handler
	conn.socket.SetCloseHandler(func(code int, text string) error {
		logger.Debugf("WebSocket close: %s [%d]", text, code)
		conn.internalClose(code, text)
		return nil
	})
	
	return conn
}

func (conn *WebSocketConn) ReadMessage() {
	// Start ping ticker
	pingTicker := time.NewTicker(pingPeriod)
	defer func() {
		pingTicker.Stop()
		conn.internalClose(1000, "reader stopped")
	}()

	// Message processing goroutine
	for {
		select {
		case <-conn.ctx.Done():
			return
		case <-pingTicker.C:
			// Send WebSocket ping frame (not text message)
			conn.mutex.Lock()
			if !conn.closed {
				conn.socket.SetWriteDeadline(time.Now().Add(writeWait))
				if err := conn.socket.WriteMessage(websocket.PingMessage, nil); err != nil {
					logger.Debugf("Failed to send ping: %v", err)
					conn.mutex.Unlock()
					return
				}
			}
			conn.mutex.Unlock()
		default:
			// Read message with timeout
			conn.socket.SetReadDeadline(time.Now().Add(pongWait))
			messageType, message, err := conn.socket.ReadMessage()
			
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					logger.Debugf("WebSocket read error: %v", err)
				}
				conn.internalClose(1006, err.Error())
				return
			}
			
			if messageType == websocket.TextMessage || messageType == websocket.BinaryMessage {
				conn.Emit("message", message)
			} else if messageType == websocket.CloseMessage {
				return
			}
		}
	}
}

/*
* Send |message| to the connection with timeout.
*/
func (conn *WebSocketConn) Send(message string) error {
	conn.mutex.RLock()
	if conn.closed {
		conn.mutex.RUnlock()
		return errors.New("websocket: connection closed")
	}
	
	// Set write deadline
	conn.socket.SetWriteDeadline(time.Now().Add(writeWait))
	conn.mutex.RUnlock()
	
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	
	// Double-check after acquiring write lock
	if conn.closed {
		return errors.New("websocket: connection closed")
	}
	
	logger.Debugf("Send data: %s", message)
	return conn.socket.WriteMessage(websocket.TextMessage, []byte(message))
}

/*
* Send binary data to the connection.
*/
func (conn *WebSocketConn) SendBinary(data []byte) error {
	conn.mutex.RLock()
	if conn.closed {
		conn.mutex.RUnlock()
		return errors.New("websocket: connection closed")
	}
	
	conn.socket.SetWriteDeadline(time.Now().Add(writeWait))
	conn.mutex.RUnlock()
	
	conn.mutex.Lock()
	defer conn.mutex.Unlock()
	
	if conn.closed {
		return errors.New("websocket: connection closed")
	}
	
	return conn.socket.WriteMessage(websocket.BinaryMessage, data)
}

/*
* Close connection gracefully.
*/
func (conn *WebSocketConn) Close() {
	conn.internalClose(1000, "normal closure")
}

/*
* Internal close with proper cleanup.
*/
func (conn *WebSocketConn) internalClose(code int, reason string) {
	conn.closeOnce.Do(func() {
		conn.mutex.Lock()
		defer conn.mutex.Unlock()
		
		if !conn.closed {
			logger.Debugf("Closing WebSocket connection: %s [%d]", reason, code)
			
			// Send close message if possible
			if conn.socket != nil {
				conn.socket.SetWriteDeadline(time.Now().Add(writeWait))
				conn.socket.WriteMessage(websocket.CloseMessage, 
					websocket.FormatCloseMessage(code, reason))
				conn.socket.Close()
			}
			
			conn.closed = true
			
			// Cancel context to stop all goroutines
			if conn.cancel != nil {
				conn.cancel()
			}
			
			// Emit close event
			conn.Emit("close", code, reason)
		}
	})
}

/*
* Check if connection is closed.
*/
func (conn *WebSocketConn) IsClosed() bool {
	conn.mutex.RLock()
	defer conn.mutex.RUnlock()
	return conn.closed
}