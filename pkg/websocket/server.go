package websocket

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/logger"
	"github.com/gorilla/websocket"
)

type WebSocketServerConfig struct {
	Host           string
	Port           int
	CertFile       string
	KeyFile        string
	HTMLRoot       string
	WebSocketPath  string
	TurnServerPath string
	EnableCORS     bool
	CORSAllowedOrigins []string
}

func DefaultConfig() WebSocketServerConfig {
	return WebSocketServerConfig{
		Host:           "0.0.0.0",
		Port:           8086,
		HTMLRoot:       "web",
		WebSocketPath:  "/ws",
		TurnServerPath: "/api/turn",
		EnableCORS:     true,
		CORSAllowedOrigins: []string{"*"},
	}
}

type WebSocketServer struct {
	handleWebSocket  func(ws *WebSocketConn, request *http.Request)
	handleTurnServer func(writer http.ResponseWriter, request *http.Request)
	upgrader         websocket.Upgrader
	server           *http.Server
}

func NewWebSocketServer(
	wsHandler func(ws *WebSocketConn, request *http.Request),
	turnServerHandler func(writer http.ResponseWriter, request *http.Request)) *WebSocketServer {
	
	server := &WebSocketServer{
		handleWebSocket:  wsHandler,
		handleTurnServer: turnServerHandler,
	}
	
	// Configure WebSocket upgrader with proper CORS for cross-network access
	server.upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			// For cross-network access, we need to check origin
			origin := r.Header.Get("Origin")
			
			// Allow all origins for testing (be more restrictive in production)
			// In production, validate against allowed domains
			return true
		},
		// Enable compression for better cross-network performance
		EnableCompression: true,
		// Set reasonable buffer sizes
		ReadBufferSize:  1024 * 32,  // 32KB
		WriteBufferSize: 1024 * 32,  // 32KB
	}
	
	return server
}

func (server *WebSocketServer) handleWebSocketRequest(writer http.ResponseWriter, request *http.Request) {
	// Add CORS headers for cross-network access
	if origin := request.Header.Get("Origin"); origin != "" {
		writer.Header().Set("Access-Control-Allow-Origin", origin)
		writer.Header().Set("Access-Control-Allow-Credentials", "true")
	}
	
	responseHeader := http.Header{}
	// You can add custom protocols if needed
	// responseHeader.Add("Sec-WebSocket-Protocol", "protoo")
	
	socket, err := server.upgrader.Upgrade(writer, request, responseHeader)
	if err != nil {
		logger.Errorf("Failed to upgrade WebSocket connection: %v", err)
		http.Error(writer, "Failed to upgrade to WebSocket", http.StatusBadRequest)
		return
	}
	
	wsTransport := NewWebSocketConn(socket)
	server.handleWebSocket(wsTransport, request)
	
	// Start reading messages in a goroutine
	go wsTransport.ReadMessage()
}

func (server *WebSocketServer) handleTurnServerRequest(writer http.ResponseWriter, request *http.Request) {
	// Add CORS headers for cross-network API access
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	writer.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	writer.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	
	// Handle preflight requests
	if request.Method == "OPTIONS" {
		writer.WriteHeader(http.StatusOK)
		return
	}
	
	server.handleTurnServer(writer, request)
}

func (server *WebSocketServer) Bind(cfg WebSocketServerConfig) {
	// Configure HTTP server with proper timeouts for cross-network reliability
	server.server = &http.Server{
		Addr: cfg.Host + ":" + strconv.Itoa(cfg.Port),
		// Important timeouts for cross-network connections
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}
	
	// Set up request handlers
	http.HandleFunc(cfg.WebSocketPath, server.handleWebSocketRequest)
	http.HandleFunc(cfg.TurnServerPath, server.handleTurnServerRequest)
	
	// Serve static files (optional)
	if cfg.HTMLRoot != "" {
		http.Handle("/", http.FileServer(http.Dir(cfg.HTMLRoot)))
		logger.Infof("Serving static files from: %s", cfg.HTMLRoot)
	}
	
	// Handle graceful shutdown
	go server.gracefulShutdown()
	
	// Start server with TLS if certificates are provided
	logger.Infof("Flutter WebRTC Server starting on: %s:%d", cfg.Host, cfg.Port)
	
	var err error
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		// Verify certificates exist
		if _, certErr := os.Stat(cfg.CertFile); os.IsNotExist(certErr) {
			logger.Errorf("Certificate file not found: %s", cfg.CertFile)
		}
		if _, keyErr := os.Stat(cfg.KeyFile); os.IsNotExist(keyErr) {
			logger.Errorf("Key file not found: %s", cfg.KeyFile)
		}
		
		logger.Infof("Starting with TLS (wss://)")
		err = server.server.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
	} else {
		logger.Warnf("Starting without TLS (ws://) - NOT recommended for production")
		logger.Warnf("WebRTC requires HTTPS/WSS for cross-network connections in most browsers")
		err = server.server.ListenAndServe()
	}
	
	if err != nil && err != http.ErrServerClosed {
		logger.Errorf("Server error: %v", err)
		os.Exit(1)
	}
}

func (server *WebSocketServer) gracefulShutdown() {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	
	<-stop
	logger.Infof("Shutting down server gracefully...")
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	if err := server.server.Shutdown(ctx); err != nil {
		logger.Errorf("Error during shutdown: %v", err)
	}
	
	logger.Infof("Server stopped")
}

// Shutdown gracefully stops the server
func (server *WebSocketServer) Shutdown() {
	if server.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		server.server.Shutdown(ctx)
	}
}

// Helper to get server address for clients
func (server *WebSocketServer) GetAddress(cfg WebSocketServerConfig) string {
	protocol := "ws"
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		protocol = "wss"
	}
	return fmt.Sprintf("%s://%s:%d%s", protocol, cfg.Host, cfg.Port, cfg.WebSocketPath)
}

// Helper to get TURN server API URL
func (server *WebSocketServer) GetTurnAPIURL(cfg WebSocketServerConfig) string {
	protocol := "http"
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		protocol = "https"
	}
	return fmt.Sprintf("%s://%s:%d%s", protocol, cfg.Host, cfg.Port, cfg.TurnServerPath)
}