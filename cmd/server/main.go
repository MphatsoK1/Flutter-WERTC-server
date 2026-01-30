package main

import (
	"os"
	"path/filepath"

	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/logger"
	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/signaler"
	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/turn"
	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/websocket"
	"gopkg.in/ini.v1"
)

func main() {
	// Load configuration
	cfg, err := ini.Load("configs/config.ini")
	if err != nil {
		logger.Errorf("Fail to read config file: %v", err)
		os.Exit(1)
	}

	// TURN Configuration
	publicIP := cfg.Section("turn").Key("public_ip").String()
	if publicIP == "" {
		logger.Panicf("TURN public_ip is required for cross-network connectivity")
	}

	stunPort, err := cfg.Section("turn").Key("port").Int()
	if err != nil {
		stunPort = 3478
	}

	realm := cfg.Section("turn").Key("realm").String()
	if realm == "" {
		realm = "flutter-webrtc.org" // Default realm
	}

	// TURN Authentication Secret (CRITICAL for TURN functionality)
	authSecret := cfg.Section("turn").Key("auth_secret").String()
	if authSecret == "" {
		logger.Panicf("TURN auth_secret is required for TURN server authentication")
	}

	// Configure TURN server
	turnConfig := turn.DefaultConfig()
	turnConfig.PublicIP = publicIP
	turnConfig.Port = stunPort
	turnConfig.Realm = realm
	turnConfig.AuthSecret = cfg.Section("turn").Key("auth_secret").String()
	// Enable both UDP and TCP for better compatibility
	turnConfig.TransportProtocols = []string{"udp", "tcp"}
	
	turnServer := turn.NewTurnServer(turnConfig)
	logger.Infof("TURN server configured on %s:%d", publicIP, stunPort)

	// Signaling server
	signaler := signaler.NewSignaler(turnServer)
	
	// WebSocket server configuration
	wsServer := websocket.NewWebSocketServer(
		signaler.HandleNewWebSocket, 
		signaler.HandleTurnServerCredentials,
	)

	// General server configuration
	sslCert := cfg.Section("general").Key("cert").String()
	sslKey := cfg.Section("general").Key("key").String()
	
	// Verify SSL/TLS certificate files exist if specified
	if sslCert != "" && sslKey != "" {
		sslCert = filepath.Clean(sslCert)
		sslKey = filepath.Clean(sslKey)
		
		if _, err := os.Stat(sslCert); os.IsNotExist(err) {
			logger.Errorf("SSL certificate file not found: %s", sslCert)
			logger.Warningf("Server will run without TLS (NOT recommended for production)")
			sslCert = ""
			sslKey = ""
		} else if _, err := os.Stat(sslKey); os.IsNotExist(err) {
			logger.Errorf("SSL key file not found: %s", sslKey)
			logger.Warningf("Server will run without TLS (NOT recommended for production)")
			sslCert = ""
			sslKey = ""
		} else {
			logger.Infof("TLS enabled with certificate: %s", sslCert)
		}
	} else {
		logger.Warningf("No TLS certificates configured. Server will use plain WebSocket (ws://)")
		logger.Warningf("For production with HTTPS, provide cert and key paths in config")
	}

	// Bind address - use 0.0.0.0 for cross-network access
	bindAddress := cfg.Section("general").Key("bind").String()
	if bindAddress == "" {
		bindAddress = "0.0.0.0" // Bind to all network interfaces
		logger.Infof("Binding to all network interfaces (0.0.0.0)")
	}

	port, err := cfg.Section("general").Key("port").Int()
	if err != nil {
		port = 8086
	}

	htmlRoot := cfg.Section("general").Key("html_root").String()
	if htmlRoot == "" {
		htmlRoot = "./web"
	}

	// WebSocket server final configuration
	config := websocket.DefaultConfig()
	config.Host = bindAddress
	config.Port = port
	config.CertFile = sslCert
	config.KeyFile = sslKey
	config.HTMLRoot = htmlRoot
	
	// Enable CORS for cross-origin requests (important for web clients)
	config.EnableCORS = true
	config.CORSAllowedOrigins = []string{"*"} // For testing; restrict in production

	logger.Infof("Starting WebRTC signaling server on %s:%d", bindAddress, port)
	if sslCert != "" && sslKey != "" {
		logger.Infof("TLS enabled: wss://%s:%d", publicIP, port)
	} else {
		logger.Infof("TLS disabled: ws://%s:%d", publicIP, port)
	}
	
	// Start the server
	wsServer.Bind(config)
}