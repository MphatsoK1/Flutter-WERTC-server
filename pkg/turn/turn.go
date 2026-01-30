package turn

import (
	"net"
	"strconv"
	"time"

	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/logger"
	"github.com/pion/turn/v2"
)

type TurnServerConfig struct {
	PublicIP    string
	Port        int
	Realm       string
	AuthSecret  string // ADD THIS - Shared secret for TURN auth
}

func DefaultConfig() TurnServerConfig {
	return TurnServerConfig{
		PublicIP:   "", // Should come from config
		Port:       3478,
		Realm:      "flutter-webrtc.org",
		AuthSecret: "", // Must be set from config
	}
}

type TurnServer struct {
	turnServer *turn.Server
	Config     TurnServerConfig
	// Remove AuthHandler - we'll use shared secret auth
}

func NewTurnServer(config TurnServerConfig) *TurnServer {
	if config.PublicIP == "" {
		logger.Panicf("TURN public_ip is required")
	}
	
	if config.AuthSecret == "" {
		logger.Panicf("TURN auth_secret is required for authentication")
	}

	// Create UDP listener
	udpListener, err := net.ListenPacket("udp4", "0.0.0.0:"+strconv.Itoa(config.Port))
	if err != nil {
		logger.Panicf("TURN UDP failed to listen on port %d: %v", config.Port, err)
	}

	// Create TCP listener
	tcpListener, err := net.Listen("tcp4", "0.0.0.0:"+strconv.Itoa(config.Port))
	if err != nil {
		logger.Panicf("TURN TCP failed to listen on port %d: %v", config.Port, err)
	}

	// Using long-term credential authentication with shared secret
	usersMap := map[string][]byte{}
	
	// For shared secret auth, we need to generate credentials dynamically
	// The actual auth will be handled by the AuthHandler below

	turnServer, err := turn.NewServer(turn.ServerConfig{
		Realm: config.Realm,
		
		// Use shared secret authentication (recommended for production)
		AuthHandler: func(username string, realm string, srcAddr net.Addr) ([]byte, bool) {
			// Generate credentials based on shared secret
			// This allows temporary credentials for WebRTC
			
			// For long-term credential auth with shared secret:
			// The username is typically a timestamp + something
			// and password is generated from the shared secret
			
			if config.AuthSecret == "" {
				return nil, false
			}
			
			// Generate key for this username/realm combination
			key := turn.GenerateAuthKey(username, realm, config.AuthSecret)
			return key, true
		},
		
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: udpListener,
				RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
					RelayAddress: net.ParseIP(config.PublicIP),
					Address:      "0.0.0.0",
				},
			},
		},
		ListenerConfigs: []turn.ListenerConfig{
			{
				Listener: tcpListener,
				RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
					RelayAddress: net.ParseIP(config.PublicIP),
					Address:      "0.0.0.0",
				},
			},
		},
		
		// Set relay address for media
		RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
			RelayAddress: net.ParseIP(config.PublicIP),
			Address:      "0.0.0.0",
		},
	})
	
	if err != nil {
		logger.Panicf("TURN server creation failed: %v", err)
	}

	logger.Infof("TURN server started on %s:%d (UDP/TCP)", config.PublicIP, config.Port)
	
	return &TurnServer{
		turnServer: turnServer,
		Config:     config,
	}
}

// GetTURNCredentials generates TURN credentials for clients
func (s *TurnServer) GetTURNCredentials() (username string, password string) {
	// Generate temporary credentials (24-hour validity)
	// This is the standard way for WebRTC TURN servers
	unixTime := time.Now().Add(24 * time.Hour).Unix()
	username = strconv.FormatInt(unixTime, 10)
	
	// Generate password using shared secret
	password = turn.GenerateAuthKey(username, s.Config.Realm, s.Config.AuthSecret)
	return username, password
}

func (s *TurnServer) Close() error {
	if s.turnServer != nil {
		return s.turnServer.Close()
	}
	return nil
}