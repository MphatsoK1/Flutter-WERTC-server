package signaler

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/logger"
	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/turn"
	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/util"
	"github.com/flutter-webrtc/flutter-webrtc-server/pkg/websocket"
)

// Use the same shared key as TURN server
const (
	sharedKey = "flutter-webrtc-turn-server-shared-key"
)

// -------------------- TURN --------------------

type TurnCredentials struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	TTL      int      `json:"ttl"`
	Uris     []string `json:"uris"`
}

// -------------------- SIGNALING --------------------

type Peer struct {
	info PeerInfo
	conn *websocket.WebSocketConn
}

type Session struct {
	id   string
	from Peer
	to   Peer
}

type Method string

const (
	New       Method = "new"
	Bye       Method = "bye"
	Offer     Method = "offer"
	Answer    Method = "answer"
	Candidate Method = "candidate"
	Leave     Method = "leave"
	Keepalive Method = "keepalive"
)

type Request struct {
	Type Method      `json:"type"`
	Data interface{} `json:"data"`
}

type PeerInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	UserAgent string `json:"user_agent"`
}

type Negotiation struct {
	From      string `json:"from"`
	To        string `json:"to"`
	SessionID string `json:"session_id"`
}

type Byebye struct {
	SessionID string `json:"session_id"`
	From      string `json:"from"`
}

type Error struct {
	Request string `json:"request"`
	Reason  string `json:"reason"`
}

// -------------------- SIGNALER --------------------

type Signaler struct {
	peers     map[string]Peer
	sessions  map[string]Session
	turn      *turn.TurnServer
	expresMap *util.ExpiredMap
	mu        sync.RWMutex // Add mutex for thread safety
}

func NewSignaler(turn *turn.TurnServer) *Signaler {
	s := &Signaler{
		peers:     make(map[string]Peer),
		sessions:  make(map[string]Session),
		turn:      turn,
		expresMap: util.NewExpiredMap(),
	}
	return s
}

func (s *Signaler) authHandler(username, realm string, srcAddr net.Addr) (string, bool) {
	if found, info := s.expresMap.Get(username); found {
		cred := info.(TurnCredentials)
		return cred.Password, true
	}
	return "", false
}

// -------------------- TURN CREDENTIAL ENDPOINT --------------------

func (s *Signaler) HandleTurnServerCredentials(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	
	// Handle CORS preflight
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "GET" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	params, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	service := params.Get("service")
	if service != "turn" {
		http.Error(w, "invalid service", http.StatusBadRequest)
		return
	}

	username := params.Get("username")
	if username == "" {
		http.Error(w, "missing username", http.StatusBadRequest)
		return
	}

	// Use the actual TURN server configuration from turn object
	if s.turn == nil {
		http.Error(w, "TURN server not configured", http.StatusInternalServerError)
		return
	}

	turnConfig := s.turn.Config
	
	// Generate timestamp-based username
	timestamp := time.Now().Unix()
	turnUsername := fmt.Sprintf("%d:%s", timestamp, username)

	// Generate password using shared key (must match TURN server's auth secret)
	h := hmac.New(sha1.New, []byte(turnConfig.AuthSecret))
	h.Write([]byte(turnUsername))
	password := base64.RawStdEncoding.EncodeToString(h.Sum(nil))

	ttl := 86400 // 24 hours

	// Generate TURN URIs using actual server configuration
	uris := []string{
		fmt.Sprintf("turn:%s:%d?transport=udp", turnConfig.PublicIP, turnConfig.Port),
		fmt.Sprintf("turn:%s:%d?transport=tcp", turnConfig.PublicIP, turnConfig.Port),
	}
	
	// If using TLS, also add turns:// URI
	if strings.Contains(r.Host, "https") || r.TLS != nil {
		uris = append(uris, fmt.Sprintf("turns:%s:443?transport=tcp", turnConfig.PublicIP))
	}

	credential := TurnCredentials{
		Username: turnUsername,
		Password: password,
		TTL:      ttl,
		Uris:     uris,
	}

	// Store for TURN server authentication
	s.expresMap.Set(turnUsername, credential, int64(ttl))
	
	// Return credentials
	if err := json.NewEncoder(w).Encode(credential); err != nil {
		logger.Errorf("Failed to encode TURN credentials: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// -------------------- WEBSOCKET --------------------

func (s *Signaler) Send(conn *websocket.WebSocketConn, m interface{}) error {
	data, err := json.Marshal(m)
	if err != nil {
		logger.Errorf("Failed to marshal message: %v", err)
		return err
	}
	return conn.Send(string(data))
}

func (s *Signaler) NotifyPeersUpdate(peers map[string]Peer) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	infos := []PeerInfo{}
	for _, p := range peers {
		infos = append(infos, p.info)
	}

	req := Request{
		Type: "peers",
		Data: infos,
	}

	for _, p := range peers {
		if err := s.Send(p.conn, req); err != nil {
			logger.Warningf("Failed to send peer update to %s: %v", p.info.ID, err)
		}
	}
}

func (s *Signaler) HandleNewWebSocket(conn *websocket.WebSocketConn, r *http.Request) {
	logger.Infof("WS Open from %v", r.RemoteAddr)

	conn.On("message", func(message []byte) {
		var raw json.RawMessage
		req := Request{Data: &raw}

		if err := json.Unmarshal(message, &req); err != nil {
			logger.Warningf("Failed to unmarshal message: %v", err)
			return
		}

		switch req.Type {
		case New:
			var info PeerInfo
			if err := json.Unmarshal(raw, &info); err != nil {
				logger.Warningf("Failed to unmarshal peer info: %v", err)
				return
			}
			
			s.mu.Lock()
			s.peers[info.ID] = Peer{conn: conn, info: info}
			s.mu.Unlock()
			
			s.NotifyPeersUpdate(s.peers)

		case Offer, Answer, Candidate:
			var n Negotiation
			if err := json.Unmarshal(raw, &n); err != nil {
				logger.Warningf("Failed to unmarshal negotiation: %v", err)
				return
			}
			
			s.mu.RLock()
			peer, ok := s.peers[n.To]
			s.mu.RUnlock()
			
			if ok {
				if err := s.Send(peer.conn, req); err != nil {
					logger.Warningf("Failed to send %s to %s: %v", req.Type, n.To, err)
				}
			} else {
				logger.Warningf("Peer %s not found for %s from %s", n.To, req.Type, n.From)
			}

		case Bye:
			var bye Byebye
			if err := json.Unmarshal(raw, &bye); err != nil {
				logger.Warningf("Failed to unmarshal bye: %v", err)
				return
			}
			
			ids := strings.Split(bye.SessionID, "-")
			for _, id := range ids {
				s.mu.RLock()
				peer, ok := s.peers[id]
				s.mu.RUnlock()
				
				if ok {
					s.Send(peer.conn, Request{
						Type: Bye,
						Data: map[string]string{
							"session_id": bye.SessionID,
							"from": bye.From,
						},
					})
				}
			}

		case Keepalive:
			// Echo back keepalive
			s.Send(conn, req)

		default:
			logger.Warningf("Unknown message type: %s", req.Type)
		}
	})

	conn.On("close", func(code int, text string) {
		logger.Infof("WS Close from %v: code=%d, text=%s", r.RemoteAddr, code, text)
		
		s.mu.Lock()
		defer s.mu.Unlock()
		
		var removedID string
		for id, peer := range s.peers {
			if peer.conn == conn {
				removedID = id
				break
			}
		}
		
		if removedID != "" {
			delete(s.peers, removedID)
			logger.Infof("Removed peer %s", removedID)
			
			// Notify remaining peers
			if len(s.peers) > 0 {
				req := Request{
					Type: "leave",
					Data: removedID,
				}
				for _, peer := range s.peers {
					s.Send(peer.conn, req)
				}
			}
		}
	})
}