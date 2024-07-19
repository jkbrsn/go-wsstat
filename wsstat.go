// Package wsstat measures the latency of WebSocket connections.
// It wraps the gorilla/websocket package and includes latency measurements in the Result struct.
package wsstat

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	// Package-specific logger, defaults to Info level
	logger = zerolog.New(os.Stderr).Level(zerolog.InfoLevel).With().Timestamp().Logger()

	// Default dial timeout
	dialTimeout = 3 * time.Second

	// Stores optional user-provided TLS configuration
	customTLSConfig *tls.Config = nil
)

// CertificateDetails holds details regarding a certificate.
type CertificateDetails struct {
	CommonName         string
	Issuer             string
	NotBefore          time.Time
	NotAfter           time.Time
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	SignatureAlgorithm x509.SignatureAlgorithm
	DNSNames           []string
	IPAddresses        []net.IP
	URIs               []*url.URL
}

// Result holds durations of each phase of a WebSocket connection, cumulative durations over
// the connection timeline, and other relevant connection details.
type Result struct {
	IPs []string // IP addresses of the WebSocket connection
	URL url.URL  // URL of the WebSocket connection

	// Duration of each phase of the connection
	DNSLookup        time.Duration // Time to resolve DNS
	TCPConnection    time.Duration // TCP connection establishment time
	TLSHandshake     time.Duration // Time to perform TLS handshake
	WSHandshake      time.Duration // Time to perform WebSocket handshake
	MessageRoundTrip time.Duration // Time to send message and receive response
	ConnectionClose  time.Duration // Time to close the connection (complete the connection lifecycle)

	// Cumulative durations over the connection timeline
	DNSLookupDone        time.Duration // Time to resolve DNS (might be redundant with DNSLookup)
	TCPConnected         time.Duration // Time until the TCP connection is established
	TLSHandshakeDone     time.Duration // Time until the TLS handshake is completed
	WSHandshakeDone      time.Duration // Time until the WS handshake is completed
	FirstMessageResponse time.Duration // Time until the first message is received
	TotalTime            time.Duration // Total time from opening to closing the connection

	// Other connection details
	RequestHeaders  http.Header          // Headers of the initial request
	ResponseHeaders http.Header          // Headers of the response
	TLSState        *tls.ConnectionState // State of the TLS connection
}

// WSStat wraps the gorilla/websocket package and includes latency measurements in Result.
type WSStat struct {
	conn   *websocket.Conn
	dialer *websocket.Dialer
	Result *Result
}

// readLoop is a helper function to process received messages.
func (ws *WSStat) readLoop() {
	defer ws.conn.Close()
	for {
		// Although the message content is not used directly here,
		// calling NextReader is necessary to trigger the pong handler.
		if _, _, err := ws.conn.NextReader(); err != nil {
			break
		}
	}
}

// CloseConn closes the WebSocket connection and measures the time taken to close the connection.
// Sets result times: ConnectionClose, TotalTime
func (ws *WSStat) CloseConn() error {
	start := time.Now()
	err := ws.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	if err != nil {
		return err
	}
	err = ws.conn.Close()
	ws.Result.ConnectionClose = time.Since(start)
	ws.Result.TotalTime = ws.Result.FirstMessageResponse + ws.Result.ConnectionClose
	return err
}

// Dial establishes a new WebSocket connection using the custom dialer defined in this package.
// If required, specify custom headers to merge with the default headers.
// Sets result times: WSHandshake, WSHandshakeDone
func (ws *WSStat) Dial(url *url.URL, customHeaders http.Header) error {
	ws.Result.URL = *url
	start := time.Now()
	headers := http.Header{}
	headers.Add("Origin", "http://example.com") // Add as default header, required by some servers
	for name, values := range customHeaders {
		headers[name] = values
	}
	conn, resp, err := ws.dialer.Dial(url.String(), headers)
	if err != nil {
		return err
	}
	totalDialDuration := time.Since(start)
	ws.conn = conn
	ws.Result.WSHandshake = totalDialDuration - ws.Result.TLSHandshakeDone
	ws.Result.WSHandshakeDone = totalDialDuration

	// Lookup IP
	ips, err := net.LookupIP(url.Hostname())
	if err != nil {
		return fmt.Errorf("failed to lookup IP: %v", err)
	}
	ws.Result.IPs = make([]string, len(ips))
	for i, ip := range ips {
		ws.Result.IPs[i] = ip.String()
	}

	// Capture request and response headers
	// documentedDefaultHeaders lists the known headers that Gorilla WebSocket sets by default.
	var documentedDefaultHeaders = map[string][]string{
		"Upgrade":               {"websocket"}, // Constant value
		"Connection":            {"Upgrade"},   // Constant value
		"Sec-WebSocket-Key":     {"<hidden>"},  // A nonce value; dynamically generated for each request
		"Sec-WebSocket-Version": {"13"},        // Constant value
		// "Sec-WebSocket-Protocol",     // Also set by gorilla/websocket, but only if subprotocols are specified
	}
	// Merge custom headers
	for name, values := range documentedDefaultHeaders {
		headers[name] = values
	}
	ws.Result.RequestHeaders = headers
	ws.Result.ResponseHeaders = resp.Header

	return nil
}

// ReadMessage reads a message from the WebSocket connection and measures the round-trip time.
// Wraps the gorilla/websocket ReadMessage method.
// Sets result times: MessageRoundTrip, FirstMessageResponse
// Requires that a timer has been started with WriteMessage to measure the round-trip time.
func (ws *WSStat) ReadMessage(writeStart time.Time) (int, []byte, error) {
	ws.conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	msgType, p, err := ws.conn.ReadMessage()
	if err != nil {
		return 0, nil, err
	}
	ws.Result.MessageRoundTrip = time.Since(writeStart)
	ws.Result.FirstMessageResponse = ws.Result.WSHandshakeDone + ws.Result.MessageRoundTrip
	return msgType, p, nil
}

// WriteMessage sends a message through the WebSocket connection and
// starts a timer to measure the round-trip time.
// Wraps the gorilla/websocket WriteMessage method.
func (ws *WSStat) WriteMessage(messageType int, data []byte) (time.Time, error) {
	start := time.Now()
	err := ws.conn.WriteMessage(messageType, data)
	if err != nil {
		return time.Time{}, err
	}
	return start, err
}

// SendMessage sends a message through the WebSocket connection and measures the round-trip time.
// Wraps the gorilla/websocket WriteMessage and ReadMessage methods.
// Sets result times: MessageRoundTrip, FirstMessageResponse
func (ws *WSStat) SendMessage(messageType int, data []byte) ([]byte, error) {
	start := time.Now()
	if err := ws.conn.WriteMessage(messageType, data); err != nil {
		return nil, err
	}
	// Assuming immediate response
	ws.conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	_, p, err := ws.conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	logger.Debug().Bytes("Response", p).Msg("Received message")
	ws.Result.MessageRoundTrip = time.Since(start)
	ws.Result.FirstMessageResponse = ws.Result.WSHandshakeDone + ws.Result.MessageRoundTrip
	return p, nil
}

// SendMessageBasic sends a basic message through the WebSocket connection and measures the round-trip time.
// Wraps the gorilla/websocket WriteMessage and ReadMessage methods.
// Sets result times: MessageRoundTrip, FirstMessageResponse
func (ws *WSStat) SendMessageBasic() error {
	_, err := ws.SendMessage(websocket.TextMessage, []byte("Hello, WebSocket!"))
	if err != nil {
		return err
	}
	return nil
}

// SendMessageJSON sends a message through the WebSocket connection and measures the round-trip time.
// Wraps the gorilla/websocket WriteJSON and ReadJSON methods.
// Sets result times: MessageRoundTrip, FirstMessageResponse
func (ws *WSStat) SendMessageJSON(v interface{}) (interface{}, error) {
	start := time.Now()
	if err := ws.conn.WriteJSON(&v); err != nil {
		return nil, err
	}
	// Assuming immediate response
	ws.conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	var resp interface{}
	err := ws.conn.ReadJSON(&resp)
	if err != nil {
		return nil, err
	}
	logger.Debug().Interface("Response", resp).Msg("Received message")
	ws.Result.MessageRoundTrip = time.Since(start)
	ws.Result.FirstMessageResponse = ws.Result.WSHandshakeDone + ws.Result.MessageRoundTrip
	return resp, nil
}

// SendPing sends a ping message through the WebSocket connection and measures the round-trip time until the pong response.
// Wraps the gorilla/websocket SetPongHandler and WriteMessage methods.
// Sets result times: MessageRoundTrip, FirstMessageResponse
func (ws *WSStat) SendPing() error {
	pongReceived := make(chan bool)        // Unbuffered channel
	timeout := time.After(5 * time.Second) // Timeout for the pong response

	ws.conn.SetPongHandler(func(appData string) error {
		pongReceived <- true
		return nil
	})

	go ws.readLoop() // Start the read loop to process the pong message

	start := time.Now()
	if err := ws.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
		return err
	}

	select {
	case <-pongReceived:
		ws.Result.MessageRoundTrip = time.Since(start)
	case <-timeout:
		return errors.New("pong response timeout")
	}

	ws.Result.FirstMessageResponse = ws.Result.WSHandshakeDone + ws.Result.MessageRoundTrip
	return nil
}

// durations returns a map of the time.Duration members of Result.
func (r *Result) durations() map[string]time.Duration {
	return map[string]time.Duration{
		"DNSLookup":        r.DNSLookup,
		"TCPConnection":    r.TCPConnection,
		"TLSHandshake":     r.TLSHandshake,
		"WSHandshake":      r.WSHandshake,
		"MessageRoundTrip": r.MessageRoundTrip,
		"ConnectionClose":  r.ConnectionClose,

		"DNSLookupDone":        r.DNSLookupDone,
		"TCPConnected":         r.TCPConnected,
		"TLSHandshakeDone":     r.TLSHandshakeDone,
		"WSHandshakeDone":      r.WSHandshakeDone,
		"FirstMessageResponse": r.FirstMessageResponse,
		"TotalTime":            r.TotalTime,
	}
}

// CertificateDetails returns a slice of CertificateDetails for each certificate in the TLS connection.
func (r *Result) CertificateDetails() []CertificateDetails {
	if r.TLSState == nil {
		return nil
	}
	var details []CertificateDetails
	for _, cert := range r.TLSState.PeerCertificates {
		details = append(details, CertificateDetails{
			CommonName:         cert.Subject.CommonName,
			Issuer:             cert.Issuer.CommonName,
			NotBefore:          cert.NotBefore,
			NotAfter:           cert.NotAfter,
			PublicKeyAlgorithm: cert.PublicKeyAlgorithm,
			SignatureAlgorithm: cert.SignatureAlgorithm,
			DNSNames:           cert.DNSNames,
			IPAddresses:        cert.IPAddresses,
			URIs:               cert.URIs,
		})
	}
	return details
}

// Format formats the time.Duration members of Result.
func (r Result) Format(s fmt.State, verb rune) {
	switch verb {
	case 'v':
		if s.Flag('+') {
			fmt.Fprintln(s, "URL")
			fmt.Fprintf(s, "  Scheme: %s\n", r.URL.Scheme)
			fmt.Fprintf(s, "  Host: %s\n", r.URL.Host)
			fmt.Fprintf(s, "  Port: %s\n", Port(r.URL))
			if r.URL.Path != "" {
				fmt.Fprintf(s, "  Path: %s\n", r.URL.Path)
			}
			if r.URL.RawQuery != "" {
				fmt.Fprintf(s, "  Query: %s\n", r.URL.RawQuery)
			}
			fmt.Fprintln(s, "IP")
			fmt.Fprintf(s, "  %v\n", r.IPs)
			fmt.Fprintln(s)

			if r.TLSState != nil {
				fmt.Fprintf(s, "TLS handshake details\n")
				// TODO: tls.VersionName restricts use to go1.21+, consider alternatives
				fmt.Fprintf(s, "  Version: %s\n", tls.VersionName(r.TLSState.Version))
				fmt.Fprintf(s, "  Cipher Suite: %s\n", tls.CipherSuiteName(r.TLSState.CipherSuite))
				fmt.Fprintf(s, "  Server Name: %s\n", r.TLSState.ServerName)
				fmt.Fprintf(s, "  Handshake Complete: %t\n", r.TLSState.HandshakeComplete)

				for i, cert := range r.CertificateDetails() {
					fmt.Fprintf(s, "Certificate %d\n", i+1)
					fmt.Fprintf(s, "  Common Name: %s\n", cert.CommonName)
					fmt.Fprintf(s, "  Issuer: %s\n", cert.Issuer)
					fmt.Fprintf(s, "  Not Before: %s\n", cert.NotBefore)
					fmt.Fprintf(s, "  Not After: %s\n", cert.NotAfter)
					fmt.Fprintf(s, "  Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm.String())
					fmt.Fprintf(s, "  Signature Algorithm: %s\n", cert.SignatureAlgorithm.String())
					fmt.Fprintf(s, "  DNS Names: %v\n", cert.DNSNames)
					fmt.Fprintf(s, "  IP Addresses: %v\n", cert.IPAddresses)
					fmt.Fprintf(s, "  URIs: %v\n", cert.URIs)
				}
				fmt.Fprintln(s)
			}

			if r.RequestHeaders != nil {
				fmt.Fprintf(s, "Request headers\n")
				for k, v := range r.RequestHeaders {
					fmt.Fprintf(s, "  %s: %s\n", k, v)
				}
			}
			if r.ResponseHeaders != nil {
				fmt.Fprintf(s, "Response headers\n")
				for k, v := range r.ResponseHeaders {
					fmt.Fprintf(s, "  %s: %s\n", k, v)
				}
			}
			fmt.Fprintln(s)

			var buf bytes.Buffer
			fmt.Fprintf(&buf, "DNS lookup:     %4d ms\n",
				int(r.DNSLookup/time.Millisecond))
			fmt.Fprintf(&buf, "TCP connection: %4d ms\n",
				int(r.TCPConnection/time.Millisecond))
			fmt.Fprintf(&buf, "TLS handshake:  %4d ms\n",
				int(r.TLSHandshake/time.Millisecond))
			fmt.Fprintf(&buf, "WS handshake:   %4d ms\n",
				int(r.WSHandshake/time.Millisecond))
			fmt.Fprintf(&buf, "Msg round trip: %4d ms\n",
				int(r.MessageRoundTrip/time.Millisecond))

			if r.ConnectionClose > 0 {
				fmt.Fprintf(&buf, "Close time:     %4d ms\n\n",
					int(r.ConnectionClose/time.Millisecond))
			} else {
				fmt.Fprintf(&buf, "Close time:     %4s ms\n\n", "-")
			}

			fmt.Fprintf(&buf, "Name lookup done:   %4d ms\n",
				int(r.DNSLookupDone/time.Millisecond))
			fmt.Fprintf(&buf, "TCP connected:      %4d ms\n",
				int(r.TCPConnected/time.Millisecond))
			fmt.Fprintf(&buf, "TLS handshake done: %4d ms\n",
				int(r.TLSHandshakeDone/time.Millisecond))
			fmt.Fprintf(&buf, "WS handshake done:  %4d ms\n",
				int(r.WSHandshakeDone/time.Millisecond))
			fmt.Fprintf(&buf, "First msg response: %4d ms\n",
				int(r.FirstMessageResponse/time.Millisecond))

			if r.TotalTime > 0 {
				fmt.Fprintf(&buf, "Total:              %4d ms\n",
					int(r.TotalTime/time.Millisecond))
			} else {
				fmt.Fprintf(&buf, "Total:          %4s ms\n", "-")
			}
			io.WriteString(s, buf.String())
			return
		}

		fallthrough
	case 's', 'q':
		d := r.durations()
		list := make([]string, 0, len(d))
		for k, v := range d {
			// Handle when End function is not called
			if (k == "ConnectionClose" || k == "TotalTime") && r.ConnectionClose == 0 {
				list = append(list, fmt.Sprintf("%s: - ms", k))
				continue
			}
			list = append(list, fmt.Sprintf("%s: %d ms", k, v/time.Millisecond))
		}
		io.WriteString(s, strings.Join(list, ", "))
	}
}

// MeasureLatency establishes a WebSocket connection, sends a message, reads the response,
// and closes the connection. Returns the Result and the response message.
// Sets all times in the Result object.
func MeasureLatency(url *url.URL, msg string, customHeaders http.Header) (Result, []byte, error) {
	ws := NewWSStat()
	if err := ws.Dial(url, customHeaders); err != nil {
		logger.Debug().Err(err).Msg("Failed to establish WebSocket connection")
		return Result{}, nil, err
	}
	start, err := ws.WriteMessage(websocket.TextMessage, []byte(msg))
	if err != nil {
		logger.Debug().Err(err).Msg("Failed to write message")
		return Result{}, nil, err
	}
	_, p, err := ws.ReadMessage(start)
	if err != nil {
		logger.Debug().Err(err).Msg("Failed to read message")
		return Result{}, nil, err
	}
	ws.CloseConn()
	return *ws.Result, p, nil
}

// MeasureLatencyJSON establishes a WebSocket connection, sends a JSON message, reads the response,
// and closes the connection. Returns the Result and the response message.
// Sets all times in the Result object.
func MeasureLatencyJSON(url *url.URL, v interface{}, customHeaders http.Header) (Result, interface{}, error) {
	ws := NewWSStat()
	if err := ws.Dial(url, customHeaders); err != nil {
		logger.Debug().Err(err).Msg("Failed to establish WebSocket connection")
		return Result{}, nil, err
	}
	p, err := ws.SendMessageJSON(v)
	if err != nil {
		logger.Debug().Err(err).Msg("Failed to send message")
		return Result{}, nil, err
	}
	ws.CloseConn()
	return *ws.Result, p, nil
}

// MeasureLatencyPing establishes a WebSocket connection, sends a ping message, awaits the pong response,
// and closes the connection. Returns the Result.
// Sets all times in the Result object.
func MeasureLatencyPing(url *url.URL, customHeaders http.Header) (Result, error) {
	ws := NewWSStat()
	if err := ws.Dial(url, customHeaders); err != nil {
		logger.Debug().Err(err).Msg("Failed to establish WebSocket connection")
		return Result{}, err
	}
	err := ws.SendPing()
	if err != nil {
		logger.Debug().Err(err).Msg("Failed to send ping")
		return Result{}, err
	}
	ws.CloseConn()
	return *ws.Result, nil
}

// Port returns the port number from a URL.
func Port(u url.URL) string {
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to split host and port")
	}
	if port == "" {
		// No port specified in the URL, return the default port based on the scheme
		switch u.Scheme {
		case "ws":
			return "80"
		case "wss":
			return "443"
		default:
			return ""
		}
	}
	return port
}

// newDialer initializes and returns a websocket.Dialer with customized dial functions to measure the connection phases.
// Sets result times: DNSLookup, TCPConnection, TLSHandshake, DNSLookupDone, TCPConnected, TLSHandshakeDone
func newDialer(result *Result) *websocket.Dialer {
	return &websocket.Dialer{
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Perform DNS lookup
			dnsStart := time.Now()
			host, port, _ := net.SplitHostPort(addr)
			addrs, err := net.DefaultResolver.LookupHost(ctx, host)
			if err != nil {
				return nil, err
			}
			result.DNSLookup = time.Since(dnsStart)

			// Measure TCP connection time
			tcpStart := time.Now()
			conn, err := net.DialTimeout(network, net.JoinHostPort(addrs[0], port), dialTimeout)
			if err != nil {
				return nil, err
			}
			result.TCPConnection = time.Since(tcpStart)

			// Record the results
			result.DNSLookupDone = result.DNSLookup
			result.TCPConnected = result.DNSLookupDone + result.TCPConnection

			return conn, nil
		},

		NetDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Perform DNS lookup
			dnsStart := time.Now()
			host, port, _ := net.SplitHostPort(addr)
			addrs, err := net.DefaultResolver.LookupHost(ctx, host)
			if err != nil {
				return nil, err
			}
			result.DNSLookup = time.Since(dnsStart)

			// Measure TCP connection time
			tcpStart := time.Now()
			dialer := &net.Dialer{}
			netConn, err := dialer.DialContext(ctx, network, net.JoinHostPort(addrs[0], port))
			if err != nil {
				return nil, err
			}
			result.TCPConnection = time.Since(tcpStart)

			// Set up TLS configuration
			tlsConfig := customTLSConfig
			if tlsConfig == nil {
				// Fall back to a default configuration
				// Note: the default is an insecure configuration, use with caution
				tlsConfig = &tls.Config{InsecureSkipVerify: true}
			}
			tlsStart := time.Now()
			// Initiate TLS handshake over the established TCP connection
			tlsConn := tls.Client(netConn, tlsConfig)
			err = tlsConn.Handshake()
			if err != nil {
				netConn.Close()
				return nil, err
			}
			result.TLSHandshake = time.Since(tlsStart)
			state := tlsConn.ConnectionState()
			result.TLSState = &state

			// Record the results
			result.DNSLookupDone = result.DNSLookup
			result.TCPConnected = result.DNSLookupDone + result.TCPConnection
			result.TLSHandshakeDone = result.TCPConnected + result.TLSHandshake

			return tlsConn, nil
		},
	}
}

// NewWSStat creates and returns a new WSStat instance.
func NewWSStat() *WSStat {
	result := &Result{}
	dialer := newDialer(result)

	ws := &WSStat{
		dialer: dialer,
		Result: result,
	}
	return ws
}

// SetCustomTLSConfig allows users to provide their own TLS configuration.
// Pass nil to use default settings.
func SetCustomTLSConfig(config *tls.Config) {
	customTLSConfig = config
}

// SetDialTimeout sets the dial timeout for WSStat.
func SetDialTimeout(timeout time.Duration) {
	dialTimeout = timeout
}

// SetLogLevel sets the log level for WSStat.
func SetLogLevel(level zerolog.Level) {
	logger = logger.Level(level)
}

// SetLogger sets the logger for WSStat.
func SetLogger(l zerolog.Logger) {
	logger = l
}
