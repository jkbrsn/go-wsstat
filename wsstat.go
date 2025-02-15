// Package wsstat measures the latency of WebSocket connections.
// It wraps the gorilla/websocket package and includes latency measurements in the Result struct.
package wsstat

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	// Package-specific logger, defaults to Info level
	logger = zerolog.New(os.Stderr).Level(zerolog.InfoLevel).With().Timestamp().Logger()

	// Default timeout for dialing and reading from the WebSocket connection
	defaultTimeout = 5 * time.Second

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

	// Timings of each phase of the connection
	DialStart time.Time // Time when the dialing process started
	CloseDone time.Time // Time when the connection was closed

	// Duration of each phase of the connection
	DNSLookup        time.Duration // Time to resolve DNS
	TCPConnection    time.Duration // TCP connection establishment time
	TLSHandshake     time.Duration // Time to perform TLS handshake
	WSHandshake      time.Duration // Time to perform WebSocket handshake
	MessageRoundTrip time.Duration // Time to send message and receive response

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

// WSStat wraps the gorilla/websocket package with latency measuring capabilities.
type WSStat struct {
	conn   *websocket.Conn
	dialer *websocket.Dialer
	Result *Result

	readChan  chan *wsRead
	writeChan chan *wsWrite

	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
}

// wsRead holds the data read from the WebSocket connection.
type wsRead struct {
	data        []byte
	err         error
	messageType int
}

// wsWrite holds the data to be written to the WebSocket connection.
type wsWrite struct {
	data        []byte
	messageType int
}

// readPump reads messages from the WebSocket connection and sends them to the read channel.
func (ws *WSStat) readPump() {
	defer ws.Close()
	for {
		select {
		case <-ws.ctx.Done():
			return
		default:
			ws.conn.SetReadDeadline(time.Now().Add(defaultTimeout))
			if messageType, p, err := ws.conn.ReadMessage(); err != nil {
				// TODO: handle close/ping/pong?
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
					logger.Debug().Err(err).Msg("Unexpected close error")
					// TODO: handle graceful shutdown on error
				}
				ws.readChan <- &wsRead{err: err, messageType: messageType}
				return
			} else {
				ws.readChan <- &wsRead{data: p, messageType: messageType}
			}
		}
	}
}

// writePump writes messages to the WebSocket connection.
func (ws *WSStat) writePump() {
	defer ws.Close()
	for {
		select {
		case write := <-ws.writeChan:
			if err := ws.conn.WriteMessage(write.messageType, write.data); err != nil {
				logger.Debug().Err(err).Msg("Failed to write message")
				return
			}
		case <-ws.ctx.Done():
			return
		}
	}
}

// Close closes the WebSocket connection and cleans up the WSStat instance.
// Sets result times: CloseDone, TotalTime
func (ws *WSStat) Close() {
	ws.closeOnce.Do(func() {
		// If the connection is not already closed, close it gracefully
		if ws.conn != nil {
			// Send close frame
			formattedCloseMessage := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
			deadline := time.Now().Add(time.Second)
			err := ws.conn.WriteControl(websocket.CloseMessage, formattedCloseMessage, deadline)
			if err != nil && !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				logger.Debug().Err(err).Msg("Failed to write close message")
			}

			err = ws.conn.Close()
			if err != nil {
				logger.Debug().Err(err).Msg("Failed to close connection")
			}
		}
		ws.Result.CloseDone = time.Now()
		ws.Result.TotalTime = ws.Result.CloseDone.Sub(ws.Result.DialStart)

		// Cancel the context
		ws.cancel()

		// Close the pump channels
		close(ws.readChan)
		close(ws.writeChan)
	})
}

// Dial establishes a new WebSocket connection using the custom dialer defined in this package.
// If required, specify custom headers to merge with the default headers.
// Sets result times: DialStart, WSHandshake, WSHandshakeDone
func (ws *WSStat) Dial(url *url.URL, customHeaders http.Header) error {
	ws.Result.URL = *url
	ws.Result.DialStart = time.Now()
	headers := http.Header{}
	for name, values := range customHeaders {
		headers.Add(name, strings.Join(values, ","))
	}
	conn, resp, err := ws.dialer.Dial(url.String(), headers)
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return fmt.Errorf("failed dial response '%s': %v", string(body), err)
		}
		return err
	}
	dialDuration := time.Since(ws.Result.DialStart)
	ws.conn = conn
	ws.Result.WSHandshake = dialDuration - ws.Result.TLSHandshakeDone
	ws.Result.WSHandshakeDone = dialDuration

	// Start the read and write pumps
	go ws.readPump()
	go ws.writePump()

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
// Sets result times: MessageRoundTrip, FirstMessageResponse
func (ws *WSStat) ReadMessage(writeStart time.Time) (int, []byte, error) {
	msg := <-ws.readChan
	if msg.err != nil {
		return msg.messageType, nil, msg.err
	}

	ws.Result.MessageRoundTrip = time.Since(writeStart)
	ws.Result.FirstMessageResponse = ws.Result.WSHandshakeDone + ws.Result.MessageRoundTrip

	return msg.messageType, msg.data, nil
}

// ReadMessageJSON reads a message from the WebSocket connection and measures the round-trip time.
// Sets result times: MessageRoundTrip, FirstMessageResponse
func (ws *WSStat) ReadMessageJSON(writeStart time.Time) (interface{}, error) {
	msg := <-ws.readChan
	if msg.err != nil {
		return nil, msg.err
	}

	ws.Result.MessageRoundTrip = time.Since(writeStart)
	ws.Result.FirstMessageResponse = ws.Result.WSHandshakeDone + ws.Result.MessageRoundTrip

	var resp interface{}
	err := json.Unmarshal(msg.data, &resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// WriteMessage sends a message through the WebSocket connection and starts a timer
// to measure the round-trip time.
func (ws *WSStat) WriteMessage(messageType int, data []byte) time.Time {
	start := time.Now()
	ws.writeChan <- &wsWrite{data: data, messageType: messageType}
	return start
}

func (ws *WSStat) WriteMessageJSON(v interface{}) time.Time {
	jsonBytes := new(bytes.Buffer)
	json.NewEncoder(jsonBytes).Encode(&v)
	start := time.Now()
	ws.writeChan <- &wsWrite{data: jsonBytes.Bytes(), messageType: websocket.TextMessage}
	return start
}

// SendMessage sends a message through the WebSocket connection and measures the round-trip time.
// Sets result times: MessageRoundTrip, FirstMessageResponse
func (ws *WSStat) SendMessage(messageType int, data []byte) ([]byte, error) {
	start := ws.WriteMessage(messageType, data)

	// Assuming immediate response
	_, p, err := ws.ReadMessage(start)
	if err != nil {
		return nil, err
	}
	ws.Result.MessageRoundTrip = time.Since(start)
	ws.Result.FirstMessageResponse = ws.Result.WSHandshakeDone + ws.Result.MessageRoundTrip
	return p, nil
}

// SendMessageJSON sends a message through the WebSocket connection and measures the round-trip time.
// Sets result times: MessageRoundTrip, FirstMessageResponse
func (ws *WSStat) SendMessageJSON(v interface{}) (interface{}, error) {
	start := ws.WriteMessageJSON(v)

	// Assuming immediate response
	resp, err := ws.ReadMessageJSON(start)
	if err != nil {
		return nil, err
	}
	ws.Result.MessageRoundTrip = time.Since(start)
	ws.Result.FirstMessageResponse = ws.Result.WSHandshakeDone + ws.Result.MessageRoundTrip
	return resp, nil
}

// SendPing sends a ping message through the WebSocket connection and measures the round-trip time until the pong response.
// Sets result times: MessageRoundTrip, FirstMessageResponse
func (ws *WSStat) SendPing() error {
	pongReceived := make(chan bool)
	timeout := time.After(5 * time.Second)

	ws.conn.SetPongHandler(func(appData string) error {
		pongReceived <- true
		return nil
	})

	start := time.Now()
	ws.writeChan <- &wsWrite{messageType: websocket.PingMessage}

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
			host, port := hostPort(r.URL)
			fmt.Fprintf(s, "  Host: %s\n", host)
			fmt.Fprintf(s, "  Port: %s\n", port)
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
			fmt.Fprintf(&buf, "Msg round trip: %4d ms\n\n",
				int(r.MessageRoundTrip/time.Millisecond))

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
			// Handle when ws.Close function has not been called
			if k == "TotalTime" && r.TotalTime == 0 {
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
	defer ws.Close()

	if err := ws.Dial(url, customHeaders); err != nil {
		logger.Debug().Err(err).Msg("Failed to establish WebSocket connection")
		return Result{}, nil, err
	}
	start := ws.WriteMessage(websocket.TextMessage, []byte(msg))
	_, p, err := ws.ReadMessage(start)
	if err != nil {
		logger.Debug().Err(err).Msg("Failed to read message")
		return Result{}, nil, err
	}
	ws.Close()

	return *ws.Result, p, nil
}

// MeasureLatencyJSON establishes a WebSocket connection, sends a JSON message, reads the response,
// and closes the connection. Returns the Result and the response message.
// Sets all times in the Result object.
func MeasureLatencyJSON(url *url.URL, v interface{}, customHeaders http.Header) (Result, interface{}, error) {
	ws := NewWSStat()
	defer ws.Close()

	if err := ws.Dial(url, customHeaders); err != nil {
		logger.Debug().Err(err).Msg("Failed to establish WebSocket connection")
		return Result{}, nil, err
	}
	p, err := ws.SendMessageJSON(v)
	if err != nil {
		logger.Debug().Err(err).Msg("Failed to send message")
		return Result{}, nil, err
	}
	ws.Close()

	return *ws.Result, p, nil
}

// MeasureLatencyPing establishes a WebSocket connection, sends a ping message, awaits the pong response,
// and closes the connection. Returns the Result.
// Sets all times in the Result object.
func MeasureLatencyPing(url *url.URL, customHeaders http.Header) (Result, error) {
	ws := NewWSStat()
	defer ws.Close()

	if err := ws.Dial(url, customHeaders); err != nil {
		logger.Debug().Err(err).Msg("Failed to establish WebSocket connection")
		return Result{}, err
	}
	err := ws.SendPing()
	if err != nil {
		logger.Debug().Err(err).Msg("Failed to send ping")
		return Result{}, err
	}
	ws.Close()

	return *ws.Result, nil
}

// hostPort returns the host and port from a URL.
func hostPort(u url.URL) (string, string) {
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to split host and port")
		return "", ""
	}
	if port == "" {
		// No port specified in the URL, return the default port based on the scheme
		switch u.Scheme {
		case "ws":
			return host, "80"
		case "wss":
			return host, "443"
		default:
			return host, ""
		}
	}
	return host, port
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
			conn, err := net.DialTimeout(network, net.JoinHostPort(addrs[0], port), defaultTimeout)
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

	ctx, cancel := context.WithCancel(context.Background())
	ws := &WSStat{
		dialer:    dialer,
		Result:    result,
		ctx:       ctx,
		cancel:    cancel,
		readChan:  make(chan *wsRead, 16),
		writeChan: make(chan *wsWrite, 16),
	}

	return ws
}

// SetCustomTLSConfig allows users to provide their own TLS configuration.
// Pass nil to use default settings.
func SetCustomTLSConfig(config *tls.Config) {
	customTLSConfig = config
}

// SetDefaultTimeout sets the default timeout for WSStat.
func SetDefaultTimeout(timeout time.Duration) {
	defaultTimeout = timeout
}

// SetLogLevel sets the log level for WSStat.
func SetLogLevel(level zerolog.Level) {
	logger = logger.Level(level)
}

// SetLogger sets the logger for WSStat.
func SetLogger(l zerolog.Logger) {
	logger = l
}
