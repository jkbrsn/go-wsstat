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
	conn    *websocket.Conn
	dialer  *websocket.Dialer
	timings *wsTimings
	Result  *Result

	readChan  chan *wsRead
	writeChan chan *wsWrite

	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	wgPumps   sync.WaitGroup
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

// wsTimings holds the timings of each event in the WebSocket connection timeline.
type wsTimings struct {
	DialStart        time.Time   // Time when the dialing process started
	DNSLookupDone    time.Time   // Time when the DNS lookup is done
	TCPConnected     time.Time   // Time when the TCP connection is established
	TLSHandshakeDone time.Time   // Time when the TLS handshake is completed
	WSHandshakeDone  time.Time   // Time when the WS handshake is completed
	MessageWrites    []time.Time // Times when messages are sent
	MessageReads     []time.Time // Times when messages are received
	CloseDone        time.Time   // Time when the connection was closed
}

func (ws *WSStat) calculateResult() {
	// Calculate durations
	ws.Result.DNSLookup = ws.timings.DNSLookupDone.Sub(ws.timings.DialStart)
	ws.Result.TCPConnection = ws.timings.TCPConnected.Sub(ws.timings.DNSLookupDone)
	ws.Result.TLSHandshake = ws.timings.TLSHandshakeDone.Sub(ws.timings.TCPConnected)
	ws.Result.WSHandshake = ws.timings.WSHandshakeDone.Sub(ws.timings.TLSHandshakeDone)
	// TODO: this assumes exatly one read and write has occured, add support for multiple reads and writes
	if len(ws.timings.MessageReads) != 1 && len(ws.timings.MessageWrites) != 1 {
		logger.Debug().Msg("Multiple reads and writes are not supported yet")
		ws.Result.MessageRoundTrip = 0
	} else {
		ws.Result.MessageRoundTrip = ws.timings.MessageReads[0].Sub(ws.timings.MessageWrites[0])
	}

	// Calculate cumulative durations
	ws.Result.DNSLookupDone = ws.timings.DNSLookupDone.Sub(ws.timings.DialStart)
	ws.Result.TCPConnected = ws.timings.TCPConnected.Sub(ws.timings.DialStart)
	ws.Result.TLSHandshakeDone = ws.timings.TLSHandshakeDone.Sub(ws.timings.DialStart)
	ws.Result.WSHandshakeDone = ws.timings.WSHandshakeDone.Sub(ws.timings.DialStart)
	if len(ws.timings.MessageReads) != 1 {
		logger.Debug().Msg("Multiple reads are not supported yet")
		ws.Result.FirstMessageResponse = 0
	} else {
		ws.Result.FirstMessageResponse = ws.timings.MessageReads[0].Sub(ws.timings.DialStart)
	}
	ws.Result.TotalTime = ws.timings.CloseDone.Sub(ws.timings.DialStart)
}

// readPump reads messages from the WebSocket connection and sends them to the read channel.
func (ws *WSStat) readPump() {
	defer func() {
		ws.wgPumps.Done()
		ws.Close()
	}()

	for {
		select {
		case <-ws.ctx.Done():
			return
		default:
			ws.conn.SetReadDeadline(time.Now().Add(defaultTimeout))
			if messageType, p, err := ws.conn.ReadMessage(); err != nil {
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
	defer func() {
		ws.wgPumps.Done()
		ws.Close()
	}()

	for {
		select {
		case write, ok := <-ws.writeChan:
			if !ok {
				// Channel closed, exit write pump
				return
			}

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
		// Cancel the context
		ws.cancel()

		// If the connection is not already closed, close it gracefully
		if ws.conn != nil {
			// Set read deadline to stop reading messages
			ws.conn.SetReadDeadline(time.Now())

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
			ws.conn = nil
		}

		// Calculate timings and set result
		ws.timings.CloseDone = time.Now()
		ws.calculateResult()

		// Wait for pumps to finish
		pumpsTimeoutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		done := make(chan struct{})
		go func() {
			ws.wgPumps.Wait()
			close(done)
		}()

		select {
		case <-done:
			// All goroutines finished
		case <-pumpsTimeoutCtx.Done():
			logger.Warn().Msg("Timeout closing WSStat pumps")
		}

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
	headers := http.Header{}
	for name, values := range customHeaders {
		headers.Add(name, strings.Join(values, ","))
	}
	ws.timings.DialStart = time.Now()
	conn, resp, err := ws.dialer.Dial(url.String(), headers)
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return fmt.Errorf("failed dial response '%s': %v", string(body), err)
		}
		return err
	}
	ws.timings.WSHandshakeDone = time.Now()
	ws.conn = conn

	// Start the read and write pumps
	ws.wgPumps.Add(2)
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
func (ws *WSStat) ReadMessage() (int, []byte, error) {
	msg := <-ws.readChan
	if msg.err != nil {
		return msg.messageType, nil, msg.err
	}

	ws.timings.MessageReads = append(ws.timings.MessageReads, time.Now())

	return msg.messageType, msg.data, nil
}

// ReadMessageJSON reads a message from the WebSocket connection and measures the round-trip time.
// Sets result times: MessageRoundTrip, FirstMessageResponse
func (ws *WSStat) ReadMessageJSON() (interface{}, error) {
	msg := <-ws.readChan
	if msg.err != nil {
		return nil, msg.err
	}

	ws.timings.MessageReads = append(ws.timings.MessageReads, time.Now())

	var resp interface{}
	err := json.Unmarshal(msg.data, &resp)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// WriteMessage sends a message through the WebSocket connection and starts a timer
// to measure the round-trip time.
func (ws *WSStat) WriteMessage(messageType int, data []byte) {
	ws.timings.MessageWrites = append(ws.timings.MessageWrites, time.Now())
	ws.writeChan <- &wsWrite{data: data, messageType: messageType}
}

func (ws *WSStat) WriteMessageJSON(v interface{}) {
	jsonBytes := new(bytes.Buffer)
	json.NewEncoder(jsonBytes).Encode(&v)
	ws.timings.MessageWrites = append(ws.timings.MessageWrites, time.Now())
	ws.writeChan <- &wsWrite{data: jsonBytes.Bytes(), messageType: websocket.TextMessage}
}

// SendMessage sends a message through the WebSocket connection and measures the round-trip time.
// Sets result times: MessageRoundTrip, FirstMessageResponse
func (ws *WSStat) SendMessage(messageType int, data []byte) ([]byte, error) {
	ws.WriteMessage(messageType, data)

	// Assuming immediate response
	_, p, err := ws.ReadMessage()
	if err != nil {
		return nil, err
	}

	return p, nil
}

// SendMessageJSON sends a message through the WebSocket connection and measures the round-trip time.
// Sets result times: MessageRoundTrip, FirstMessageResponse
func (ws *WSStat) SendMessageJSON(v interface{}) (interface{}, error) {
	ws.WriteMessageJSON(v)

	// Assuming immediate response
	resp, err := ws.ReadMessageJSON()
	if err != nil {
		return nil, err
	}

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

	ws.timings.MessageWrites = append(ws.timings.MessageWrites, time.Now())
	ws.writeChan <- &wsWrite{messageType: websocket.PingMessage}

	select {
	case <-pongReceived:
		ws.timings.MessageReads = append(ws.timings.MessageReads, time.Now())
	case <-timeout:
		return errors.New("pong response timeout")
	}

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
// Sets timings: DNSLookupDone, TCPConnected, TLSHandshakeDone.
func newDialer(result *Result, timings *wsTimings) *websocket.Dialer {
	return &websocket.Dialer{
		NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Perform DNS lookup
			host, port, _ := net.SplitHostPort(addr)
			addrs, err := net.DefaultResolver.LookupHost(ctx, host)
			if err != nil {
				return nil, err
			}
			timings.DNSLookupDone = time.Now()

			// Measure TCP connection time
			conn, err := net.DialTimeout(network, net.JoinHostPort(addrs[0], port), defaultTimeout)
			if err != nil {
				return nil, err
			}
			timings.TCPConnected = time.Now()

			return conn, nil
		},

		NetDialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Perform DNS lookup
			host, port, _ := net.SplitHostPort(addr)
			addrs, err := net.DefaultResolver.LookupHost(ctx, host)
			if err != nil {
				return nil, err
			}
			timings.DNSLookupDone = time.Now()

			// Measure TCP connection time
			dialer := &net.Dialer{}
			netConn, err := dialer.DialContext(ctx, network, net.JoinHostPort(addrs[0], port))
			if err != nil {
				return nil, err
			}
			timings.TCPConnected = time.Now()

			// Set up TLS configuration
			tlsConfig := customTLSConfig
			if tlsConfig == nil {
				// Fall back to a default configuration
				// Note: the default is an insecure configuration, use with caution
				tlsConfig = &tls.Config{InsecureSkipVerify: true}
			}

			// Initiate TLS handshake over the established TCP connection
			tlsConn := tls.Client(netConn, tlsConfig)
			err = tlsConn.Handshake()
			if err != nil {
				netConn.Close()
				return nil, err
			}
			timings.TLSHandshakeDone = time.Now()
			state := tlsConn.ConnectionState()
			result.TLSState = &state

			return tlsConn, nil
		},
	}
}

// NewWSStat creates and returns a new WSStat instance.
func NewWSStat() *WSStat {
	result := &Result{}
	timings := &wsTimings{}
	dialer := newDialer(result, timings)

	ctx, cancel := context.WithCancel(context.Background())
	ws := &WSStat{
		dialer:    dialer,
		timings:   timings,
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
