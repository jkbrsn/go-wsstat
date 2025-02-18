package wsstat

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	serverAddr       = "localhost:8080"
	echoServerAddrWs *url.URL
	// TODO: support wss in tests
)

func init() {
	var err error
	echoServerAddrWs, err = url.Parse("ws://" + serverAddr + "/echo")
	if err != nil {
		log.Fatalf("Failed to parse URL: %v", err)
	}

	// Set log level to debug for the tests
	SetLogLevel(zerolog.DebugLevel)
}

// TestMain sets up the test server and runs the tests in this file.
func TestMain(m *testing.M) {
	// Set up test server
	go func() {
		startEchoServer(serverAddr)
	}()

	// Ensure the echo server starts before any tests run
	time.Sleep(250 * time.Millisecond)

	// Run the tests in this file
	os.Exit(m.Run())
}

func TestNewWSStat(t *testing.T) {
	ws := NewWSStat()
	defer ws.Close()

	assert.NotNil(t, ws)
	assert.NotNil(t, ws.dialer)
	assert.NotNil(t, ws.Result)
}

func TestDial(t *testing.T) {
	testStart := time.Now()
	ws := NewWSStat()
	defer ws.Close()

	err := ws.Dial(echoServerAddrWs, http.Header{})
	assert.NoError(t, err)
	validateDialResult(testStart, ws, echoServerAddrWs, getFunctionName(), t)
}

func TestWriteReadClose(t *testing.T) {
	testStart := time.Now()
	ws := NewWSStat()
	defer func() {
		ws.Close()
		validateCloseResult(ws, getFunctionName(), t)
	}()

	err := ws.Dial(echoServerAddrWs, http.Header{})
	assert.NoError(t, err)
	validateDialResult(testStart, ws, echoServerAddrWs, getFunctionName(), t)

	message := []byte("Hello, world!")
	ws.WriteMessage(websocket.TextMessage, message)
	_, receivedMessage, err := ws.ReadMessage()
	assert.NoError(t, err)
	assert.Equal(t, message, receivedMessage, "Received message does not match sent message")

	// Call close before defer, since Close calls calculateResult
	ws.Close()

	validateSendResult(ws, getFunctionName(), t)
}

func TestSendMessage(t *testing.T) {
	testStart := time.Now()
	ws := NewWSStat()
	defer func() {
		ws.Close()
		validateCloseResult(ws, getFunctionName(), t)
	}()

	err := ws.Dial(echoServerAddrWs, http.Header{})
	assert.NoError(t, err)
	validateDialResult(testStart, ws, echoServerAddrWs, getFunctionName(), t)

	message := []byte("Hello, world!")
	response, err := ws.SendMessage(websocket.TextMessage, message)
	assert.NoError(t, err)
	assert.Equal(t, message, response, "Received message does not match sent message")

	// Call close before defer, since Close calls calculateResult
	ws.Close()

	validateSendResult(ws, getFunctionName(), t)
}

func TestSendMessageJSON(t *testing.T) {
	testStart := time.Now()
	ws := NewWSStat()
	defer func() {
		ws.Close()
		validateCloseResult(ws, getFunctionName(), t)
	}()

	err := ws.Dial(echoServerAddrWs, http.Header{})
	assert.NoError(t, err)
	validateDialResult(testStart, ws, echoServerAddrWs, getFunctionName(), t)

	message := struct {
		Text string `json:"text"`
	}{
		Text: "Hello, world!",
	}
	response, err := ws.SendMessageJSON(message)
	assert.NoError(t, err)
	responseMap, ok := response.(map[string]interface{})
	require.True(t, ok, "Response is not a map")
	assert.Equal(t, message.Text, responseMap["text"])

	// Call close before defer, since Close calls calculateResult
	ws.Close()

	validateSendResult(ws, getFunctionName(), t)
}

func TestLoggerFunctionality(t *testing.T) {
	// Set custom logger with buffer as output
	var buf bytes.Buffer
	customLogger := zerolog.New(&buf).Level(zerolog.InfoLevel).With().Timestamp().Logger()
	SetLogger(customLogger)

	// Test log level Info
	logger.Info().Msg("info message")
	assert.True(t, bytes.Contains(buf.Bytes(), []byte("info message")), "Expected info level log")
	buf.Reset() // Clear buffer

	// Test log level Debug
	SetLogLevel(zerolog.DebugLevel)
	logger.Debug().Msg("debug message")
	assert.True(t, bytes.Contains(buf.Bytes(), []byte("debug message")), "Expected debug level log")
	buf.Reset() // Clear buffer

	// Return log level to Info and confirm debug messages are not logged
	SetLogLevel(zerolog.InfoLevel)
	logger.Debug().Msg("another debug message")
	assert.False(t, bytes.Contains(buf.Bytes(), []byte("another debug message")), "Did not expect debug level log")

	// Restore original logger to avoid affecting other tests
	logger = zerolog.New(os.Stderr).Level(zerolog.DebugLevel).With().Timestamp().Logger()
}

// Helpers

// getFunctionName returns the name of the calling function.
func getFunctionName() string {
	pc, _, _, _ := runtime.Caller(1)
	return strings.TrimPrefix(runtime.FuncForPC(pc).Name(), "main.")
}

// startEchoServer starts a WebSocket server that echoes back any received messages.
func startEchoServer(addr string) {
	var upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins
		},
	}

	http.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Print("upgrade:", err)
			return
		}
		defer conn.Close()
		for {
			mt, message, err := conn.ReadMessage()
			if err != nil {
				// Only print error if it's not a normal closure
				if !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
					log.Println("read:", err)
				}
				break
			}
			err = conn.WriteMessage(mt, message)
			if err != nil {
				log.Println("write:", err)
				break
			}
		}
	})

	fmt.Printf("Echo server started on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

// Validation of WSStat results after Dial has been called
func validateDialResult(testStart time.Time, ws *WSStat, url *url.URL, msg string, t *testing.T) {
	assert.Greater(t,
		ws.timings.dnsLookupDone.Sub(testStart),
		time.Duration(0),
		"Invalid DNSLookupDone time in %s", msg)
	assert.Greater(t,
		ws.timings.tcpConnected.Sub(ws.timings.dnsLookupDone),
		time.Duration(0),
		"Invalid TCPConnected time in %s", msg)

	if strings.Contains(url.String(), "wss://") {
		assert.Greater(t,
			ws.timings.tlsHandshakeDone.Sub(ws.timings.dnsLookupDone),
			time.Duration(0),
			"Invalid TLSHandshakeDone time in %s", msg)
	}

	assert.Greater(t,
		ws.timings.wsHandshakeDone.Sub(ws.timings.tcpConnected),
		time.Duration(0),
		"Invalid WSHandshakeDone time in %s", msg)
}

// Validation of WSStat results after ReadMessage or SendMessage have been called
func validateSendResult(ws *WSStat, msg string, t *testing.T) {
	assert.Greater(t, ws.Result.MessageRoundTrip, time.Duration(0), "Invalid MessageRoundTrip time in %s", msg)
	assert.Greater(t, ws.Result.FirstMessageResponse, time.Duration(0), "Invalid FirstMessageResponse time in %s", msg)
}

// Validation of WSStat results after CloseConn has been called
func validateCloseResult(ws *WSStat, msg string, t *testing.T) {
	assert.Greater(t, ws.Result.TotalTime, time.Duration(0), "Invalid TotalTime time in %s", msg)
}
