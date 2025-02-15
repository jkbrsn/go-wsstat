package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/gorilla/websocket"
	"github.com/jakobilobi/go-wsstat"
)

func main() {
	args := os.Args
	if len(args) < 2 {
		log.Fatalf("Usage: go run main.go URL")
	}
	rawUrl := args[1]

	url, err := url.Parse(rawUrl)
	if err != nil {
		log.Fatalf("Failed to parse URL: %v", err)
	}

	basicExample(url)
	detailedExample(url)
}

// This example demonstrates how to measure the latency of a WebSocket connection
// with a single function call.
func basicExample(url *url.URL) {
	fmt.Print("> Running basic example\n")
	// Measure with a text message
	var msg = "Hello, WebSocket!"
	result, p, err := wsstat.MeasureLatency(url, msg, http.Header{})
	if err != nil {
		log.Fatalf("Failed to measure latency: %v", err)
	}
	fmt.Printf("Response: %s\n\n", p)
	// Measure with a JSON message
	/* var msg = map[string]interface{}{"json": "message", "compatible": "with", "your": "target", "ws": "server"}
	result, p, _ := wsstat.MeasureLatencyJSON(url, msg)
	fmt.Printf("Response: %s\n\n", p) */
	// Measure with a ping message
	//result, _ := wsstat.MeasureLatencyPing(url)
	fmt.Printf("%+v\n", result)
}

// This example demonstrates how to measure the latency of a WebSocket connection
// with more control over the steps in the process.
func detailedExample(url *url.URL) {
	fmt.Print("> Running detailed example\n")
	var err error

	// 1.a. Create a new WSStat instance
	ws := wsstat.NewWSStat()
	defer ws.Close()
	// 1.b. Load custom CA certificate if required
	/* caCert, err := ioutil.ReadFile("path/to/ca.cert")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	// Set up custom TLS configuration
	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
		// Further configuration as needed...
	}
	wsstat.SetCustomTLSConfig(tlsConfig) */

	// 2. Establish a WebSocket connection
	// This triggers the DNS lookup, TCP connection, TLS handshake, and WebSocket handshake timers
	if err := ws.Dial(url, http.Header{}); err != nil {
		log.Fatalf("Failed to establish WebSocket connection: %v", err)
	}

	// 3. Send a message and wait for the response
	// This triggers the first message round trip timer
	// 3.a. Write and read a message
	msg := "Hello, WebSocket!"
	startTime := ws.WriteMessage(websocket.TextMessage, []byte(msg))
	msgType, p, err := ws.ReadMessage(startTime)
	if err != nil {
		log.Fatalf("Failed to read message: %v", err)
	}
	fmt.Printf("Received message '%s' of type '%d'\n\n", p, msgType)
	// 3.b. Send a custom message and wait for the response in a single function
	/* msg := "Hello, WebSocket!"
		p, err := ws.SendMessage(websocket.TextMessage, []byte(msg))
	    if err != nil {
	        log.Fatalf("Failed to send message: %v", err)
	    }
		fmt.Printf("Received message: %s\n\n", p) */
	// 3.c. Send a JSON message and wait for the response
	/* var msg = map[string]interface{}{"json": "message", "compatible": "with", "your": "target", "ws": "server"}
		p, err := ws.SendMessageJSON(msg)
	    if err != nil {
	        log.Fatalf("Failed to send message: %v", err)
	    }
		log.Printf("Received message: %s", p) */
	// 3.e. Alternatively send a ping
	/* if err := ws.SendPing(); err != nil {
		log.Fatalf("Failed to send ping: %v", err)
	} */

	// 4. Close the WSStat instance
	// This triggers the total duration timer as well as closes the WebSocket connection
	ws.Close()
	if err != nil {
		log.Fatalf("Failed to close WebSocket connection: %v", err)
	}

	// 5. Print the results
	fmt.Printf("%+v\n", ws.Result)
}
