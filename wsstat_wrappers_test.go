package wsstat

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMeasureLatency(t *testing.T) {
	msg := "Hello, world!"
	result, response, err := MeasureLatency(echoServerAddrWs, msg, http.Header{})

	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, result.TotalTime, time.Duration(0))
	assert.NotEqual(t, "", response)
	assert.Equal(t, msg, string(response))
}

func TestMeasureLatencyJSON(t *testing.T) {
	message := struct {
		Text string `json:"text"`
	}{
		Text: "Hello, world!",
	}
	result, response, err := MeasureLatencyJSON(echoServerAddrWs, message, http.Header{})

	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, result.TotalTime, time.Duration(0))
	assert.NotEqual(t, nil, response)

	responseMap, ok := response.(map[string]interface{})
	require.True(t, ok, "Response is not a map")
	assert.Equal(t, message.Text, responseMap["text"])
}

func TestMeasureLatencyPing(t *testing.T) {
	result, err := MeasureLatencyPing(echoServerAddrWs, http.Header{})

	assert.NoError(t, err)
	require.NotNil(t, result)
	assert.Greater(t, result.TotalTime, time.Duration(0))
	assert.Greater(t, result.MessageRoundTrip, time.Duration(0))
	assert.Greater(t, result.FirstMessageResponse, time.Duration(0))
}
