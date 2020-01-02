package gopentsdb

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// ClientConfig represents the client configuration
// Endpoint: URL as string
// Username and Password: used for HTTP AUTH (optionals)
// Timeout: optional, defualt value is 0 -> system timeout
// InsecureSkipVerify: controls whether a client verifies the
// server's certificate chain and host name.
type ClientConfig struct {
	Endpoint           string
	Username           string
	Password           string
	Timeout            int
	InsecureSkipVerify bool
}

// Client represents an OpenSTDB client
type Client struct {
	endpoint   *url.URL
	username   string
	password   string
	httpClient *http.Client
}

// NewClient returns a new OpenSTDB Client
func NewClient(config ClientConfig) (client *Client, err error) {
	client = &Client{
		username:   config.Username,
		password:   config.Password,
		httpClient: new(http.Client),
	}
	if client.endpoint, err = url.Parse(config.Endpoint); err != nil {
		return nil, err
	}

	if config.Timeout != 0 {
		client.httpClient.Timeout = time.Duration(config.Timeout) * time.Second
	}

	if config.InsecureSkipVerify {
		client.httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	return
}

// Query is used to query data points
type Query struct {
	Aggregator string            `json:"aggregator"`
	Metric     string            `json:"metric"`
	Rate       bool              `json:"rate,omitempty"`
	Downsample string            `json:"downsample,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
}

// Request is used to query data points
type Request struct {
	Start             interface{} `json:"start"`
	End               interface{} `json:"end,omitempty"`
	Queries           []*Query    `json:"queries"`
	NoAnnotations     bool        `json:"noAnnotations,omitempty"`
	GlobalAnnotations bool        `json:"globalAnnotations,omitempty"`
	MsResolution      bool        `json:"msResolution,omitempty"`
	ShowTSUIDs        bool        `json:"showTSUIDs,omitempty"`
	Delete            bool        `json:"delete,omitempty"`
}

// GetResponse represents the response of a Get request
type GetResponse struct {
	Metric string                 `json:"metric"`
	Tags   map[string]string      `json:"tags"`
	DPS    map[string]interface{} `json:"dps"`
}

// PushResponse represents the response of a Put request
type PushResponse struct {
	// The number of data points that were queued successfully for storage
	Success int `json:"success"`
	// The number of data points that could not be queued for storage
	Failed int `json:"failed"`
}

// Get get points of OpenSTDB
func (c *Client) Get(r Request) ([]*GetResponse, error) {
	var response []*GetResponse
	return response, c.query("/api/query", r, &response)
}

// Push pushes a slice of points to OpenSTDB
func (c *Client) Push(points []Point) error {
	var response PushResponse
	return c.query("/api/put", points, &response)
}

func (c *Client) query(endpoint string, data, response interface{}) error {
	query, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", c.endpoint.String()+endpoint, bytes.NewBuffer(query))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.username != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf(string(body))
	}
	return json.NewDecoder(resp.Body).Decode(&response)
}

// GetPoints will order and convert the response in an ordered array of points
func (r *GetResponse) GetPoints() []*Point {
	points := make([]*Point, len(r.DPS))
	timestamps := make([]string, len(r.DPS))
	i := 0
	for k := range r.DPS {
		timestamps[i] = k
		i++
	}

	for j, timestamp := range timestamps {
		ts, err := strconv.Atoi(timestamp)
		if err != nil {
			continue
		}
		points[j] = &Point{
			Metric:    r.Metric,
			Timestamp: int64(ts),
			Tags:      r.Tags,
			Value:     r.DPS[timestamp],
		}
	}
	return points
}
