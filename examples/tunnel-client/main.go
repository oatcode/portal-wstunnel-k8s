package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/oatcode/portal"
	"nhooyr.io/websocket"
)

var address string
var jwt string
var trustFile string

type WebsocketFramer struct {
	conn *websocket.Conn
}

func NewWebsocketFramer(conn *websocket.Conn, connString string) *WebsocketFramer {
	return &WebsocketFramer{conn: conn}
}
func (c *WebsocketFramer) Read() (b []byte, err error) {
	_, b, err = c.conn.Read(context.Background())
	return b, err
}

func (c *WebsocketFramer) Write(b []byte) error {
	return c.conn.Write(context.Background(), websocket.MessageBinary, b)
}

func (c *WebsocketFramer) Close(err error) error {
	if err == nil {
		return c.conn.Close(websocket.StatusNormalClosure, "")
	} else {
		return c.conn.Close(websocket.StatusInternalError, err.Error())
	}
}

func dialAndServe(tlsConfig *tls.Config) {
	u := url.URL{
		Scheme: "https",
		Host:   address,
		Path:   "tunnel",
	}

	h := http.Header{}
	h.Add("Authorization", "Bearer "+jwt)
	options := &websocket.DialOptions{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
				Proxy:           http.ProxyFromEnvironment,
			},
		},
		HTTPHeader: h,
	}
	c, _, err := websocket.Dial(context.Background(), u.String(), options)
	if err != nil {
		log.Fatal("Dial: ", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")
	log.Print("Tunnel client connected")

	portal.TunnelServe(context.Background(), NewWebsocketFramer(c, address), nil)
}

func createClientTlsConfig(trustFile string) *tls.Config {
	pemCerts, err := ioutil.ReadFile(trustFile)
	if err != nil {
		log.Fatal(err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(pemCerts)
	return &tls.Config{
		RootCAs: rootCAs,
	}
}

func main() {
	flag.StringVar(&address, "address", "", "Address [<hostname>]:<port>")
	flag.StringVar(&jwt, "jwt", "", "Tunnel bearer auth JWT")
	flag.StringVar(&trustFile, "trust", "", "TLS client certificate filename to trust")
	flag.Parse()

	portal.Logf = log.Printf
	log.Printf("Tunnel client...")
	dialAndServe(createClientTlsConfig(trustFile))
}
