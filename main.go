package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v4"
	"github.com/oatcode/portal"
	"nhooyr.io/websocket"
)

var JwtCert = os.Getenv("JWT_CERT")
var SecretCert = os.Getenv("SECRET_CERT")
var SecretKey = os.Getenv("SECRET_KEY")
var ServerPort = os.Getenv("SERVER_PORT")
var ServerInternalPort = os.Getenv("SERVER_INTERNAL_PORT")
var RedisAddress = os.Getenv("REDIS_HOST") + ":" + os.Getenv("REDIS_PORT")
var RedisPassword = os.Getenv("REDIS_PASSWORD")

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

func connString(c net.Conn) string {
	return fmt.Sprintf("%v->%v", c.LocalAddr(), c.RemoteAddr())
}

const (
	expire      = 1 * time.Minute
	refreshTime = expire / 2
)

var mapTenantToCoch = make(map[string]chan portal.ConnectOperation)
var mapLock sync.RWMutex
var localAddress string
var rdb *redis.Client
var jwtPublicKey interface{}

type proxyConnectHandler struct {
	other *http.ServeMux
}

type internalConnectHandler struct {
}

func (h proxyConnectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		// Auth
		tenant, err := parseBearerAuthForTenant(r.Header.Get("Proxy-Authorization"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		var server string
		coch, ok := getTenantLocalChannel(tenant)
		if !ok {
			var err error
			server, err = getTenantRemoteServer(r.Context(), tenant)
			if err != nil {
				if err == redis.Nil {
					http.Error(w, "unknown tenant: "+tenant, http.StatusNotFound)
				} else {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
				return
			}
		}

		// Hijack
		conn, err := hijack(w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Handle
		if coch != nil {
			coch <- portal.ConnectOperation{Conn: conn, Address: r.URL.Host}
		} else {
			routeToServer(conn, server, r)
		}
	} else {
		h.other.ServeHTTP(w, r)
	}
}

// Internal handler only handles CONNECT
func (h internalConnectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "Only CONNECT allowed", http.StatusMethodNotAllowed)
		return
	}
	// Auth
	tenant, err := parseBearerAuthForTenant(r.Header.Get("Proxy-Authorization"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	coch, ok := getTenantLocalChannel(tenant)
	if !ok {
		http.Error(w, "unknown tenant: "+tenant, http.StatusNotFound)
		return
	}
	// Hijack
	conn, err := hijack(w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Handle
	coch <- portal.ConnectOperation{Conn: conn, Address: r.URL.Host}
}

func hijack(w http.ResponseWriter) (net.Conn, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("webserver doesn't support hijacking")
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return conn, err
	}
	conn.SetDeadline(time.Time{})
	log.Printf("Proxy connect: %s", connString(conn))
	return conn, nil
}

func routeToServer(conn net.Conn, server string, r *http.Request) {
	log.Printf("routeToServer: server=%s", server)
	var rc net.Conn
	var err error
	rc, err = net.Dial("tcp", server+":"+ServerInternalPort)
	if err != nil {
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n" + err.Error() + "\r\n"))
		return
	}
	// Send with original CONNECT request
	buf := bytes.Buffer{}
	r.Write(&buf)
	if _, err = rc.Write(buf.Bytes()); err != nil {
		conn.Write([]byte("HTTP/1.1 500 Internal Server Error\r\n" + err.Error() + "\r\n"))
		return
	}
	// Start transfer
	go func() {
		transfer(rc, conn)
		conn.Close()
	}()
	transfer(conn, rc)
	rc.Close()
}

func transfer(src, dst net.Conn) {
	connString := fmt.Sprintf("%v->%v", src.LocalAddr(), dst.RemoteAddr())
	log.Printf("transfer starts: %s", connString)
	_, err := io.Copy(dst, src)
	if err != nil {
		if err == io.EOF {
			log.Printf("transfer source disconnected: %s", connString)
		} else if strings.Contains(err.Error(), "use of closed network connection") {
			log.Printf("transfer destination disconnected: %s", connString)
		} else {
			log.Printf("transfer err: %s %v", connString, err)
		}
	}
	log.Printf("transfer ends: %s", connString)
}

func tunnelHandler(w http.ResponseWriter, r *http.Request) {
	tenant, err := parseBearerAuthForTenant(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	coch, err := newTenant(r.Context(), tenant)
	if err != nil {
		conn.Close(websocket.StatusInternalError, err.Error())
		return
	}
	defer removeTenant(r.Context(), tenant)
	portal.TunnelServe(context.Background(), NewWebsocketFramer(conn, r.RemoteAddr), coch)
}

// Load cert and expect a single cert in pem
func loadCert(pemString []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemString)
	if block == nil {
		return nil, errors.New("unable to load pem")
	}
	if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return nil, errors.New("pem not certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)

	if err != nil {
		return nil, err
	}
	return cert, nil
}

func newTenant(ctx context.Context, tenant string) (chan portal.ConnectOperation, error) {
	mapLock.Lock()
	defer mapLock.Unlock()
	if _, found := mapTenantToCoch[tenant]; found {
		return nil, errors.New("tenant already in used")
	}
	if err := rdb.Set(ctx, tenant, localAddress, expire).Err(); err != nil {
		return nil, err
	}
	coch := make(chan portal.ConnectOperation)
	mapTenantToCoch[tenant] = coch
	return coch, nil
}

func getTenantLocalChannel(tenant string) (chan portal.ConnectOperation, bool) {
	mapLock.RLock()
	defer mapLock.RUnlock()
	coch, ok := mapTenantToCoch[tenant]
	return coch, ok
}

func getTenantRemoteServer(ctx context.Context, tenant string) (string, error) {
	server, err := rdb.Get(ctx, tenant).Result()
	if err != nil {
		return "", err
	}
	if server == localAddress {
		return "", errors.New("self hostname")
	}
	return server, nil
}

func removeTenant(ctx context.Context, tenant string) error {
	mapLock.Lock()
	defer mapLock.Unlock()
	delete(mapTenantToCoch, tenant)
	return rdb.Del(ctx, tenant).Err()
}

func refreshTenant(ctx context.Context) {
	mapLock.RLock()
	defer mapLock.RUnlock()
	for k := range mapTenantToCoch {
		if err := rdb.Expire(ctx, k, expire).Err(); err != nil {
			log.Printf("failed to set redis expire: %v", err)
		}
	}
}

func parseBearerAuthForTenant(auth string) (string, error) {
	const prefix = "Bearer "
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", errors.New("not bearer token")
	}
	tokenString := auth[len(prefix):]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtPublicKey, nil
	})
	if err != nil {
		return "", err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// TODO check cast
		return claims["tenant"].(string), nil
	}
	return "", errors.New("JWT claim not found")
}

func main() {
	portal.Logf = log.Printf

	// Find local address
	n, err := os.Hostname()
	if err != nil {
		log.Fatal(err)
	}
	addrs, err := net.LookupHost(n)
	if err != nil {
		log.Fatal(err)
	}
	if len(addrs) != 1 {
		log.Fatalf("unable to determine IP address: %v", addrs)
	}
	localAddress = addrs[0]
	log.Printf("Tunnel server. localAddress=%s", localAddress)

	// Setup Redis
	rdb = redis.NewClient(&redis.Options{
		Addr:     RedisAddress,
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	// Setup refresh
	go func() {
		ticker := time.NewTicker(refreshTime)
		for range ticker.C {
			refreshTenant(context.TODO())
		}
	}()

	// Cert
	cer, err := tls.X509KeyPair([]byte(SecretCert), []byte(SecretKey))
	if err != nil {
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(SecretCert)) {
		log.Fatal(err)
	}
	tlsServerConfig := &tls.Config{
		Certificates: []tls.Certificate{cer},
	}

	// JWT
	jc, err := loadCert([]byte(JwtCert))
	if err != nil {
		log.Fatal(err)
	}
	jwtPublicKey = jc.PublicKey

	// Setup internal
	go http.ListenAndServe(":"+ServerInternalPort, internalConnectHandler{})

	// Setup listener
	listener, err := tls.Listen("tcp", ":"+ServerPort, tlsServerConfig)
	if err != nil {
		log.Fatal(err)
	}

	// Serve
	otherHandler := http.NewServeMux()
	otherHandler.HandleFunc("/tunnel", tunnelHandler)

	// TODO pre-auth handler
	http.Serve(listener, proxyConnectHandler{
		other: otherHandler,
	})
}
