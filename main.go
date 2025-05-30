package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"bytes"
	"math"
	"net"
	"strconv"
	"time"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/hotp"
	"golang.org/x/crypto/pbkdf2"

)

var aeskey string

var totp string
var password string
var env_ssh_pass string

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func GCM_encrypt(plaintext, key []byte) []byte {
	// Load your secret key from a safe place and reuse it across multiple
	// Seal/Open calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	// When decoded the key should be 16 bytes (AES-128) or 32 (AES-256).
	// ciphertext is prefixed by a 12 byte nonce

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...)
}

func GCM_decrypt(ciphertext, key []byte) []byte {
	// Load your secret key from a safe place and reuse it across multiple
	// Seal/Open calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	// When decoded the key should be 16 bytes (AES-128) or 32 (AES-256).
	// ciphertext is prefixed by a 12 byte nonce

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, ciphertext[:12], ciphertext[12:], nil)
	if err != nil {
		return nil
	}
	return plaintext
}

func initializeKey() []byte {
	if aeskey == "" {
		_k := [32]byte{}
		_, err := io.ReadFull(rand.Reader, _k[:])
		if err != nil {
			panic(err)
		}
		log.Fatalf("AESKEY was not supplied.  Rebuild with:\ngo build -ldflags '-s -w -X main.aeskey=%s'",
			base64.StdEncoding.EncodeToString(_k[:]))
	}
	_k, err := base64.StdEncoding.DecodeString(aeskey)
	if err != nil {
		panic(err)
	}
	return []byte(_k)
}

type WS struct {
	conn *websocket.Conn
	key []byte
}

func (ws *WS) SetKey(data []byte) {
	ws.key = data
}

func (ws *WS) Send(data interface {}) error {
	var msg []byte
	switch v := data.(type) {
	case string:
		// Handle string
		msg = []byte(v)
	case []byte:
		// Handle byte array
		msg = v
	default:
		return fmt.Errorf("Got unexpected data type")
	}
	if ws.key != nil {
		msg = GCM_encrypt(msg, ws.key)
	}
	err := ws.conn.WriteMessage(websocket.BinaryMessage, msg)
	if err != nil {
		return fmt.Errorf("Write to WebSocket error: %s", err)
	}
	return nil
}

func (ws *WS) Receive() ([]byte, error) {
	messageType, p, err := ws.conn.ReadMessage()
	if err != nil {
		if err != io.EOF {
			return nil, fmt.Errorf("Read from WebSocket error: %s", err)
		}
		return nil, err
	}
	if messageType != websocket.BinaryMessage && messageType != websocket.TextMessage {
		return nil, nil
	}
	if ws.key != nil {
		return GCM_decrypt(p, ws.key), nil
	}
	return p, nil
}

func (ws *WS) ReadLine(prompt string, echo bool) ([]byte, error) {
	buf := make([]byte, 1024)
	n := 0
	ws.Send(prompt)
	for {
		msg, err := ws.Receive()
		if err != nil {
			return nil, err
		}
		if echo {
			ws.Send(msg)
		}
		for i := 0; i < len(msg); i++ {
			if msg[i] == '\r' || msg[i] == '\n' {
				ws.Send("\r\n")
				return buf[:n], nil
			}
			buf[n] = msg[i]
			n += 1
			if n >= 1024 {
				return nil, fmt.Errorf("Read too many characters")
			}
		}
	}
}

func sshHandler(w http.ResponseWriter, r *http.Request) {
	user := os.Getenv("SSH_USER")
	host := os.Getenv("SSH_HOST")
	port := os.Getenv("SSH_PORT")
	var key []byte

	hostport := fmt.Sprintf("%s:%s", host, port)

	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}
	defer wsConn.Close()

	ws := WS{conn: wsConn}

	// TOTP Auth
	challenge := make([]byte, 32)
	_, err = rand.Read(challenge)
	if err != nil {
		log.Println("Failed to generate challenge")
		return
	}
	err = ws.Send(challenge)
	if err != nil {
		log.Println("Failed to send challenge")
		return
	}
	auth := false
	p, err := ws.Receive()
	if p == nil || err != nil {
		if err != nil && err != io.EOF {
			fmt.Printf("Failed to receieve response: %s", err)
		}
		return
	}
	log.Printf("Got message len %d\n", len(p))
	counters := []uint64{}
	counter := int64(math.Floor(float64(time.Now().UTC().Unix()) / float64(30)))

	counters = append(counters, uint64(counter))
	counters = append(counters, uint64(counter+int64(1)))
	counters = append(counters, uint64(counter-int64(1)))
	for _, counter := range counters {
		passcode, err := hotp.GenerateCodeCustom(totp, counter, hotp.ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
			})
		if err != nil {
			fmt.Println("Failed to generate TOTP: %s", err)
			return
		}
		_ = passcode
		salt := pbkdf2.Key([]byte(passcode), challenge[:16], 10000, 16, sha256.New)
		fmt.Printf("%x\n", salt)
		key = pbkdf2.Key([]byte(password), salt, 10000, 32, sha256.New)
		response := GCM_decrypt(p, key)
		if bytes.Equal(response, challenge[16:]) {
			auth = true
			break
		}
	}
	if ! auth {
		log.Println("Authorization failed")
		return
	} else {
		log.Println("Authenticated")
		ws.SetKey(key)
	}
	ws.Send("ok")
	p, err = ws.Receive()
        if p == nil || err != nil || string(p) != "ok" {
            fmt.Printf("Did not complete handshake: %s (%s)", p, err)
            return
        }
	ssh_pass := env_ssh_pass	
	if ssh_pass == "" {
		pass_bytes, err := ws.ReadLine("password: ", false)
		if err != nil {
			fmt.Printf("Failed to receive password: %s", err)
			return
		}
		ssh_pass = string(pass_bytes)
		// fmt.Printf("Received: %s\n", ssh_pass)
	}
        log.Println("Received Password")

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(ssh_pass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	sshConn, err := ssh.Dial("tcp", hostport, config)
	if err != nil {
		log.Println("SSH dial error:", err)
		return
	}
	defer sshConn.Close()

	session, err := sshConn.NewSession()
	if err != nil {
		log.Println("SSH session error:", err)
		return
	}
	defer session.Close()

	sshOut, err := session.StdoutPipe()
	if err != nil {
		log.Println("STDOUT pipe error:", err)
		return
	}

	sshIn, err := session.StdinPipe()
	if err != nil {
		log.Println("STDIN pipe error:", err)
		return
	}

	if err := session.RequestPty("xterm", 80, 40, ssh.TerminalModes{}); err != nil {
		log.Println("Request PTY error:", err)
		return
	}

	if err := session.Shell(); err != nil {
		log.Println("Start shell error:", err)
		return
	}

	go func() {
		defer session.Close()
		buf := make([]byte, 1024)
		for {
			n, err := sshOut.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Println("Read from SSH stdout error:", err)
				}
				return
			}
			if n > 0 {
				msg := GCM_encrypt(buf[:n], key)
				err = wsConn.WriteMessage(websocket.BinaryMessage, msg)
				if err != nil {
					log.Println("Write to WebSocket error:", err)
					return
				}
			}
		}
	}()

	for {
		messageType, p, err := wsConn.ReadMessage()
		if err != nil {
			if err != io.EOF {
				log.Println("Read from WebSocket error:", err)
			}
			return
		}
		if messageType == websocket.BinaryMessage || messageType == websocket.TextMessage {
			msg := GCM_decrypt(p, key)
			_, err = sshIn.Write(msg)
			if err != nil {
				log.Println("Write to SSH stdin error:", err)
				return
			}
		}
	}
}

func checkForVariables() error {
	if os.Getenv("SSH_USER") == "" {
		return fmt.Errorf("SSH_USER is not set")
	}
	if os.Getenv("SSH_HOST") == "" {
		return fmt.Errorf("SSH_HOST is not set")
	}
	if os.Getenv("SSH_PORT") == "" {
		return fmt.Errorf("SSH_PORT is not set")
	}
	if os.Getenv("PORT_OR_SOCKET") == "" {
		return fmt.Errorf("PORT_OR_SOCKET is not set")
	}
	if os.Getenv("PASSWORD") == "" {
		return fmt.Errorf("PASSWORD is not set")
	}
	return nil
}

func createListener(portOrSocketPath string) (net.Listener, error) {
	_, err := strconv.Atoi(portOrSocketPath)
	if err == nil {
		listener, err := net.Listen("tcp", ":" + portOrSocketPath)
		return listener, err
	} else {
		os.Remove(portOrSocketPath) // Remove if it exists
		listener, err := net.Listen("unix", portOrSocketPath)
		s, err := os.Stat(portOrSocketPath)
		if err != nil {
			log.Fatalf("Error creating socket: %s", err)
		}
		os.Chmod(portOrSocketPath, s.Mode().Perm()|os.FileMode(0o666))
		return listener, err
	}
}

func createServer(shouldMountHTML bool) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/ssh", sshHandler)
	if shouldMountHTML {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "index.html")
		})
		mux.HandleFunc("/xterm.css", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "xterm.css")
		})
		mux.HandleFunc("/xterm.js", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, "xterm.js")
		})
	}

	return &http.Server{
		Handler: mux,
	}
}

func serveHTTP(server *http.Server, listener net.Listener) error {
       return server.Serve(listener)
}

func decryptArg(envname string, key []byte, ignore_errors bool) string {
	enc_value := os.Getenv(envname)
	if enc_value == "" {
		return ""
	}
	decodedData, err := base64.StdEncoding.DecodeString(enc_value)
	if err != nil {
		if ignore_errors {
			return ""
		}
		log.Fatalf("Couldn't decode %s", envname)
	}
	value := GCM_decrypt([]byte(decodedData), key)
	if value == nil {
		if ignore_errors {
			return ""
		}
		log.Fatalf("Couldn't decrypt %s", envname)
	}
	return string(value)
}

func encryptArg(value string, key []byte) string {
	enc := GCM_encrypt([]byte(value), key)
	if enc == nil {
		log.Fatalf("Failed to encrypt %s", value)
	}
	return base64.StdEncoding.EncodeToString(enc)
}

func decryptArgs() {
 	key := initializeKey()
	totp = decryptArg("TOTP", key, false)
	generated := false
	if totp == "" {
		randomBytes := make([]byte, 10)
		_, err := io.ReadFull(rand.Reader, randomBytes)
		if err != nil {
			panic(err)
		}
		totp = base32.StdEncoding.EncodeToString(randomBytes)
		fmt.Printf("TOTP key: %s\n", totp)
		log.Printf("Encrypted TOTP key: %s", encryptArg(totp, key))
		generated = true
	}
	password = decryptArg("PASSWORD", key, true)
	if password == "" {
		log.Printf("Encrypted password: %s", encryptArg(os.Getenv("PASSWORD"), key))
		generated = true
	}
	env_ssh_pass = decryptArg("SSH_PASS", key, true)
	if env_ssh_pass == "" {
		if os.Getenv("SSH_PASS") != "" {
			log.Printf("Encrypted ssh password: %s", encryptArg(os.Getenv("SSH_PASS"), key))
			generated = true
		}
	}
	if generated {
		log.Fatal("Please rerun with encrypted arguments")
	}
}

func printUsage() {
	fmt.Println("Usage (set proper environmental variables): ")
	fmt.Println("SSH_USER - username for ssh connection")
	fmt.Println("SSH_PASS - password for ssh connection")
	fmt.Println("SSH_HOST - host for ssh connection")
	fmt.Println("SSH_PORT - port for ssh connection")
	fmt.Println("MOUNT_HTML - mount html files (default true, set to false to disable)")

}
func main() {
	errOf := checkForVariables()
	if errOf != nil {

		printUsage()
		log.Fatal(errOf)
	}
	decryptArgs()
	shouldMountHTML := os.Getenv("MOUNT_HTML") == "true" || os.Getenv("MOUNT_HTML") == ""
	server := createServer(shouldMountHTML)

	socketPath := os.Getenv("PORT_OR_SOCKET")
	listener, err := createListener(socketPath)
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	fmt.Printf("Starting server on unix://%s\n", socketPath)
	log.Fatal(serveHTTP(server, listener))
}
