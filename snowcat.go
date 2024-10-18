package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"github.com/leahneukirchen/snowcat/noiseconn"

	"github.com/flynn/noise"
	"github.com/zeebo/errs"
	"crypto/ecdh"
)

const prologue = "SNOWCAT-001"

func proxyCopy(errc chan<- error, dst io.Writer, src io.Reader) {
	var err error
	if dst == nil {
		dst, err = os.OpenFile("/dev/stdout", os.O_WRONLY, 0)
	}
	if src == nil {
		src, err = os.OpenFile("/dev/stdin", os.O_RDONLY, 0)
	}
	defer src.(io.Closer).Close()
	defer dst.(io.Closer).Close()
	_, err = io.Copy(dst, src)
	errc <- err
}

func copy(dst, src net.Conn) {
	if dst == nil && src == nil {
		io.Copy(os.Stdout, os.Stdin)
		return
	}

	errc := make(chan error, 1)
	go proxyCopy(errc, src, dst)
	go proxyCopy(errc, dst, src)
	<-errc
}

func makeServer(arg, clientarg string) {
	if arg == "-" {
		client, err := makeClient(clientarg)
		if err != nil {
			log.Fatal(err)
		}

		copy(nil, client)
		return
	}

	if strings.HasPrefix(arg, "snow:") {
		makeNoiseServer(arg[5:], clientarg)
		return
	}

	makeTcpServer(arg, clientarg)
	return
}

func makeTcpServer(arg, clientarg string) {
	arg, opts := parseConn(arg)

	protocol := "tcp"
	if _, ok := opts["tcp6"]; ok {
		protocol = "tcp6"
	} else if _, ok := opts["tcp4"]; ok {
		protocol = "tcp4"
	}

	ln, err := net.Listen(protocol, arg)
	if err != nil {
		log.Panic(err)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Panic(err)
		}

		go func() {
			client, err := makeClient(clientarg)
			if err != nil {
				conn.(*net.TCPConn).SetLinger(0)
				conn.Close()
				log.Printf("error: %v", err)
				return
			}
			copy(conn, client)
		}()
	}
}

func makeNoiseServer(arg, clientarg string) {
	arg, opts := parseConn(arg)

	protocol := "tcp"
	if _, ok := opts["tcp6"]; ok {
		protocol = "tcp6"
	} else if _, ok := opts["tcp4"]; ok {
		protocol = "tcp4"
	}

	ln, err := net.Listen(protocol, arg)
	if err != nil {
		log.Panic(err)
	}

	var keypair noise.DHKey
	if privkey, ok := opts["privkey"]; ok {
		keypair = loadKey(privkey)
	} else {
		keypair, err = noise.DH25519.GenerateKeypair(nil)
		if err != nil {
			log.Panic(err)
		}
	}

	var verifyPeer []byte

	if verify, ok := opts["verify"]; ok {
		verifyPeer = loadKey(verify).Private // abuse, it's the public key
	}

	log.Printf("pubkey: %s\n", base64.StdEncoding.EncodeToString(keypair.Public))

	cfg := noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519,
			noise.CipherChaChaPoly, noise.HashBLAKE2b),
		Pattern:       noise.HandshakeXX,
		Initiator:     false,
		Prologue:      []byte(prologue),
		StaticKeypair: keypair,
	}

	nln := noiseconn.NewListener(ln, cfg)

Accept:
	for {
		nconn, err := nln.Accept()
		if err != nil {
			log.Panic(err)
		}
		log.Printf("accepted %+v\n", nconn)

		for !nconn.(*noiseconn.Conn).HandshakeComplete() {
			_, err := nconn.Write([]byte(""))
			if err != nil {
				log.Println("error: ", err)
				go nconn.Close()
				continue Accept
			}
		}

		if verifyPeer != nil && !bytes.Equal(nconn.(*noiseconn.Conn).PeerStatic(), verifyPeer) {
			log.Println("error: key mismatch!")
			go nconn.Close()
			continue Accept
		}

		go func() {
			client, err := makeClient(clientarg)
			if err != nil {
				nconn.Close()
				log.Print("error: %v", err)
				return
			}
			copy(nconn, client)
			log.Printf("done")
		}()
	}
}

func makeClient(arg string) (net.Conn, error) {
	if arg == "-" {
		return nil, nil
	}

	if strings.HasPrefix(arg, "snow:") {
		return makeNoiseClient(arg[5:])
	}

	return makeTcpClient(arg)
}

func makeTcpClient(arg string) (net.Conn, error) {
	return net.Dial("tcp", arg)
}

func loadKey(encoded string) noise.DHKey {
	if strings.HasPrefix(encoded, "/") && !strings.HasSuffix(encoded, "=") {
		file, err := os.Open(encoded)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		if !scanner.Scan() {
			log.Fatal("no private key found")
		}
		encoded = scanner.Text()
	}

	privkey, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Fatal(err)
	}
	if len(privkey) != 32 {
		log.Fatalf("privkey is not 32 bytes: %#v", privkey)
	}

	key, err := ecdh.X25519().NewPrivateKey(privkey)
	if err != nil {
		log.Fatal(err)
	}
	return noise.DHKey{Private: privkey, Public: key.PublicKey().Bytes()}
}

func parseConn(arg string) (dial string, options map[string]string) {
	args := strings.Split(arg, ",")
	dial = args[0]

	options = make(map[string]string)

	for _, flag := range args[1:] {
		kv := strings.SplitN(flag, "=", 2)
		if len(kv) == 2 {
			options[kv[0]] = kv[1]
		} else {
			options[kv[0]] = ""
		}
	}

	return
}

func makeNoiseClient(arg string) (net.Conn, error) {
	arg, opts := parseConn(arg)

	var verifyPeer []byte

	if verify, ok := opts["verify"]; ok {
		verifyPeer = loadKey(verify).Private // abuse, it's the public key
	}

	var keypair noise.DHKey
	if privkey, ok := opts["privkey"]; ok {
		keypair = loadKey(privkey)
	} else {
		var err error
		keypair, err = noise.DH25519.GenerateKeypair(nil)
		if err != nil {
			log.Panic(err)
		}
	}

	log.Printf("%v\n", keypair)

	cfg := noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519,
			noise.CipherChaChaPoly, noise.HashBLAKE2b),
		Pattern:       noise.HandshakeXX,
		Initiator:     true,
		Prologue:      []byte(prologue),
		StaticKeypair: keypair,
	}

	conn, err := net.Dial("tcp", arg)
	if err != nil {
		log.Fatal(err)
	}

	nconn, err := noiseconn.NewConn(conn, cfg)

	log.Printf("%v\n", nconn.HandshakeComplete())
	log.Printf("%#+v\n", nconn.PeerStatic())

	for !nconn.HandshakeComplete() {
		_, err := nconn.Write([]byte(""))
		if err != nil {
			go nconn.Close()
			log.Fatal(err)
		}
	}

	if verifyPeer != nil && !bytes.Equal(nconn.PeerStatic(), verifyPeer) {
		go nconn.Close()
		return nil, errs.New("key mismatch!")
	}

	return nconn, nil
}

func main() {
	log.SetPrefix("snowcat: ")
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))

	if os.Args[1] == "genkey" {
		keypair, err := noise.DH25519.GenerateKeypair(nil)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(base64.StdEncoding.EncodeToString(keypair.Private))
		return
	}

	if os.Args[1] == "pubkey" {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			log.Fatal("no private key given on standard input")
		}
		keypair := loadKey(scanner.Text())
		fmt.Println(base64.StdEncoding.EncodeToString(keypair.Public))
		return
	}

	makeServer(os.Args[1], os.Args[2])
}
