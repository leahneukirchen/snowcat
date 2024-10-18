package main

import (
//	"fmt"
	"log"
	"net"
	"os"
	"io"
	"strings"
	"encoding/base64"
	"bytes"

	"github.com/leahneukirchen/snowcat/noiseconn"

	"golang.org/x/crypto/curve25519"
	"github.com/flynn/noise"
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
		client := makeClient(clientarg)
		
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
	ln, err := net.Listen("tcp", arg)
	if err != nil {
		log.Panic(err)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Panic(err)
		}
//		defer conn.Close()

		client := makeClient(clientarg)

		go copy(conn, client)
	}
}

func makeNoiseServer(arg, clientarg string) {
	ln, err := net.Listen("tcp", arg)
	if err != nil {
		log.Panic(err)
	}

	keypair, err := noise.DH25519.GenerateKeypair(nil)
	if err != nil {
		log.Panic(err)
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
				nconn.Close()
				continue Accept
			}
		}

		go func() {
			client := makeClient(clientarg)
			copy(nconn, client)
			log.Printf("done")
		}()
	}
}

func makeClient(arg string) net.Conn {
	if arg == "-" {
		return nil
	}

	if strings.HasPrefix(arg, "snow:") {
		return makeNoiseClient(arg[5:])
	}

	return makeTcpClient(arg)
}

func makeTcpClient(arg string) net.Conn {
	conn, err := net.Dial("tcp", arg)
	if err != nil {
		log.Fatal(err)
	}

	return conn
}

func loadKey(encoded string) noise.DHKey {
	privkey, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Fatal(err)
	}
	if len(privkey) != 32 {
		log.Fatalf("privkey is not 32 bytes: %#v", privkey)
	}
	pubkey, err := curve25519.X25519(privkey, curve25519.Basepoint)
	if err != nil {
		log.Fatal(err)
	}

	return noise.DHKey{Private: privkey, Public: pubkey}
}

func parseConn(arg string) (dial string, options map[string]string) {
	args := strings.Split(arg, ",")
	dial = args[0]

	options = make(map[string]string)

	for _, flag := range(args[1:]) {
		kv := strings.SplitN(flag, "=", 2)
		if len(kv) == 2 {
			options[kv[0]] = kv[1]
		} else {
			options[kv[0]] = ""
		}
	}

	return
}

func makeNoiseClient(arg string) net.Conn {
	arg, opts := parseConn(arg)

	var verifyPeer []byte

	keypair, err := noise.DH25519.GenerateKeypair(nil)
	if err != nil {
		log.Panic(err)
	}

	if verify, ok := opts["verify"]; ok {
		data, err := base64.StdEncoding.DecodeString(verify)
		if err != nil {
			log.Fatal(err)
		}
		verifyPeer = data
	}

	if privkey, ok := opts["privkey"]; ok {
		keypair = loadKey(privkey)
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
		log.Fatal("key mismatch!")
	}

//	log.Printf("connected to: %s %s\n", base64.StdEncoding.EncodeToString(nconn.PeerStatic()),
//		base64.StdEncoding.EncodeToString(verify))
//	log.Printf("%+v\n", nconn.PeerStatic())

	return nconn
}

func main() {
	log.SetPrefix("snowcat: ")
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))

	makeServer(os.Args[1], os.Args[2])
}
