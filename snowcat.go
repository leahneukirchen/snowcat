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

	"reflect"
	"unsafe"

	"github.com/leahneukirchen/snowcat/noiseconn"

	"golang.org/x/crypto/curve25519"
	"github.com/flynn/noise"
)

const prologue = "SNOWCAT-000"

func GetHandshakeState(conn *noiseconn.Conn) (*noise.HandshakeState) {
	rs := reflect.ValueOf(conn).Elem()
	rf := rs.FieldByName("hs")
	// rf can't be read or set.
	rf = reflect.NewAt(rf.Type(), unsafe.Pointer(rf.UnsafeAddr())).Elem()
	return rf.Interface().(*noise.HandshakeState)
}

func proxyCopy(errc chan<- error, dst io.Writer, src io.Reader) {
	if dst == nil {
		dst = os.Stdout
	}
	if src == nil {
		src = os.Stdin
	}
	defer src.(io.Closer).Close()
	defer dst.(io.Closer).Close()
	_, err := io.Copy(dst, src)
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

	for {
		nconn, err := nln.Accept()
		if err != nil {
			log.Panic(err)
		}
		log.Printf("%+v\n", nconn)
		defer nconn.Close()

		log.Printf("%v\n", nconn.(*noiseconn.Conn).HandshakeComplete())

		for {
			log.Println("READ")
			b := make([]byte, 655360)
			n, err := nconn.Read(b)
			log.Println("READ DONE")
			if err != nil {
				log.Panic(err)
			}
			log.Printf("hsread=%v\n", n)
			log.Println("WRITE")
			nconn.Write([]byte("!"))
			log.Println("WRITE DONE")
			if nconn.(*noiseconn.Conn).HandshakeComplete() {
				break
			}
		}
		
		client := makeClient(clientarg)

		go copy(nconn, client)
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

func makeNoiseClient(arg string) net.Conn {
	args := strings.Split(arg, ",")
	arg = args[0]

	var verify []byte

	keypair, err := noise.DH25519.GenerateKeypair(nil)
	if err != nil {
		log.Panic(err)
	}

	for _, flag := range(args[1:]) {
		switch {
		case strings.HasPrefix(flag, "verify="):
			data, err := base64.StdEncoding.DecodeString(flag[7:])
			if err != nil {
				log.Fatal(err)
			}
			verify = data
		case strings.HasPrefix(flag, "privkey="):
			keypair = loadKey(flag[8:])
		default:
			log.Printf("ignoring unknown flag %s\n", flag)
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

	hs := GetHandshakeState(nconn)
		
	log.Printf("%v\n", nconn.HandshakeComplete())
	log.Printf("%#+v\n", hs.PeerStatic())
	
	for !nconn.HandshakeComplete() {
		log.Println("WRITE")
		nconn.Write([]byte("!"))
		log.Println("WRITE DONE")
		
		b := make([]byte, 65536)
		log.Println("READ")
		n, err := nconn.Read(b)
		log.Println("READ DONE")
		if err != nil {
			log.Panic(err)
		}
		log.Printf("hsread=%v\n", n)
		log.Printf("%v\n", nconn.HandshakeComplete())
	}

	if verify != nil && !bytes.Equal(hs.PeerStatic(), verify) {
		go nconn.Close()
		log.Fatal("key mismatch!")
	}

//	log.Printf("connected to: %s %s\n", base64.StdEncoding.EncodeToString(hs.PeerStatic()),
//		base64.StdEncoding.EncodeToString(verify))
//	log.Printf("%+v\n", hs.PeerStatic())

	return nconn
}

func main() {
	log.SetPrefix("snowcat: ")
	log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))

	makeServer(os.Args[1], os.Args[2])
}
