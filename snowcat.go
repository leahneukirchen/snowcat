package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"github.com/leahneukirchen/snowcat/noiseconn"

	"github.com/flynn/noise"
	"github.com/zeebo/errs"
)

const prologue = "SNOWCAT-001"

type HeaderField byte

const (
	HeaderEOH HeaderField = iota
	HeaderCertificate
)

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

	var verifyCA ed25519.PublicKey

	if verify, ok := opts["verifyca"]; ok {
		log.Println("will check certs")
		verifyCA = loadCertificate(verify)
	}

	var cert []byte
	if certificate, ok := opts["certificate"]; ok {
		log.Println("loaded certificate")
		cert = loadCertificate(certificate)
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
		log.Printf("accepted %+v\n", nconn)

		go func() {
			nconn := nconn.(*noiseconn.Conn)

			for !nconn.HandshakeComplete() {
				_, err := nconn.Write([]byte(""))
				if err != nil {
					log.Println("error: ", err)
					nconn.Close()
					return
				}
			}

			if verifyPeer != nil && !bytes.Equal(nconn.PeerStatic(), verifyPeer) {
				log.Println("error: key mismatch!")
				nconn.Close()
				return
			}

			if cert != nil {
				log.Printf("sending cert\n")
				writeFramed(nconn, HeaderCertificate, cert)
			}
			writeFramed(nconn, HeaderEOH, nil)

			var certificatePeer []byte

		Frame:
			for {
				typ, data := readFramed(nconn)
				switch typ {
				case HeaderEOH:
					log.Printf("end of metadata\n")
					break Frame
				case HeaderCertificate:
					certificatePeer = data
				}
			}

			if verifyCA != nil {
				if certificatePeer == nil {
					go nconn.Close()
					log.Println("no certificate sent!")
					return
				}

				if !ed25519.Verify(verifyCA, nconn.PeerStatic(), certificatePeer) {
					go nconn.Close()
					log.Println("can't validate certificate!")
					return
				}
			}

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

func loadCertificate(encoded string) []byte {
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

	cert, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		log.Fatal(err)
	}

	return cert
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

func writeFramed(wr io.Writer, typ HeaderField, data []byte) {
	if typ == 0 {
		wr.Write([]byte{0, 0})
		return
	}
	buf := append(make([]byte, 3), data...)
	buf[2] = byte(typ)
	binary.BigEndian.PutUint16(buf[:2], uint16(len(data)))
	wr.Write(buf)
}

func readFramed(rd io.Reader) (typ HeaderField, data []byte) {
	buf := make([]byte, 2)
	if n, err := rd.Read(buf); err != nil || n != 2 {
		log.Fatal("??? ", err)
	}
	msgSize := int(binary.BigEndian.Uint16(buf[:]))
	if msgSize == 0 {
		return 0, nil
	}
	buf = make([]byte, 1+msgSize)
	if n, err := rd.Read(buf); err != nil || n != 1+msgSize {
		log.Fatalf("??! n=%d %v\n", n, err)
	}
	return HeaderField(buf[0]), buf[1:]
}

func makeNoiseClient(arg string) (net.Conn, error) {
	arg, opts := parseConn(arg)

	var verifyPeer []byte

	if verify, ok := opts["verify"]; ok {
		verifyPeer = loadKey(verify).Private // abuse, it's the public key
	}

	var verifyCA ed25519.PublicKey

	if verify, ok := opts["verifyca"]; ok {
		log.Println("will check certs")
		verifyCA = loadCertificate(verify)
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

	if certificate, ok := opts["certificate"]; ok {
		writeFramed(nconn, HeaderCertificate, loadCertificate(certificate))
	}
	writeFramed(nconn, HeaderEOH, nil)

	var certificatePeer []byte

Frame:
	for {
		typ, data := readFramed(nconn)
		switch typ {
		case HeaderEOH:
			log.Printf("end of metadata\n")
			break Frame
		case HeaderCertificate:
			log.Printf("got cert\n")
			certificatePeer = data
		}
	}

	if verifyCA != nil {
		if certificatePeer == nil {
			go nconn.Close()
			return nil, errs.New("no certificate sent!")
		}

		if !ed25519.Verify(verifyCA, nconn.PeerStatic(), certificatePeer) {
			go nconn.Close()
			return nil, errs.New("can't validate certificate!")
		}
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

	if os.Args[1] == "genca" {
		_, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(base64.StdEncoding.EncodeToString(priv))
		return
	}

	if os.Args[1] == "capubkey" {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			log.Fatal("no private CA key given on standard input")
		}
		var privkey ed25519.PrivateKey
		privkey, err := base64.StdEncoding.DecodeString(scanner.Text())
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(base64.StdEncoding.EncodeToString(privkey.Public().(ed25519.PublicKey)))
		return
	}

	if os.Args[1] == "casignkey" {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			log.Fatal("no private CA key given on standard input")
		}

		var privkey ed25519.PrivateKey
		privkey, err := base64.StdEncoding.DecodeString(scanner.Text())
		if err != nil {
			log.Fatal(err)
		}

		if !scanner.Scan() {
			log.Fatal("no public key given on standard input")
		}

		pubkey := loadKey(scanner.Text()).Private // abuse

		log.Printf("%+v\n", privkey[:32])
		log.Printf("%+v\n", privkey.Public().(ed25519.PublicKey))
		log.Printf("%+v\n", pubkey)

		signature := ed25519.Sign(privkey, pubkey)

		log.Printf("%+v\n", signature)

		fmt.Println(base64.StdEncoding.EncodeToString(signature))

		log.Println(ed25519.Verify(privkey.Public().(ed25519.PublicKey), pubkey, signature))
		return
	}

	if os.Args[1] == "cacheckkey" {
		scanner := bufio.NewScanner(os.Stdin)
		if !scanner.Scan() {
			log.Fatal("no private CA key given on standard input")
		}

		var capubkey ed25519.PublicKey
		capubkey, err := base64.StdEncoding.DecodeString(scanner.Text())
		if err != nil {
			log.Fatal(err)
		}

		if !scanner.Scan() {
			log.Fatal("no public key given on standard input")
		}

		pubkey := loadKey(scanner.Text()).Private // abuse

		if !scanner.Scan() {
			log.Fatal("no public key given on standard input")
		}

		signature, err := base64.StdEncoding.DecodeString(scanner.Text())
		if err != nil {
			log.Fatal(err)
		}

		if ed25519.Verify(capubkey, pubkey, signature) {
			log.Println("OK!")
		} else {
			log.Fatal("fail")
		}

		return
	}

	makeServer(os.Args[1], os.Args[2])
}
