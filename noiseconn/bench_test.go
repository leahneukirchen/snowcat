package noiseconn

import (
	"crypto/rand"
	"io"
	"net"
	"testing"

	"github.com/dsnet/try"
	"github.com/flynn/noise"
	"golang.org/x/sync/errgroup"
)

func osNetPipe() (client net.Conn, server net.Conn, err error) {
	defer try.HandleF(&err, func() {
		if client != nil {
			client.Close()
		}
		if server != nil {
			server.Close()
		}
	})
	l := try.E1(net.Listen("tcp", "127.0.0.1:0"))
	defer l.Close()

	var eg errgroup.Group

	eg.Go(func() (err error) {
		defer try.Handle(&err)
		client = try.E1(net.Dial(l.Addr().Network(), l.Addr().String()))
		return nil
	})
	eg.Go(func() (err error) {
		defer try.Handle(&err)
		server = try.E1(l.Accept())
		return nil
	})
	try.E(eg.Wait())
	return client, server, nil
}

func BenchmarkThroughput(b *testing.B) {
	run := func(size int64) func(*testing.B) {
		return func(b *testing.B) {
			defer try.F(b.Fatal)
			p1, p2 := try.E2(osNetPipe())

			clientKey := try.E1(noise.DH25519.GenerateKeypair(rand.Reader))
			serverKey := try.E1(noise.DH25519.GenerateKeypair(rand.Reader))

			client := try.E1(NewConn(p1, noise.Config{
				CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b),
				Pattern:       noise.HandshakeIK,
				Initiator:     true,
				StaticKeypair: clientKey,
				PeerStatic:    serverKey.Public,
			}))
			defer client.Close()

			server := try.E1(NewConn(p2, noise.Config{
				CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2b),
				Pattern:       noise.HandshakeIK,
				Initiator:     false,
				StaticKeypair: serverKey,
			}))
			defer server.Close()

			write := make([]byte, size)
			read := make([]byte, size)
			try.E1(rand.Read(write))
			b.SetBytes(size)
			b.ReportAllocs()
			b.ResetTimer()

			errch := make(chan error, 2)
			go func() {
				errch <- (func() (err error) {
					defer try.Handle(&err)
					try.E1(client.Write([]byte("get data")))
					for i := 0; i < b.N; i++ {
						try.E1(io.ReadFull(client, read))
					}
					return nil
				})()
			}()
			go func() {
				errch <- (func() (err error) {
					defer try.Handle(&err)
					try.E1(io.ReadFull(server, make([]byte, len("get data"))))
					for i := 0; i < b.N; i++ {
						try.E1(server.Write(write))
					}
					return nil
				})()
			}()
			try.E(<-errch)
			try.E(<-errch)
			try.E(client.Close())
			try.E(server.Close())
		}
	}

	b.Run("1K", run(1000))
	b.Run("10K", run(1000*10))
	b.Run("100K", run(1000*100))
	b.Run("1M", run(1000*1000))
	b.Run("10M", run(1000*10000))
	b.Run("100M", run(1000*100000))
}
