package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"
)

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	dir, err := ioutil.TempDir("", "gimmie")
	if err != nil {
		http.Error(w, "unable to make tmp directory", http.StatusBadRequest)
		return
	}
	defer os.RemoveAll(dir)
	if err = uploadToTmp(r, dir); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	getIP := func() string {
		ip, port, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return ""
		}

		userIP := net.ParseIP(ip)
		if userIP == nil {
			return ""
		}
		forward := r.Header.Get("X-Forwarded-For")
		if forward != "" {
			forward = "-" + forward
		}
		if port != "" {
			port = "-" + port
		}
		return ip + "-" + port + forward
	}

	if err = os.Rename(dir, "./store/"+getIP()+time.Now().Format("20060102-15_04_05")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/static", http.StatusSeeOther)
}

func uploadToTmp(req *http.Request, dir string) error {
	read, merr := req.MultipartReader()
	if merr != nil {
		return fmt.Errorf("unable to read http form request")
	}
	for {
		part, err := read.NextPart()
		if err == io.EOF {
			break
		}
		f, err := os.OpenFile(filepath.Join(dir, part.FileName()), os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			return fmt.Errorf("unable to write create file %v on disk, due to error: %s", part.FileName(), err.Error())
		}
		defer f.Close()
		if _, err = io.Copy(f, part); err != nil {
			return fmt.Errorf("unable to write data to %v on disk, due to error %s", part.FileName(), err)
		}
	}
	return nil
}

func main() {
	stop := make(chan os.Signal)
	signal.Notify(stop, os.Interrupt)
	addr := os.Getenv("PORT")
	if addr == "" {
		addr = "2310"
	}

	ip := os.Getenv("IP")
	if ip == "" {
		ip = "127.0.0.1"
	}
	mux := http.NewServeMux()
	if _, err := os.Stat("./store"); os.IsNotExist(err) {
		os.Mkdir("./store", 0700)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./store"))))
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		fmt.Fprintf(w, `<!DOCTYPE html>
      <html>
      <body>
      <form id="uploadbanner" enctype="multipart/form-data" method="post" action="/upload">
        <input id="fileupload" name="file" type="file" />
        <input type="submit" value="submit" id="submit" />
      </form>
      </body>
      </html>
  `)
	})
	mux.HandleFunc("/upload", uploadHandler)
	// generate a new key-pair
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("unable to generate root key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		log.Fatalf("unable to create root certificate, failed to generate serial number: %v" + err.Error())
	}

	rootCert := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Gimme, Skiarn."}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:        true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP(ip)},
	}

	cert, err := x509.CreateCertificate(rand.Reader, rootCert, rootCert, &rootKey.PublicKey, rootKey)
	if err != nil {
		log.Fatalf("error while creating root certificate: %v\n", err)
	}

	err = ioutil.WriteFile("cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0644)
	if err != nil {
		log.Fatalf("error writing cert.pem: %v", err)
	}
	err = ioutil.WriteFile("key.pem", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rootKey)}), 0644)
	if err != nil {
		log.Fatalf("error writing key.pem: %v", err)
	}

	server := &http.Server{
		Addr:    ":" + addr,
		Handler: mux,
	}

	go func() {
		log.Printf("Listening on https://%s:%s\n", ip, addr)
		server.ListenAndServeTLS("cert.pem", "key.pem")
	}()

	<-stop

	log.Println("\nShutting down the server...")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	select {
	default:
		server.Shutdown(ctx)
		err = os.Remove("./cert.pem")
		if err != nil {
			log.Println("Error during cleanup:", err)
		}
		err = os.Remove("./key.pem")
		if err != nil {
			log.Println("Error during cleanup:", err)
		}
		ctx.Done()
		log.Println("Cleanup successful.")
	case <-ctx.Done():
		fmt.Println(ctx.Err())
	}

	if ctx.Err() != nil {
		log.Println("Failed to stop server gracefully:", ctx.Err())
	}
	log.Println("Server stopped")
}
