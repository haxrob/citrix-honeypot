/*
Author: robert@x1sec.com
        https://twitter.com/x1sec

License: MIT

To generate self-signed certificate:

openssl genrsa -out server.key 2048
openssl ecparam -genkey -name secp384r1 -out server.key
openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
*/

package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type eventLogger struct {
	mu     sync.Mutex
	logger *log.Logger
	path   string
	file   io.Writer
}

var (
	hitLog          eventLogger
	allRequestsLog  eventLogger
	loginAttemptLog eventLogger
)

func main() {

	fmt.Println("test")

	setupLogging()

	r := mux.NewRouter()

	// Important as not to redirect /../
	r.SkipClean(true)

	// Custom 404
	r.NotFoundHandler = http.HandlerFunc(notFoundHandler)

	// Detect scanners
	r.HandleFunc("/vpn/../vpns/cfg/smb.conf", smbHandler)

	// Login attempts (TODO: fix path to correct one)
	r.HandleFunc("/login", loginHandler)

	// Will trigger all method types under /vpn/
	r.PathPrefix("/vpn/").Handler(http.HandlerFunc(traversalHandler))

	// Lots of content to serve (css, js etc)
	r.PathPrefix("/admin_ui/").Handler(staticWrapper(http.FileServer(http.Dir("./static/"))))

	//r.PathPrefix("/").Handler(staticWrapper(http.FileServer(http.Dir("./static/"))))
	// Can't use PathPrefix from / otherwise will catch 404 and skip our custom 404 handler
	r.HandleFunc("/", indexHandler)

	fmt.Println("Listening on port 80 and 443 ... ")

	// Listen on plain HTTP
	go func() {
		http.ListenAndServe(":80", logHandler(r))
	}()

	// log invalid TLS connections to file rather then stderr (default)
	tlsErrLog, err := os.Create("./logs/tlsErrors.log")
	if err != nil {
		panic(err)
	}
	defer tlsErrLog.Close()

	// must support HTTPS
	if _, err := os.Stat("./server.crt"); os.IsNotExist(err) {
		fmt.Println("TLS certificate missing.")
		os.Exit(1)
	}
	if _, err := os.Stat("./server.key"); os.IsNotExist(err) {
		fmt.Println("Private key missing.")
		os.Exit(1)
	}

	// Listen on HTTPS
	srv := &http.Server{
		ErrorLog: log.New(tlsErrLog, "", log.LstdFlags|log.Lshortfile),
		Handler:  logHandler(r),
		Addr:     ":443",
	}

	srv.ListenAndServeTLS("server.crt", "server.key")
}

/* 404 */
func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("The requested page was not found on this server."))
}

/* main login page */
func indexHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/index.html")
}

/* attempted login */
func loginHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodPost {
		r.ParseForm()

		u := r.PostForm.Get("username")
		p := r.PostForm.Get("password")

		loginAttemptLog.mu.Lock()
		defer loginAttemptLog.mu.Unlock()
		loginAttemptLog.logger.Printf("Failed login from %s user:%s pass:%s\n", r.RemoteAddr, u, p)
	}

	http.ServeFile(w, r, "./static/do_login.html")
}

/* trigger CVE-2019-19781 traversal vulnerability */
func traversalHandler(w http.ResponseWriter, r *http.Request) {

	match, _ := regexp.MatchString(".+(pl|xml)", r.URL.Path)
	if match == false {
		return
	}

	headers := `Server: Apache
	X-Citrix-Application: Receiver for Web
	X-Frame-Options: SAMEORIGIN
	Transfer-Encoding: chunked
	Content-Type: text; charset=utf-8`

	setResponseHeaders(w, headers)
	writeLogEntry(r, "Exploitation detected ...")

}

/* scanning attempts for CVE-2019-19781 */
func smbHandler(w http.ResponseWriter, r *http.Request) {

	message := "Scanning detected ... "
	if strings.ContainsRune(r.URL.RawPath, '%') {
		message = message + " with IDS evasion."
	}

	writeLogEntry(r, message)

	headers := `Server: Apache
	X-Frame-Options: SAMEORIGIN
	Last-Modified: Thu, 28 Nov 2019 20:19:22 GMT
	ETag: "53-5986dd42b0680"
	Accept-Ranges: bytes
	X-XSS-Protection: 1; mode=block
	X-Content-Type-Options: nosniff
	Content-Type: text/plain; charset=UTF-8`

	setResponseHeaders(w, headers)

	smbConfig := "[global]\r\n\tencrypt passwords = yes\r\n\tname resolve order = lmhosts wins host bcast\r\n"
	w.Write([]byte(smbConfig))
}

/* Log all requests regardless of match */
func logHandler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		clientIP := r.RemoteAddr
		if colon := strings.LastIndex(clientIP, ":"); colon != -1 {
			clientIP = clientIP[:colon]
		}

		requestLine := fmt.Sprintf("%s %s %s", r.Method, r.RequestURI, r.Proto)
		x := fmt.Sprintf("%s - - \"%s\"\n", clientIP, requestLine)
		allRequestsLog.logger.Printf(x)

		h.ServeHTTP(w, r)
	})
}

/* default headers */
func staticWrapper(h http.Handler) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		headers := `Cache-Control : no-cache		
		Server: Apache
		X-Frame-Options: SAMEORIGIN
		X-XSS-Protection: 1; mode=block
		Set-Cookie: NSC_TEMP=xyz;Path=/;expires=Wednesday, 09-Nov-2024 23:12:40 GMT;Secure
		Set-Cookie: NSC_PERS=xyz;Path=/;expires=Wednesday, 09-Nov-2024 23:12:40 GMT;Secure`

		//Content-Type: text/html; charset=UTF-8


		setResponseHeaders(w, headers)

		h.ServeHTTP(w, r)
	})
}

/* set headers in response */
func setResponseHeaders(w http.ResponseWriter, h string) {
	t := time.Now().UTC()
	d := t.Format(time.RFC1123)
	dh := "Date: " + d + "\n"
	ah := dh + h

	for _, l := range strings.Split(ah, "\n") {
		k := strings.SplitN(l, ":", 2)
		w.Header().Set(strings.TrimLeft(k[0], "\t"), strings.Trim(k[1], " "))
	}
}

/* Log everything related to CVE-2019-19781 */
func writeLogEntry(r *http.Request, message string) {
	hitLog.mu.Lock()
	defer hitLog.mu.Unlock()

	logLine := "\n-------------------\n"
	if message != "" {
		logLine = logLine + message + "\n"
	}

	i := strings.LastIndex(r.RemoteAddr, ":")
	if i != -1 {
		logLine += "src: " + r.RemoteAddr[:i] + "\n"
	}

	l, err := httputil.DumpRequest(r, true)
	if err == nil {
		logLine = logLine + string(l)
	} else {
		fmt.Println("error")
	}

	hitLog.logger.Println(logLine)

}

/* should do this better */
func setupLogging() {

	cdir, _ := os.Getwd()
	dir := cdir + "/logs/"

	fmt.Println(dir)
	// create logs dir
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0755)
		if err != nil {
			panic(err)
		}
	}

	openLogger(&hitLog, dir + "hits.log")
	openLogger(&loginAttemptLog, dir + "logins.log")
	openLogger(&allRequestsLog, dir + "all.log")
}

func openLogger(e *eventLogger, path string) {
	var err error
	e.path = path
	e.file, err = os.OpenFile(e.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	e.logger = log.New(e.file, "", log.LstdFlags)
}
