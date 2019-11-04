package main

import (
    "fmt"
    "log"
    "os"
    "os/exec"
	"os/signal"
	"syscall"
    "strings"
    "net/http"
    "context"
)

// TODO automatically parse `ip addr show $IFACE`
const IP_ADDRESS = "192.168.43.227"
const HTTP_PORT = 80
const IFACE = "wlan0"
// /system/bin/iptables
const IPTABLES_BINARY = "/system/bin/iptables"

// TODO when an authenticated IP accesses any route, automatically forward it to a public website
// (firefox needs this for /success.txt, otherwise it keeps showing the auth page)
var authenticatedIPs []string

func root(w http.ResponseWriter, r *http.Request) {
    ip := strings.Split(r.RemoteAddr, ":")[0]
    log.Printf("[root] <%s> path: %s", ip, r.URL.Path)
    http.ServeFile(w, r, "login.html")
}

func auth(w http.ResponseWriter, r *http.Request) {
    ip := strings.Split(r.RemoteAddr, ":")[0]
    
    r.ParseForm()
    userEmail := r.Form.Get("user_email")

    log.Printf("[auth] <%s> authenticating: '%s'...", ip, userEmail)

    cmd := fmt.Sprintf("%s -t nat -I PREROUTING 1 -s %s -j ACCEPT", IPTABLES_BINARY, ip)
    out, err := run(cmd)
    log.Printf("[auth] iptables: %s", out)
    if err != nil {
        log.Printf("[auth] iptables: err - %v", err)
        fmt.Fprintf(w, "Something went wrong")
        return
    }

    //fmt.Fprintf(w, "Authenticated")

    // redirect to a public page so the client knows it's now connected to the internet
    // no-one uses duck.com :(
    http.Redirect(w, r, "https://google.com", http.StatusSeeOther)
}

// TODO remove from array + iptables
func deauth(w http.ResponseWriter, r *http.Request) {
}

// TODO remove from array + iptables
func deauthAll(w http.ResponseWriter, r *http.Request) {
}

// TODO hold-and-catch-fire
func shutdown(w http.ResponseWriter, r *http.Request) {
}

func setupIP() {
    commands := [...]string{
        fmt.Sprintf("%s -t nat -A PREROUTING -i %s -p tcp --dport 80 -j DNAT --to-destination %s:%d", IPTABLES_BINARY, IFACE, IP_ADDRESS, HTTP_PORT),
        fmt.Sprintf("%s -t nat -A PREROUTING -i %s -p tcp --dport 443 -j DNAT --to-destination %s:%d", IPTABLES_BINARY, IFACE, IP_ADDRESS, HTTP_PORT),
        fmt.Sprintf("%s -t nat -A POSTROUTING -j MASQUERADE", IPTABLES_BINARY),
    }
    for k, v := range commands {
        log.Printf("[setupIP] %d: %s", k, v)

        out, err := run(v)
        log.Printf("[setupIP] %d: %s", k, out)
        if err != nil {
            log.Fatalf("[setupIP] %d: err - %v", k, err)
        }
    }
}

func dismantleIP() {
    commands := [...]string{
        fmt.Sprintf("%s -t nat -D PREROUTING -i %s -p tcp --dport 80 -j DNAT --to-destination %s:%d", IPTABLES_BINARY, IFACE, IP_ADDRESS, HTTP_PORT),
        fmt.Sprintf("%s -t nat -D PREROUTING -i %s -p tcp --dport 443 -j DNAT --to-destination %s:%d", IPTABLES_BINARY, IFACE, IP_ADDRESS, HTTP_PORT),
        fmt.Sprintf("%s -t nat -D POSTROUTING -j MASQUERADE", IPTABLES_BINARY),
    }
    for k, v := range commands {
        log.Printf("[dismantleIP] %d: %s", k, v)

        out, err := run(v)
        log.Printf("[dismantleIP] %d: %s", k, out)
        if err != nil {
            log.Fatalf("[dismantleIP] %d: err - %v", k, err)
        }
    }
}

func run(command string) ([]byte, error) {
    parts := strings.Fields(command)
    head := parts[0]
    parts = parts[1:len(parts)]
    //out, err := exec.Command("bash", "-c", fmt.Sprintf("\"%s\"", v)).Output()
    return exec.Command(head, parts...).Output()
}

func main() {
    srv := &http.Server{Addr: fmt.Sprintf(":%d", HTTP_PORT)}

    signals := make(chan os.Signal, 1)
    done := make(chan bool, 1)
    go func() {
        sig := <-signals
        log.Printf("Signal: %v", sig)
        dismantleIP()
        if err := srv.Shutdown(context.TODO()); err != nil {
            panic(err)
        }    
        done <- true
    }()

    signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
    
    setupIP()

    http.HandleFunc("/auth", auth)
    http.HandleFunc("/", root)

    go func() {
        log.Print("[main] starting captive portal...")
        if err := http.ListenAndServe(fmt.Sprintf(":%d", HTTP_PORT), nil); err != nil {
            log.Printf("[main] http failed: %v", err)
        }
    }()
    log.Println("Awaiting signal...")
    <-done
    log.Println("Exiting...")
}
