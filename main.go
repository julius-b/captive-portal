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
const IPTABLES_BINARY = "iptables"

// when an authenticated IP accesses any route, automatically forward it to a public website
// (firefox needs this for /success.txt, otherwise it keeps showing the auth page)
// TODO elimintate duplicates
var authenticatedIPs []string
var emails []string

var signals chan os.Signal

func root(w http.ResponseWriter, r *http.Request) {
    ip := strings.Split(r.RemoteAddr, ":")[0]
    log.Printf("[root] <%s> path: %s", ip, r.URL.Path)

    if contains(authenticatedIPs, ip) {
        log.Printf("[root] <%s> already authenticated", ip)
        http.Redirect(w, r, "https://google.com", http.StatusSeeOther)
        return
    }

    http.ServeFile(w, r, "login.html")
}

func auth(w http.ResponseWriter, r *http.Request) {
    ip := strings.Split(r.RemoteAddr, ":")[0]
    
    r.ParseForm()
    userEmail := r.Form.Get("user_email")

    log.Printf("[auth] <%s> authenticating: '%s'...", ip, userEmail)
    emails = append(emails, userEmail)

    authenticatedIPs = append(authenticatedIPs, ip)

    cmd := fmt.Sprintf("%s -t nat -I PREROUTING -s %s -j ACCEPT", IPTABLES_BINARY, ip)
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

func deauth(w http.ResponseWriter, r *http.Request) {
    ip := strings.Split(r.RemoteAddr, ":")[0]

    log.Printf("[deauth] <%s> deauthenticating...", ip)

    i := index(authenticatedIPs, ip)
    if i != -1 {
        authenticatedIPs = append(authenticatedIPs[:i], authenticatedIPs[i+1:]...)
    }

    cmd := fmt.Sprintf("%s -t nat -D PREROUTING -s %s -j ACCEPT", IPTABLES_BINARY, ip)
    out, err := run(cmd)
    log.Printf("[deauth] iptables: %s", out)
    if err != nil {
        log.Printf("[deauth] iptables: err - %v", err)
        fmt.Fprintf(w, "Something went wrong")
        return
    }
    
    fmt.Fprintf(w, "Deauthenticated")
}

func deauthAll(w http.ResponseWriter, r *http.Request) {
    ip := strings.Split(r.RemoteAddr, ":")[0]

    log.Printf("[deauth-all] <%s> deauthenticating all...", ip)
    if !contains(authenticatedIPs, ip) {
        log.Printf("[deauth-all] <%s> err: not authenticated", ip)
        fmt.Fprintf(w, "Not authenticated")
        return
    }
    log.Printf("[deauth-all] <%s> - deauthenticating...", ip)
    deauthAllImpl()
    
    authenticatedIPs = make([]string, 0)
}

func deauthAllImpl() {
    for k, v := range authenticatedIPs {
        log.Printf("[deauth-all] %d: %s - deauthenticating...", k, v)
        cmd := fmt.Sprintf("%s -t nat -D PREROUTING -s %s -j ACCEPT", IPTABLES_BINARY, v)
        out, err := run(cmd)
        log.Printf("[deauth-all] iptables: %s", out)
        if err != nil {
            log.Printf("[deauth-all] iptables: err - %v", err)
        }
    }
}

func shutdown(w http.ResponseWriter, r *http.Request) {
    ip := strings.Split(r.RemoteAddr, ":")[0]

    log.Printf("[shutdown] <%s> shutting down...", ip)
    if !contains(authenticatedIPs, ip) {
        log.Printf("[shutdown] <%s> err: not authenticated", ip)
        fmt.Fprintf(w, "Not authenticated")
        return
    }

    signals <- os.Interrupt
}

func info(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "authenticatedIPs: %v\nemails: %v", authenticatedIPs, emails)
}

// does not grant actual access
func fakeAuth(w http.ResponseWriter, r *http.Request) {
    ip := strings.Split(r.RemoteAddr, ":")[0]

    log.Printf("[fake-auth] <%s> authenticating...", ip)
    authenticatedIPs = append(authenticatedIPs, ip)
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

    signals = make(chan os.Signal, 1)
    done := make(chan bool, 1)
    go func() {
        sig := <-signals
        log.Printf("Signal: %v", sig)
        dismantleIP()
        deauthAllImpl()
        if err := srv.Shutdown(context.TODO()); err != nil {
            panic(err)
        }
        done <- true
    }()

    signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
    
    setupIP()

    http.HandleFunc("/auth", auth)
    http.HandleFunc("/deauth", deauth)
    http.HandleFunc("/deauth-all", deauthAll)
    http.HandleFunc("/info", info)
    http.HandleFunc("/fake-auth", fakeAuth)
    http.HandleFunc("/shutdown", shutdown)
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
