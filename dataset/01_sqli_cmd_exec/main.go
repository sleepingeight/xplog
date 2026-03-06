package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sync"
	"time"
)

// Label represents a ground-truth attack label for GNN training.
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

// Simulated in-memory "database".
var userDB = map[string]string{
	"alice":   "Alice Johnson - Engineering",
	"bob":     "Bob Smith - Marketing",
	"charlie": "Charlie Brown - Sales",
	"dave":    "Dave Wilson - DevOps",
	"eve":     "Eve Davis - Security",
}

func writeLabel(l Label) {
	labelMu.Lock()
	defer labelMu.Unlock()
	if labelFile != nil {
		data, _ := json.Marshal(l)
		labelFile.Write(append(data, '\n'))
	}
}

// handleQuery processes user lookup queries.
// In normal mode: safe map lookup only.
// In attack mode: if query contains shell metacharacters, executes via shell.
func handleQuery(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	if user == "" {
		http.Error(w, "missing 'user' parameter", http.StatusBadRequest)
		return
	}

	// Always do normal processing first (the legitimate lookup).
	result, found := userDB[user]
	if found {
		fmt.Fprintf(w, "User: %s\n", result)
		log.Printf("[NORMAL] Query for user=%s -> found", user)
		return
	}

	if mode == "attack" {
		// In attack mode, simulate a vulnerable handler that passes unsanitized
		// input to a shell command (e.g., legacy lookup script).
		log.Printf("[ATTACK] Executing shell command for user=%s", user)
		writeLabel(Label{
			Timestamp: time.Now().UnixNano(),
			Type:      "sqli_exec",
			Detail:    fmt.Sprintf("sh -c echo Searching for user: %s", user),
		})

		// This triggers: clone -> execve -> open -> read -> write
		cmd := exec.Command("sh", "-c", fmt.Sprintf("echo 'Searching for user: %s' && cat /etc/hostname 2>/dev/null && echo 'Lookup complete'", user))
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Fprintf(w, "Lookup error: %v\nPartial output: %s\n", err, string(output))
		} else {
			fmt.Fprintf(w, "Lookup result:\n%s\n", string(output))
		}
		return
	}

	// Normal mode: user not found.
	fmt.Fprintf(w, "User '%s' not found\n", user)
	log.Printf("[NORMAL] Query for user=%s -> not found", user)
}

// normalTrafficGenerator continuously sends legitimate HTTP requests.
func normalTrafficGenerator(stopCh <-chan struct{}) {
	users := []string{"alice", "bob", "charlie", "dave", "eve"}
	client := &http.Client{Timeout: 2 * time.Second}
	interval := time.Second / time.Duration(normalRate)

	for {
		select {
		case <-stopCh:
			return
		default:
			user := users[rand.Intn(len(users))]
			url := fmt.Sprintf("http://localhost:8080/query?user=%s", user)
			resp, err := client.Get(url)
			if err == nil {
				resp.Body.Close()
			}
			time.Sleep(interval)
		}
	}
}

// attackTrafficGenerator sends attack queries at Poisson-distributed intervals.
func attackTrafficGenerator(stopCh <-chan struct{}) {
	payloads := []string{
		"; cat /etc/hostname",
		"; id",
		"; whoami",
		"; uname -a",
		"; ls /tmp",
		"; cat /etc/resolv.conf",
		"; ps aux",
		"; env",
	}
	client := &http.Client{Timeout: 5 * time.Second}

	for {
		// Poisson-distributed wait (exponential inter-arrival).
		wait := time.Duration(float64(attackInterval) * (0.5 + rand.ExpFloat64()))
		select {
		case <-stopCh:
			return
		case <-time.After(wait):
			payload := payloads[rand.Intn(len(payloads))]
			// Use url.Values for proper encoding of special characters.
			params := url.Values{}
			params.Set("user", payload)
			targetURL := "http://localhost:8080/query?" + params.Encode()
			log.Printf("[ATTACK-GEN] Sending attack payload: %s", payload)
			resp, err := client.Get(targetURL)
			if err == nil {
				resp.Body.Close()
			}
		}
	}
}


func main() {
	flag.StringVar(&mode, "mode", "normal", "Run mode: 'normal' or 'attack'")
	flag.DurationVar(&duration, "duration", 120*time.Second, "Total runtime duration")
	flag.DurationVar(&attackInterval, "attack-interval", 5*time.Second, "Mean time between attack actions")
	flag.IntVar(&normalRate, "normal-rate", 10, "Normal operations per second")
	flag.Parse()

	// Override from env if set (for Docker).
	if envMode := os.Getenv("MODE"); envMode != "" {
		mode = envMode
	}
	if envDur := os.Getenv("DURATION"); envDur != "" {
		if d, err := time.ParseDuration(envDur); err == nil {
			duration = d
		}
	}

	log.Printf("Starting SQL Injection Emulator | mode=%s duration=%s attack-interval=%s normal-rate=%d",
		mode, duration, attackInterval, normalRate)

	// Open label file.
	var err error
	labelFile, err = os.OpenFile("/app/labels.jsonl", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("Warning: could not open label file: %v", err)
		labelFile = nil
	}

	// Start HTTP server.
	http.HandleFunc("/query", handleQuery)
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

	// Give server a moment to start.
	time.Sleep(500 * time.Millisecond)

	stopCh := make(chan struct{})

	// Start normal traffic generator.
	go normalTrafficGenerator(stopCh)

	// In attack mode, also start the attack traffic generator.
	if mode == "attack" {
		go attackTrafficGenerator(stopCh)
	}

	// Run for the specified duration.
	time.Sleep(duration)
	close(stopCh)

	if labelFile != nil {
		labelFile.Close()
	}

	log.Println("Emulator finished.")
}
