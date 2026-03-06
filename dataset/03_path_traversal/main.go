package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
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

// createSampleFiles populates /app/public/ with sample files for normal serving.
func createSampleFiles() {
	os.MkdirAll("/app/public", 0755)
	for i := 1; i <= 10; i++ {
		filename := fmt.Sprintf("/app/public/doc%d.txt", i)
		content := fmt.Sprintf("This is document %d.\nIt contains sample data for testing.\nLine %d of content.\n", i, i*10)
		os.WriteFile(filename, []byte(content), 0644)
	}
	// Also create a nested directory.
	os.MkdirAll("/app/public/reports", 0755)
	for i := 1; i <= 5; i++ {
		filename := fmt.Sprintf("/app/public/reports/report%d.csv", i)
		content := fmt.Sprintf("id,name,value\n%d,item_%d,%d\n", i, i, i*100)
		os.WriteFile(filename, []byte(content), 0644)
	}
}

// handleFileRequest serves files from /app/public/.
// In normal mode: validates paths. In attack mode: allows traversal.
func handleFileRequest(w http.ResponseWriter, r *http.Request) {
	requestedPath := strings.TrimPrefix(r.URL.Path, "/files/")
	if requestedPath == "" {
		http.Error(w, "no file specified", http.StatusBadRequest)
		return
	}

	var fullPath string
	if mode == "attack" {
		// In attack mode, do NOT sanitize path — allow traversal.
		// filepath.Join would collapse "../" so we concatenate directly.
		fullPath = "/app/public/" + requestedPath

		// Check if this is actually a traversal attempt.
		if strings.Contains(requestedPath, "..") {
			log.Printf("[ATTACK] Path traversal detected: %s -> %s", requestedPath, fullPath)
			// Resolve the actual path to see what file would be opened.
			resolved, _ := filepath.Abs(fullPath)
			writeLabel(Label{
				Timestamp: time.Now().UnixNano(),
				Type:      "path_traversal",
				Detail:    fmt.Sprintf("requested=%s resolved=%s", requestedPath, resolved),
			})
			fullPath = resolved
		}
	} else {
		// Normal mode: clean the path and validate it stays within /app/public/.
		cleanPath := filepath.Clean(requestedPath)
		fullPath = filepath.Join("/app/public", cleanPath)
		if !strings.HasPrefix(fullPath, "/app/public") {
			http.Error(w, "access denied", http.StatusForbidden)
			log.Printf("[NORMAL] Blocked traversal attempt: %s", requestedPath)
			return
		}
	}

	// Open and read the file — this is where the interesting syscalls happen.
	// open -> read -> write(send)
	f, err := os.Open(fullPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("file not found: %s", requestedPath), http.StatusNotFound)
		log.Printf("[SERVER] File open error: %s -> %v", fullPath, err)
		return
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		http.Error(w, "read error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(data)
	log.Printf("[SERVER] Served file: %s (%d bytes)", fullPath, len(data))
}

// normalTrafficGenerator requests legitimate files continuously.
func normalTrafficGenerator(stopCh <-chan struct{}) {
	files := []string{
		"doc1.txt", "doc2.txt", "doc3.txt", "doc4.txt", "doc5.txt",
		"doc6.txt", "doc7.txt", "doc8.txt", "doc9.txt", "doc10.txt",
		"reports/report1.csv", "reports/report2.csv", "reports/report3.csv",
	}
	client := &http.Client{Timeout: 2 * time.Second}
	interval := time.Second / time.Duration(normalRate)

	for {
		select {
		case <-stopCh:
			return
		default:
			file := files[rand.Intn(len(files))]
			url := fmt.Sprintf("http://localhost:8080/files/%s", file)
			resp, err := client.Get(url)
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			time.Sleep(interval)
		}
	}
}

// attackTrafficGenerator sends path traversal requests at Poisson intervals.
func attackTrafficGenerator(stopCh <-chan struct{}) {
	traversalPayloads := []string{
		"../../etc/passwd",
		"../../etc/hostname",
		"../../etc/resolv.conf",
		"../../etc/os-release",
		"../../proc/self/status",
		"../../proc/self/cmdline",
		"../../etc/group",
		"../../etc/nsswitch.conf",
	}
	client := &http.Client{Timeout: 5 * time.Second}

	for {
		wait := time.Duration(float64(attackInterval) * (0.5 + rand.ExpFloat64()))
		select {
		case <-stopCh:
			return
		case <-time.After(wait):
			payload := traversalPayloads[rand.Intn(len(traversalPayloads))]
			url := fmt.Sprintf("http://localhost:8080/files/%s", payload)
			log.Printf("[ATTACK-GEN] Sending traversal: %s", payload)
			resp, err := client.Get(url)
			if err == nil {
				io.Copy(io.Discard, resp.Body)
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

	if envMode := os.Getenv("MODE"); envMode != "" {
		mode = envMode
	}
	if envDur := os.Getenv("DURATION"); envDur != "" {
		if d, err := time.ParseDuration(envDur); err == nil {
			duration = d
		}
	}

	log.Printf("Starting Path Traversal Emulator | mode=%s duration=%s attack-interval=%s normal-rate=%d",
		mode, duration, attackInterval, normalRate)

	createSampleFiles()

	var err error
	labelFile, err = os.OpenFile("/app/labels.jsonl", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("Warning: could not open label file: %v", err)
		labelFile = nil
	}

	http.HandleFunc("/files/", handleFileRequest)
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
		go attackTrafficGenerator(stopCh)
	}

	time.Sleep(duration)
	close(stopCh)

	if labelFile != nil {
		labelFile.Close()
	}

	log.Println("Emulator finished.")
}
