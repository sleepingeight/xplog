package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
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

const triggerString = "TRIGGER_REVERSE_SHELL"

// handleConnection handles a single TCP connection (echo server).
func handleConnection(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 4096)

	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("[SERVER] Read error: %v", err)
			}
			return
		}

		msg := string(buf[:n])

		// Check for attack trigger.
		if mode == "attack" && msg == triggerString {
			log.Printf("[ATTACK] Reverse shell trigger received!")
			simulateReverseShell()
			conn.Write([]byte("SHELL_SIMULATED\n"))
			return
		}

		// Normal echo.
		log.Printf("[NORMAL] Echo: %d bytes", n)
		conn.Write(buf[:n])
	}
}

// simulateReverseShell emulates the syscall pattern of a reverse shell.
// This produces: socket -> connect -> dup2 x3 -> execve
func simulateReverseShell() {
	writeLabel(Label{
		Timestamp: time.Now().UnixNano(),
		Type:      "reverse_shell",
		Detail:    "socket->connect->dup2x3->execve",
	})

	// Phase 1: Create a socket and connect to "C2" (localhost:19999).
	// We start a temporary listener to accept our connection.
	c2Listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Printf("[ATTACK] Could not create C2 listener: %v", err)
		return
	}
	c2Addr := c2Listener.Addr().String()

	// Accept in background.
	go func() {
		c2Conn, err := c2Listener.Accept()
		if err == nil {
			time.Sleep(500 * time.Millisecond)
			c2Conn.Close()
		}
		c2Listener.Close()
	}()

	// Connect to C2 — this triggers socket + connect syscalls.
	c2Sock, err := net.Dial("tcp", c2Addr)
	if err != nil {
		log.Printf("[ATTACK] C2 connect failed: %v", err)
		return
	}

	// Phase 2: dup2 — redirect file descriptors.
	// Get the raw fd from the connection.
	rawConn, err := c2Sock.(*net.TCPConn).SyscallConn()
	if err != nil {
		log.Printf("[ATTACK] Could not get raw conn: %v", err)
		c2Sock.Close()
		return
	}

	var dupErr error
	rawConn.Control(func(fd uintptr) {
		// Create duplicated fds to simulate dup2 pattern.
		// We dup to high fds to avoid disrupting our own process.
		newFd1, err1 := syscall.Dup(int(fd))
		newFd2, err2 := syscall.Dup(int(fd))
		newFd3, err3 := syscall.Dup(int(fd))
		if err1 != nil || err2 != nil || err3 != nil {
			dupErr = fmt.Errorf("dup errors: %v, %v, %v", err1, err2, err3)
			return
		}
		log.Printf("[ATTACK] dup2 simulated: fds %d, %d, %d", newFd1, newFd2, newFd3)
		// Close the duplicated fds.
		syscall.Close(newFd1)
		syscall.Close(newFd2)
		syscall.Close(newFd3)
	})

	c2Sock.Close()

	if dupErr != nil {
		log.Printf("[ATTACK] dup2 simulation error: %v", dupErr)
		return
	}

	// Phase 3: execve — execute a shell command.
	cmd := exec.Command("sh", "-c", "echo 'reverse_shell_simulated' && sleep 0.1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[ATTACK] execve error: %v", err)
	} else {
		log.Printf("[ATTACK] Shell output: %s", string(output))
	}
}

// normalTrafficGenerator sends echo messages to the server.
func normalTrafficGenerator(stopCh <-chan struct{}) {
	messages := []string{
		"hello world",
		"ping",
		"status check",
		"heartbeat",
		"data packet 12345",
		"test message",
		"keep alive",
	}
	interval := time.Second / time.Duration(normalRate)

	for {
		select {
		case <-stopCh:
			return
		default:
			conn, err := net.DialTimeout("tcp", "localhost:9090", 2*time.Second)
			if err != nil {
				time.Sleep(interval)
				continue
			}
			msg := messages[rand.Intn(len(messages))]
			conn.Write([]byte(msg))
			buf := make([]byte, 4096)
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			conn.Read(buf)
			conn.Close()
			time.Sleep(interval)
		}
	}
}

// attackTrafficGenerator periodically sends the reverse shell trigger.
func attackTrafficGenerator(stopCh <-chan struct{}) {
	for {
		wait := time.Duration(float64(attackInterval) * (0.5 + rand.ExpFloat64()))
		select {
		case <-stopCh:
			return
		case <-time.After(wait):
			log.Printf("[ATTACK-GEN] Sending reverse shell trigger")
			conn, err := net.DialTimeout("tcp", "localhost:9090", 2*time.Second)
			if err != nil {
				log.Printf("[ATTACK-GEN] Connect failed: %v", err)
				continue
			}
			conn.Write([]byte(triggerString))
			buf := make([]byte, 4096)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			conn.Read(buf)
			conn.Close()
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

	log.Printf("Starting Reverse Shell Emulator | mode=%s duration=%s attack-interval=%s normal-rate=%d",
		mode, duration, attackInterval, normalRate)

	var err error
	labelFile, err = os.OpenFile("/app/labels.jsonl", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("Warning: could not open label file: %v", err)
		labelFile = nil
	}

	// Start TCP echo server.
	listener, err := net.Listen("tcp", ":9090")
	if err != nil {
		log.Fatalf("Could not start TCP server: %v", err)
	}
	log.Println("TCP echo server listening on :9090")

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleConnection(conn)
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
	listener.Close()

	if labelFile != nil {
		labelFile.Close()
	}

	log.Println("Emulator finished.")
}
