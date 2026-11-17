package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sealpath/internal/repository"
	"sealpath/internal/transport"
	"strings"
	"time"
)

func main() {
	workflow := flag.String("workflow", "verify", "bounded service walkthrough")
	emit := flag.String("emit", "", "write fresh public example material as JSON")
	algorithm := flag.String("algorithm", "ed25519", "artifact signing algorithm")
	flag.Parse()
	samples, err := generate(*algorithm)
	if err != nil {
		fatal(err)
	}
	joint, err := generateJoint()
	if err != nil {
		fatal(err)
	}
	if *emit != "" {
		data, e := json.MarshalIndent(samples, "", "  ")
		if e != nil {
			fatal(e)
		}
		if e = os.WriteFile(*emit, append(data, '\n'), 0644); e != nil {
			fatal(e)
		}
		return
	}
	directory, err := os.MkdirTemp("", "sealpath-walkthrough-")
	if err != nil {
		fatal(err)
	}
	defer os.RemoveAll(directory)
	statePath := filepath.Join(directory, "service.json")
	store, err := repository.Open(statePath)
	if err != nil {
		fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatal(err)
	}
	server := &http.Server{Handler: transport.New(store, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler(), ReadHeaderTimeout: time.Second, WriteTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	defer server.Shutdown(context.Background())
	client := &client{base: "http://" + listener.Addr().String(), http: &http.Client{Timeout: 5 * time.Second}}
	var result map[string]any
	if strings.HasPrefix(*workflow, "joint") {
		result, err = walkJoint(client, joint, *workflow)
	} else {
		result, err = walk(client, samples, *workflow, statePath)
	}
	if err != nil {
		fatal(err)
	}
	if err = json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fatal(err)
	}
}
func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
