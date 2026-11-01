// Command zdas runs the Ziti Device Authentication Service as a standalone binary.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/smilindave26/zdas/pkg/zdas"
)

var version = "dev"

// shutdownTimeout bounds how long a signal waits for in-flight requests.
const shutdownTimeout = 10 * time.Second

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	configPath := flag.String("config", "", "path to config file (YAML)")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	cfg, err := zdas.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	if cfg.RateLimit.AuthorizePerSecond <= 0 {
		// Every /authorize request creates server state before anyone
		// signs in. Embedders usually limit requests in front of ZDAS;
		// the binary usually faces clients directly.
		logger.Warn("rate limiting on /authorize is off; set rate_limit.authorize_per_second " +
			"unless something in front of zdas limits requests")
	}

	srv, err := zdas.NewServer(*cfg, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "server setup error: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("shutdown error", "error", err)
		}
	}()

	if err := srv.Start(ctx); err != nil {
		logger.Error("server exited", "error", err)
		os.Exit(1)
	}
	// Start returns nil only once a signal has started the shutdown; wait
	// for in-flight requests to drain.
	<-shutdownDone
}
