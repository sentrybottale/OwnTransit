package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/sentrybottale/owntransit/internal/buildinfo"
	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/enrollmentexchange"
	"github.com/sentrybottale/owntransit/internal/enrollmenttarget"
	"github.com/sentrybottale/owntransit/internal/relay"
	"github.com/sentrybottale/owntransit/internal/transport"
)

type relayCommands struct {
	version      func(io.Writer) error
	checkConfig  func(string) error
	checkRuntime func(string, string, int) error
	run          func(string, io.Writer) error
	runRuntime   func(string, string, int, io.Writer) error
}

type relayRuntimeSource struct {
	configPath     string
	runtimeRoot    string
	anchorViewRoot string
	readerGID      int
}

func main() {
	code := executeRelay(os.Args[1:], os.Stdout, os.Stderr, productionRelayCommands())
	if code != 0 {
		os.Exit(code)
	}
}

func productionRelayCommands() relayCommands {
	return relayCommands{
		version: func(output io.Writer) error {
			return buildinfo.Write(output, "relay", "")
		},
		checkConfig: func(configPath string) error {
			_, err := config.LoadRelay(configPath)
			return err
		},
		checkRuntime: checkRelayRuntime,
		run:          runRelay,
		runRuntime:   runRelayRuntime,
	}
}

func executeRelay(arguments []string, output, diagnostics io.Writer, commands relayCommands) int {
	command := "run"
	commandArguments := arguments
	if len(arguments) > 0 {
		switch arguments[0] {
		case "version", "check-config", "run":
			command = arguments[0]
			commandArguments = arguments[1:]
		}
	}

	switch command {
	case "version":
		if len(commandArguments) != 0 {
			fmt.Fprintln(diagnostics, "owntransit-relay version: unexpected argument")
			return 2
		}
		if err := commands.version(output); err != nil {
			fmt.Fprintf(diagnostics, "owntransit-relay version: %v\n", err)
			return 1
		}
		return 0
	case "check-config":
		source, code, ok := parseRelayConfigArguments(command, commandArguments, diagnostics)
		if !ok {
			return code
		}
		if source.runtimeRoot != "" {
			if commands.checkRuntime == nil {
				fmt.Fprintln(diagnostics, "owntransit-relay check-config: runtime-view validation is unavailable")
				return 1
			}
			if err := commands.checkRuntime(source.runtimeRoot, source.anchorViewRoot, source.readerGID); err != nil {
				fmt.Fprintf(diagnostics, "owntransit-relay check-config: %v\n", err)
				return 1
			}
			fmt.Fprintln(output, "owntransit-relay: configuration valid")
			return 0
		}
		if commands.checkConfig == nil {
			fmt.Fprintln(diagnostics, "owntransit-relay check-config: direct-config validation is unavailable")
			return 1
		}
		if err := commands.checkConfig(source.configPath); err != nil {
			fmt.Fprintf(diagnostics, "owntransit-relay check-config: %v\n", err)
			return 1
		}
		fmt.Fprintln(output, "owntransit-relay: configuration valid")
		return 0
	case "run":
		source, code, ok := parseRelayConfigArguments(command, commandArguments, diagnostics)
		if !ok {
			return code
		}
		if source.runtimeRoot != "" {
			if commands.runRuntime == nil {
				fmt.Fprintln(diagnostics, "owntransit-relay run: runtime-view carrier is unavailable")
				return 1
			}
			if err := commands.runRuntime(source.runtimeRoot, source.anchorViewRoot, source.readerGID, diagnostics); err != nil {
				fmt.Fprintf(diagnostics, "owntransit-relay run: %v\n", err)
				return 1
			}
			return 0
		}
		if commands.run == nil {
			fmt.Fprintln(diagnostics, "owntransit-relay run: direct-config carrier is unavailable")
			return 1
		}
		if err := commands.run(source.configPath, diagnostics); err != nil {
			fmt.Fprintf(diagnostics, "owntransit-relay run: %v\n", err)
			return 1
		}
		return 0
	default:
		panic("unreachable relay command")
	}
}

func parseRelayConfigArguments(command string, arguments []string, diagnostics io.Writer) (relayRuntimeSource, int, bool) {
	flags := flag.NewFlagSet("owntransit-relay "+command, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	configPath := flags.String("config", "", "development-only direct relay configuration file")
	runtimeRoot := flags.String("runtime-root", "", "root-owned read-only runtime view root")
	anchorViewRoot := flags.String("anchor-view-root", "", "root-owned read-only anchor view root")
	readerGID := flags.Int("reader-gid", 0, "exact dedicated runtime reader primary GID")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return relayRuntimeSource{}, 0, false
		}
		return relayRuntimeSource{}, 2, false
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(diagnostics, "owntransit-relay %s: unexpected positional argument\n", command)
		return relayRuntimeSource{}, 2, false
	}
	configExplicit := false
	flags.Visit(func(value *flag.Flag) {
		if value.Name == "config" {
			configExplicit = true
		}
	})
	viewSelected := *runtimeRoot != "" || *anchorViewRoot != "" || *readerGID != 0
	if viewSelected && configExplicit {
		fmt.Fprintf(diagnostics, "owntransit-relay %s: -config and runtime-view arguments are mutually exclusive\n", command)
		return relayRuntimeSource{}, 2, false
	}
	if viewSelected && (*runtimeRoot == "" || *anchorViewRoot == "" || *readerGID <= 0) {
		fmt.Fprintf(diagnostics, "owntransit-relay %s: -runtime-root, -anchor-view-root and a positive -reader-gid are required together\n", command)
		return relayRuntimeSource{}, 2, false
	}
	if !viewSelected && !configExplicit {
		fmt.Fprintf(diagnostics, "owntransit-relay %s: select the authenticated runtime views explicitly\n", command)
		return relayRuntimeSource{}, 2, false
	}
	return relayRuntimeSource{
		configPath: *configPath, runtimeRoot: *runtimeRoot,
		anchorViewRoot: *anchorViewRoot, readerGID: *readerGID,
	}, 0, true
}

func runRelay(configPath string, diagnostics io.Writer) error {
	value, err := config.LoadRelay(configPath)
	if err != nil {
		return err
	}
	service, err := relay.New(value)
	if err != nil {
		return fmt.Errorf("initialize service: %w", err)
	}
	return serveRelay(value, service, diagnostics, nil)
}

func checkRelayRuntime(runtimeRoot, anchorViewRoot string, readerGID int) error {
	handle, _, _, err := prepareRelayRuntime(runtimeRoot, anchorViewRoot, readerGID)
	if err != nil {
		return err
	}
	defer handle.Close()
	return handle.FinalCheck()
}

func runRelayRuntime(runtimeRoot, anchorViewRoot string, readerGID int, diagnostics io.Writer) error {
	handle, value, service, err := prepareRelayRuntime(runtimeRoot, anchorViewRoot, readerGID)
	if err != nil {
		return err
	}
	defer handle.Close()
	return serveRelay(value, service, diagnostics, handle.FinalCheck)
}

func prepareRelayRuntime(runtimeRoot, anchorViewRoot string, readerGID int) (*enrollmenttarget.RuntimeGenerationHandle, config.Relay, *relay.Service, error) {
	handle, err := enrollmenttarget.OpenRuntimeGeneration(runtimeRoot, anchorViewRoot, readerGID, enrollment.RoleRelay)
	if err != nil {
		return nil, config.Relay{}, nil, err
	}
	fail := func(value error) (*enrollmenttarget.RuntimeGenerationHandle, config.Relay, *relay.Service, error) {
		_ = handle.Close()
		return nil, config.Relay{}, nil, value
	}
	value, err := handle.RelayConfig()
	if err != nil {
		return fail(err)
	}
	service, err := relay.NewFromMaterial(value, handle.ReadMaterial)
	if err != nil {
		return fail(fmt.Errorf("initialize service: %w", err))
	}
	return handle, value, service, nil
}

func serveRelay(value config.Relay, service *relay.Service, diagnostics io.Writer, finalCheck func() error) error {

	root, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	carrierSlots := make(chan struct{}, value.Limits.CarrierGlobal())
	var exchange *enrollmentexchange.ExchangeHandler
	if value.EnrollmentAllocationCapabilitySHA256 != "" {
		var err error
		exchange, err = enrollmentexchange.NewExchangeHandler(
			enrollmentexchange.NewMailboxStore(),
			value.EnrollmentAllocationCapabilitySHA256,
		)
		if err != nil {
			return fmt.Errorf("initialize enrollment exchange: %w", err)
		}
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if exchange != nil && exactRelayRequest(request, value.Path+"/enrollment") {
			exchange.Serve(root, w, request)
			return
		}
		if !exactCarrierRequest(request, value.Path) {
			http.NotFound(w, request)
			return
		}
		// nginx terminates public WebPKI and forwards only this loopback-bound
		// location. OwnTransit's own outer TLS starts on the returned stream.
		// The root context intentionally outlives this HTTP handler: a DATA_JOIN
		// transfers stream ownership to the matching client handler.
		carrier, err := acceptLeasedCarrier(root, w, request, carrierSlots)
		if err != nil {
			return
		}
		service.Handle(root, carrier)
	})

	server := &http.Server{
		Addr:              value.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
		BaseContext: func(net.Listener) context.Context {
			return root
		},
	}
	errorChannel := make(chan error, 1)
	// ListenAndServe is the first network action for a state-backed relay.
	if finalCheck != nil {
		if err := finalCheck(); err != nil {
			return err
		}
	}
	go func() {
		errorChannel <- server.ListenAndServe()
	}()
	fmt.Fprintln(diagnostics, "owntransit-relay: ready")

	select {
	case <-root.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		return nil
	case err := <-errorChannel:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve: %w", err)
	}
}

func exactCarrierRequest(request *http.Request, expectedPath string) bool {
	return exactRelayRequest(request, expectedPath)
}

func exactRelayRequest(request *http.Request, expectedPath string) bool {
	return request != nil && request.URL != nil && request.URL.Path == expectedPath &&
		request.URL.RawPath == "" && request.URL.RawQuery == "" && !request.URL.ForceQuery
}

func acceptLeasedCarrier(
	ctx context.Context,
	w http.ResponseWriter,
	request *http.Request,
	slots chan struct{},
) (net.Conn, error) {
	select {
	case slots <- struct{}{}:
	default:
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return nil, errors.New("relay carrier capacity exhausted")
	}
	releaseSlot := func() { <-slots }
	carrier, err := transport.AcceptWebSocket(ctx, w, request, transport.WebSocketOptions{AllowCleartext: true})
	if err != nil {
		releaseSlot()
		return nil, err
	}
	// A DATA_JOIN can outlive its HTTP handler after ownership moves to the
	// paired client goroutine. Tie the slot to connection close so the cap
	// covers every upgraded socket, not just upgrade and admission.
	return &leasedCarrier{Conn: carrier, release: releaseSlot}, nil
}

// leasedCarrier releases one pre-upgrade admission slot only after the
// upgraded connection is actually closed. Abort preserves the WebSocket
// transport's immediate-close path for unauthenticated rejection.
type leasedCarrier struct {
	net.Conn
	release     func()
	releaseOnce sync.Once
}

func (carrier *leasedCarrier) Close() error {
	err := carrier.Conn.Close()
	carrier.releaseOnce.Do(carrier.release)
	return err
}

func (carrier *leasedCarrier) Abort() error {
	err := transport.Abort(carrier.Conn)
	carrier.releaseOnce.Do(carrier.release)
	return err
}
