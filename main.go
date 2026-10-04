package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

const managedBy = "kubectl-portscan"

type options struct {
	configFlags *genericclioptions.ConfigFlags
	out         io.Writer
	errOut      io.Writer

	// name is the invoked plugin name without the "kubectl-" prefix
	// ("portscan" or "nmap"); used only for help text and hints.
	name string

	targets []string

	ports         string
	scanType      string
	timing        int
	ping          bool
	serviceDetect bool
	extraArgs     []string

	fromNode    string
	hostNetwork bool
	image       string
	timeout     time.Duration
	keep        bool

	output  string
	showAll bool

	allowExternal bool
	force         bool
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := newRootCmd().ExecuteContext(ctx)
	stop()

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	// The same binary is installed as kubectl-portscan and kubectl-nmap.
	// Derive the display name from how we were invoked.
	bin := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
	short := strings.TrimPrefix(bin, "kubectl-")
	if short == bin || short == "" { // e.g. `go run .`
		bin, short = "kubectl-portscan", "portscan"
	}

	o := &options{
		name:        short,
		configFlags: genericclioptions.NewConfigFlags(true),
		out:         os.Stdout,
		errOut:      os.Stderr,
	}

	cmd := &cobra.Command{
		Use:   bin + " [flags] TARGET...",
		Short: "Run nmap from inside the cluster (works on shell-less nodes like Talos)",
		Long: `Runs nmap in an ephemeral pod, optionally pinned to a node and/or on the
host network, and prints the open ports it finds. Each run creates a throwaway
namespace labelled pod-security.kubernetes.io/enforce=privileged and deletes it
afterwards.

TARGET is one or more IPs or CIDRs (private/cluster ranges only by default;
use --allow-external for anything else):
  10.0.0.5        a single host
  10.0.0.0/24     a range (CIDRs larger than /16 need --force)

Note: --namespace/-n is accepted (kubectl convention) but ignored; scans always
run in their own ephemeral namespace.`,
		Example: strings.ReplaceAll(`  # Open ports on a host, as seen from the pod network (no extra caps needed)
  kubectl portscan 10.0.0.5 --scan-type connect

  # All TCP ports on a host, from a specific node's own network namespace
  kubectl portscan 10.0.0.5 --from-node worker-2 --host-network -p-

  # Leftover namespaces after a crash or --keep
  kubectl portscan cleanup --older-than 0`, "kubectl portscan", "kubectl "+short),
		Args:          cobra.MinimumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.targets = args
			return o.run(cmd.Context())
		},
	}

	// kubeconfig flags (--context, --kubeconfig, ...) are persistent so the
	// cleanup subcommand inherits them.
	o.configFlags.AddFlags(cmd.PersistentFlags())

	f := cmd.Flags()
	f.StringVarP(&o.ports, "ports", "p", "", `ports to scan (nmap syntax, e.g. "22,80,443", "T:1-1024,U:53"); "-" or "all" = every port; default = top 1000`)
	f.StringVar(&o.scanType, "scan-type", "syn", "syn | connect | udp (connect needs no extra capabilities)")
	f.IntVar(&o.timing, "timing", 4, "nmap timing template 0-5 (-T)")
	f.BoolVar(&o.ping, "ping", false, "do host discovery first (default skips it: -Pn, since firewalls often drop probes)")
	f.BoolVar(&o.serviceDetect, "service-detect", false, "probe service/version on open ports (-sV)")
	f.StringArrayVar(&o.extraArgs, "nmap-arg", nil, "extra argument passed to nmap verbatim (repeatable)")

	f.StringVar(&o.fromNode, "from-node", "", "pin the scanner pod to this node")
	f.BoolVar(&o.hostNetwork, "host-network", false, "run scanner in the node's network namespace instead of the pod network")
	f.StringVar(&o.image, "image", defaultImage, "scanner image; must contain nmap and /bin/sh (pin by digest for reproducibility)")
	f.DurationVar(&o.timeout, "timeout", 10*time.Minute, "maximum scan duration")
	f.BoolVar(&o.keep, "keep", false, "do not delete the scan namespace afterwards (debugging)")

	f.StringVarP(&o.output, "output", "o", "table", "table | json | xml")
	f.BoolVar(&o.showAll, "all", false, "table output: also list closed/filtered ports nmap enumerated")

	f.BoolVar(&o.allowExternal, "allow-external", false, "allow non-private IPs as targets")
	f.BoolVar(&o.force, "force", false, "allow CIDRs larger than /16")

	cmd.AddCommand(newCleanupCmd(o.configFlags))
	return cmd
}

func newCleanupCmd(cf *genericclioptions.ConfigFlags) *cobra.Command {
	var olderThan time.Duration
	cmd := &cobra.Command{
		Use:           "cleanup",
		Short:         "Delete leftover scan namespaces (e.g. after a crash or --keep)",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := cf.ToRESTConfig()
			if err != nil {
				return fmt.Errorf("loading kubeconfig: %w", err)
			}
			cs, err := kubernetes.NewForConfig(cfg)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			list, err := cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{
				LabelSelector: "app.kubernetes.io/managed-by=" + managedBy,
			})
			if err != nil {
				return err
			}
			deleted := 0
			for _, ns := range list.Items {
				if time.Since(ns.CreationTimestamp.Time) < olderThan {
					continue
				}
				if err := cs.CoreV1().Namespaces().Delete(ctx, ns.Name, metav1.DeleteOptions{}); err != nil {
					fmt.Fprintf(os.Stderr, "failed to delete %s: %v\n", ns.Name, err)
					continue
				}
				fmt.Printf("deleted namespace %s\n", ns.Name)
				deleted++
			}
			if deleted == 0 {
				fmt.Println("nothing to clean up")
			}
			return nil
		},
	}
	cmd.Flags().DurationVar(&olderThan, "older-than", 15*time.Minute, "only delete namespaces at least this old (protects concurrent scans)")
	return cmd
}
