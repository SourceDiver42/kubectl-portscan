package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// NOTE: pin this by digest (or mirror it) once you've picked an image you trust.
const defaultImage = "instrumentisto/nmap:latest"

const (
	markXMLBegin = "__PORTSCAN_XML_BEGIN__"
	markXMLEnd   = "__PORTSCAN_XML_END__"
	markErrBegin = "__PORTSCAN_STDERR_BEGIN__"
	markErrEnd   = "__PORTSCAN_STDERR_END__"
)

// Runs nmap with the argv passed after the script name ("$@" -> no shell
// quoting/injection issues), writes XML to a file, then dumps XML and stderr
// between markers so stdout/stderr interleaving can't corrupt the XML.
const runScript = `nmap "$@" -oX /tmp/out.xml >/tmp/stdout.txt 2>/tmp/stderr.txt
rc=$?
echo ` + markXMLBegin + `
cat /tmp/out.xml 2>/dev/null
echo ` + markXMLEnd + `
echo ` + markErrBegin + `
cat /tmp/stderr.txt 2>/dev/null
echo ` + markErrEnd + `
exit $rc`

func ptr[T any](v T) *T { return &v }

func (o *options) validate() error {
	switch o.scanType {
	case "syn", "connect", "udp":
	default:
		return fmt.Errorf("--scan-type must be syn, connect or udp (got %q)", o.scanType)
	}
	if o.timing < 0 || o.timing > 5 {
		return fmt.Errorf("--timing must be between 0 and 5")
	}
	switch o.output {
	case "table", "json", "xml":
	default:
		return fmt.Errorf("--output must be table, json or xml (got %q)", o.output)
	}
	if o.timeout <= 0 {
		return fmt.Errorf("--timeout must be positive")
	}
	return nil
}

func (o *options) nmapArgs(targets []string) []string {
	var a []string
	switch o.scanType {
	case "syn":
		a = append(a, "-sS")
	case "connect":
		a = append(a, "-sT")
	case "udp":
		a = append(a, "-sU")
	}
	if !o.ping {
		a = append(a, "-Pn")
	}
	a = append(a, "-n", "--reason", fmt.Sprintf("-T%d", o.timing))
	switch o.ports {
	case "":
		a = append(a, "--top-ports", "1000")
	case "-", "all":
		a = append(a, "-p-")
	default:
		a = append(a, "-p", o.ports)
	}
	if o.serviceDetect {
		a = append(a, "-sV")
	}
	a = append(a, o.extraArgs...)
	a = append(a, targets...)
	return a
}

// namespaceObj builds the throwaway namespace. The pod-security labels are
// what allow NET_RAW/NET_ADMIN and hostNetwork on clusters (like Talos) that
// default to baseline/restricted enforcement.
func (o *options) namespaceObj() *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "portscan-",
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":               managedBy,
				"pod-security.kubernetes.io/enforce":         "privileged",
				"pod-security.kubernetes.io/enforce-version": "latest",
				"pod-security.kubernetes.io/audit":           "privileged",
				"pod-security.kubernetes.io/warn":            "privileged",
			},
		},
	}
}

func (o *options) scannerPod(args []string) *corev1.Pod {
	sc := &corev1.SecurityContext{RunAsUser: ptr(int64(0))}
	var env []corev1.EnvVar
	if o.scanType != "connect" {
		sc.Capabilities = &corev1.Capabilities{
			Drop: []corev1.Capability{"ALL"},
			Add:  []corev1.Capability{"NET_RAW", "NET_ADMIN"},
		}
		// Tell nmap to assume raw-socket privileges instead of probing for root.
		env = append(env, corev1.EnvVar{Name: "NMAP_PRIVILEGED", Value: "1"})
	}

	spec := corev1.PodSpec{
		RestartPolicy:                corev1.RestartPolicyNever,
		NodeName:                     o.fromNode,
		HostNetwork:                  o.hostNetwork,
		AutomountServiceAccountToken: ptr(false),
		ActiveDeadlineSeconds:        ptr(int64(o.timeout.Seconds())),
		Tolerations:                  []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
		Containers: []corev1.Container{{
			Name:            "nmap",
			Image:           o.image,
			ImagePullPolicy: corev1.PullIfNotPresent,
			Command:         []string{"sh", "-c", runScript, "portscan"},
			Args:            args,
			Env:             env,
			SecurityContext: sc,
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("50m"),
					corev1.ResourceMemory: resource.MustParse("64Mi"),
				},
			},
		}},
	}
	if o.hostNetwork {
		spec.DNSPolicy = corev1.DNSClusterFirstWithHostNet
	}

	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "scanner",
			Labels: map[string]string{"app.kubernetes.io/managed-by": managedBy},
		},
		Spec: spec,
	}
}

func (o *options) run(ctx context.Context) error {
	if err := o.validate(); err != nil {
		return err
	}

	cfg, err := o.configFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("loading kubeconfig: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}

	if o.fromNode != "" {
		if _, err := cs.CoreV1().Nodes().Get(ctx, o.fromNode, metav1.GetOptions{}); err != nil {
			return fmt.Errorf("--from-node %q: %w", o.fromNode, err)
		}
	}

	targets, err := resolveTargets(ctx, cs, o.targets, o.allowExternal, o.force)
	if err != nil {
		return err
	}
	args := o.nmapArgs(targets)

	ns, err := cs.CoreV1().Namespaces().Create(ctx, o.namespaceObj(), metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("creating scan namespace: %w", err)
	}
	fmt.Fprintf(o.errOut, "created namespace %s (pod-security: privileged)\n", ns.Name)

	if o.keep {
		defer fmt.Fprintf(o.errOut, "kept namespace %s; remove with: kubectl delete ns %s\n", ns.Name, ns.Name)
	} else {
		defer func() {
			// Fresh context: ctx may already be cancelled by Ctrl-C.
			cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := cs.CoreV1().Namespaces().Delete(cctx, ns.Name, metav1.DeleteOptions{}); err != nil {
				fmt.Fprintf(o.errOut, "warning: could not delete namespace %s: %v (try: kubectl %s cleanup --older-than 0)\n", ns.Name, err, o.name)
			}
		}()
	}

	pod, err := cs.CoreV1().Pods(ns.Name).Create(ctx, o.scannerPod(args), metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("creating scanner pod: %w", err)
	}

	vantage := "the pod network"
	if o.hostNetwork {
		vantage = "the host network"
	}
	if o.fromNode != "" {
		vantage += " of node " + o.fromNode
	}
	fmt.Fprintf(o.errOut, "scanning %d target spec(s) from %s...\n", len(targets), vantage)

	done, err := waitForPod(ctx, cs, ns.Name, pod.Name, o.timeout+2*time.Minute)
	if err != nil {
		return err
	}

	logs, err := podLogs(ctx, cs, ns.Name, pod.Name)
	if err != nil {
		return fmt.Errorf("reading scanner logs: %w", err)
	}
	xmlOut := between(logs, markXMLBegin, markXMLEnd)
	stderrOut := between(logs, markErrBegin, markErrEnd)
	if xmlOut == "" {
		return fmt.Errorf("scan produced no results (pod phase %s, reason %q)\n%s",
			done.Status.Phase, done.Status.Reason, stderrOut)
	}
	if strings.TrimSpace(stderrOut) != "" {
		fmt.Fprintf(o.errOut, "nmap stderr:\n%s\n", stderrOut)
	}

	hosts, err := parseNmapXML([]byte(xmlOut))
	if err != nil {
		return err
	}

	switch o.output {
	case "json":
		enc := json.NewEncoder(o.out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(hosts); err != nil {
			return err
		}
	case "xml":
		fmt.Fprintln(o.out, xmlOut)
	default:
		renderTable(o.out, hosts, o.showAll)
	}
	return nil
}

func waitForPod(ctx context.Context, cs kubernetes.Interface, ns, name string, timeout time.Duration) (*corev1.Pod, error) {
	deadline := time.Now().Add(timeout)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		pod, err := cs.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		switch pod.Status.Phase {
		case corev1.PodSucceeded, corev1.PodFailed:
			return pod, nil
		}
		for _, st := range pod.Status.ContainerStatuses {
			if w := st.State.Waiting; w != nil {
				switch w.Reason {
				case "ImagePullBackOff", "InvalidImageName", "CreateContainerConfigError":
					return pod, fmt.Errorf("scanner container %s: %s: %s", st.Name, w.Reason, w.Message)
				}
			}
		}
		if time.Now().After(deadline) {
			return pod, fmt.Errorf("timed out waiting for scanner pod (phase %s)", pod.Status.Phase)
		}
		select {
		case <-ctx.Done():
			return pod, ctx.Err()
		case <-t.C:
		}
	}
}

func podLogs(ctx context.Context, cs kubernetes.Interface, ns, name string) (string, error) {
	rc, err := cs.CoreV1().Pods(ns).GetLogs(name, &corev1.PodLogOptions{Container: "nmap"}).Stream(ctx)
	if err != nil {
		return "", err
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	return string(b), err
}
