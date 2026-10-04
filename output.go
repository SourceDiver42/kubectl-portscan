package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// ---- nmap XML schema (only the parts we use) ----

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus     `xml:"status"`
	Addresses []nmapAddress  `xml:"address"`
	Hostnames []nmapHostname `xml:"hostnames>hostname"`
	Ports     nmapPorts      `xml:"ports"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
}

type nmapPorts struct {
	Extra []nmapExtraPorts `xml:"extraports"`
	Ports []nmapPort       `xml:"port"`
}

type nmapExtraPorts struct {
	State   string             `xml:"state,attr"`
	Count   int                `xml:"count,attr"`
	Reasons []nmapExtraReasons `xml:"extrareasons"`
}

type nmapExtraReasons struct {
	Reason string `xml:"reason,attr"`
	Count  int    `xml:"count,attr"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   int         `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

// ---- our result model (also what --output json emits) ----

type portResult struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	State    string `json:"state"`
	Reason   string `json:"reason,omitempty"`
	Service  string `json:"service,omitempty"`
}

type hostResult struct {
	Address  string       `json:"address"`
	Hostname string       `json:"hostname,omitempty"`
	State    string       `json:"state"`
	Ports    []portResult `json:"ports"`
	NotShown []string     `json:"not_shown,omitempty"`
}

func parseNmapXML(data []byte) ([]hostResult, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parsing nmap output: %w", err)
	}

	hosts := make([]hostResult, 0, len(run.Hosts))
	for _, h := range run.Hosts {
		hr := hostResult{State: h.Status.State, Ports: []portResult{}}
		for _, a := range h.Addresses {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				hr.Address = a.Addr
				break
			}
		}
		if len(h.Hostnames) > 0 {
			hr.Hostname = h.Hostnames[0].Name
		}

		for _, p := range h.Ports.Ports {
			svc := strings.TrimSpace(strings.Join(
				nonEmpty(p.Service.Name, p.Service.Product, p.Service.Version), " "))
			hr.Ports = append(hr.Ports, portResult{
				Protocol: p.Protocol,
				Port:     p.PortID,
				State:    p.State.State,
				Reason:   p.State.Reason,
				Service:  svc,
			})
		}

		for _, e := range h.Ports.Extra {
			var reasons []string
			for _, r := range e.Reasons {
				reasons = append(reasons, fmt.Sprintf("%d %s", r.Count, r.Reason))
			}
			s := fmt.Sprintf("%d %s", e.Count, e.State)
			if len(reasons) > 0 {
				s += " (" + strings.Join(reasons, ", ") + ")"
			}
			hr.NotShown = append(hr.NotShown, s)
		}
		hosts = append(hosts, hr)
	}
	return hosts, nil
}

func nonEmpty(ss ...string) []string {
	var out []string
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func between(s, begin, end string) string {
	i := strings.Index(s, begin)
	if i < 0 {
		return ""
	}
	i += len(begin)
	j := strings.Index(s[i:], end)
	if j < 0 {
		return strings.TrimSpace(s[i:])
	}
	return strings.TrimSpace(s[i : i+j])
}

// ---- table rendering ----

func renderTable(w io.Writer, hosts []hostResult, showAll bool) {
	for _, h := range hosts {
		title := h.Address
		if h.Hostname != "" {
			title += " (" + h.Hostname + ")"
		}
		fmt.Fprintf(w, "\n%s  [%s]\n", title, h.State)
		if h.State != "up" {
			continue
		}

		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  PORT\tSTATE\tREASON\tSERVICE")
		shown := 0
		for _, p := range h.Ports {
			if !showAll && p.State != "open" {
				continue
			}
			fmt.Fprintf(tw, "  %d/%s\t%s\t%s\t%s\n", p.Port, p.Protocol, p.State, p.Reason, p.Service)
			shown++
		}
		if shown == 0 {
			tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0) // drop the header
			fmt.Fprintln(w, "  (no open ports)")
		}
		tw.Flush()

		for _, ns := range h.NotShown {
			fmt.Fprintf(w, "  not shown: %s\n", ns)
		}
	}
	fmt.Fprintln(w)
}
