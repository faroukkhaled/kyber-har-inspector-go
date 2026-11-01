// HAR Inspector reviews local browser exports without sending network requests.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
)

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type Entry struct {
	Request struct {
		URL     string   `json:"url"`
		Headers []Header `json:"headers"`
	} `json:"request"`
	Response struct {
		Status   int      `json:"status"`
		BodySize int64    `json:"bodySize"`
		Headers  []Header `json:"headers"`
	} `json:"response"`
	Time float64 `json:"time"`
}
type HAR struct {
	Log struct {
		Entries []Entry `json:"entries"`
	} `json:"log"`
}
type Finding struct {
	Entry    int    `json:"entry"`
	Origin   string `json:"origin"`
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
}
type Report struct {
	Entries     int       `json:"entries"`
	Origins     []string  `json:"origins"`
	Findings    []Finding `json:"findings"`
	InvalidURLs int       `json:"invalidUrls"`
	Note        string    `json:"note"`
}

func headers(values []Header) map[string]string {
	m := map[string]string{}
	for _, h := range values {
		k := strings.ToLower(h.Name)
		m[k] += " " + h.Value
	}
	return m
}
func analyze(h HAR) Report {
	r := Report{Entries: len(h.Log.Entries), Origins: []string{}, Findings: []Finding{}, Note: "Queries, paths, bodies, credentials and cookie values are omitted. Findings are review signals."}
	origins := map[string]bool{}
	for i, e := range h.Log.Entries {
		u, err := url.Parse(e.Request.URL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			r.InvalidURLs++
			continue
		}
		origin := u.Scheme + "://" + u.Host
		origins[origin] = true
		add := func(rule, severity string) { r.Findings = append(r.Findings, Finding{i + 1, origin, rule, severity}) }
		req, res := headers(e.Request.Headers), headers(e.Response.Headers)
		if u.Scheme == "http" {
			add("unencrypted-http", "medium")
		}
		sensitive := req["authorization"] != "" || req["cookie"] != ""
		if sensitive && e.Response.Status >= 200 && e.Response.Status < 300 && !strings.Contains(strings.ToLower(res["cache-control"]), "no-store") {
			add("authenticated-response-without-no-store", "review")
		}
		if e.Response.Status >= 500 {
			add("server-error", "review")
		}
		if e.Time > 3000 {
			add("slow-response-over-3s", "low")
		}
		if e.Response.BodySize > 5*1024*1024 {
			add("response-over-5mib", "low")
		}
	}
	for origin := range origins {
		r.Origins = append(r.Origins, origin)
	}
	sort.Strings(r.Origins)
	return r
}
func main() {
	input := flag.String("input", "", "Local HAR path")
	output := flag.String("html", "", "Optional HTML report path")
	flag.Parse()
	if *input == "" {
		fmt.Fprintln(os.Stderr, "Usage: go run . -input sample.har [-html report.html]")
		os.Exit(2)
	}
	file, err := os.Open(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot open input")
		os.Exit(2)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 20*1024*1024+1))
	if err != nil || len(raw) > 20*1024*1024 {
		fmt.Fprintln(os.Stderr, "Unreadable input or size exceeds 20 MiB")
		os.Exit(2)
	}
	var h HAR
	if json.Unmarshal(raw, &h) != nil || h.Log.Entries == nil {
		fmt.Fprintln(os.Stderr, "Invalid HAR: log.entries array required")
		os.Exit(2)
	}
	r := analyze(h)
	encoded, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(encoded))
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Cannot create report")
			os.Exit(2)
		}
		t := template.Must(template.New("report").Parse(reportTemplate))
		err = t.Execute(f, r)
		f.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Cannot write report")
			os.Exit(2)
		}
	}
	if r.InvalidURLs > 0 {
		os.Exit(2)
	}
	if len(r.Findings) > 0 {
		os.Exit(1)
	}
}

const reportTemplate = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>KYBER HAR Inspector</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:20px;background:#f3f7fa;color:#203147}td,th{padding:12px;text-align:left;border-bottom:1px solid #dde}table{width:100%;background:white;border-collapse:collapse}</style><h1>HAR Inspector</h1><p>{{.Note}}</p><p>Entries: {{.Entries}} · Invalid URLs: {{.InvalidURLs}}</p><table><tr><th>Entry</th><th>Origin</th><th>Signal</th><th>Severity</th></tr>{{range .Findings}}<tr><td>{{.Entry}}</td><td>{{.Origin}}</td><td>{{.Rule}}</td><td>{{.Severity}}</td></tr>{{end}}</table></html>`
