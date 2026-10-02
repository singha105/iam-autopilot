// Command gen rebuilds internal/catalog/data/actions.json from AWS's
// machine-readable Service Authorization Reference. Run it with `make catalog`.
// It is the only code in the repo that downloads the catalog; tests and the
// autopilot itself read the committed, embedded file.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const indexURL = "https://servicereference.us-east-1.amazonaws.com/"

// services are the prefixes the demo roles and the autopilot can touch.
var services = []string{"cloudwatch", "dynamodb", "ec2", "iam", "kms", "lambda", "logs", "s3", "sns", "sqs", "ssm", "sts"}

type indexEntry struct {
	Service string `json:"service"`
	URL     string `json:"url"`
}

// serviceDoc is the subset of a service JSON the catalog keeps.
type serviceDoc struct {
	Name    string `json:"Name"`
	Version string `json:"Version"`
	Actions []struct {
		Name      string `json:"Name"`
		Resources []struct {
			Name string `json:"Name"`
		} `json:"Resources"`
	} `json:"Actions"`
	Resources []struct {
		Name       string   `json:"Name"`
		ARNFormats []string `json:"ARNFormats"`
	} `json:"Resources"`
}

// The output shape matches internal/catalog's file types.
type outAction struct {
	Action        string   `json:"action"`
	ResourceTypes []string `json:"resourceTypes"`
}

type outResourceType struct {
	Name       string   `json:"name"`
	ARNFormats []string `json:"arnFormats"`
}

type outService struct {
	Version       string            `json:"version"`
	Actions       []outAction       `json:"actions"`
	ResourceTypes []outResourceType `json:"resourceTypes"`
}

type outFile struct {
	Source   string                `json:"source"`
	Services map[string]outService `json:"services"`
}

func main() {
	out := flag.String("out", "internal/catalog/data/actions.json", "file to write")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := run(ctx, *out); err != nil {
		fmt.Fprintln(os.Stderr, "catalog:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, outPath string) error {
	var index []indexEntry
	if err := getJSON(ctx, indexURL, &index); err != nil {
		return fmt.Errorf("index: %w", err)
	}
	urls := map[string]string{}
	for _, e := range index {
		urls[e.Service] = e.URL
	}

	file := outFile{Source: indexURL, Services: map[string]outService{}}
	total := 0
	for _, prefix := range services {
		url, ok := urls[prefix]
		if !ok {
			return fmt.Errorf("service %q is not in the index", prefix)
		}
		var doc serviceDoc
		if err := getJSON(ctx, url, &doc); err != nil {
			return fmt.Errorf("%s: %w", prefix, err)
		}
		svc := outService{Version: doc.Version, Actions: []outAction{}, ResourceTypes: []outResourceType{}}
		for _, a := range doc.Actions {
			types := []string{}
			for _, r := range a.Resources {
				types = append(types, r.Name)
			}
			sort.Strings(types)
			svc.Actions = append(svc.Actions, outAction{Action: a.Name, ResourceTypes: types})
		}
		sort.Slice(svc.Actions, func(i, j int) bool { return svc.Actions[i].Action < svc.Actions[j].Action })
		for _, r := range doc.Resources {
			formats := append([]string{}, r.ARNFormats...)
			sort.Strings(formats)
			svc.ResourceTypes = append(svc.ResourceTypes, outResourceType{Name: r.Name, ARNFormats: formats})
		}
		sort.Slice(svc.ResourceTypes, func(i, j int) bool { return svc.ResourceTypes[i].Name < svc.ResourceTypes[j].Name })
		file.Services[prefix] = svc
		total += len(svc.Actions)
		fmt.Printf("%-10s %4d actions, %3d resource types (version %s)\n", prefix, len(svc.Actions), len(svc.ResourceTypes), doc.Version)
	}

	b, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(outPath, append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s: %d services, %d actions, %d bytes\n", outPath, len(file.Services), total, len(b)+1)
	return nil
}

func getJSON(ctx context.Context, url string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}
