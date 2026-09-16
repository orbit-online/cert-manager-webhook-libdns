package main

//go:generate go run ./libdnsregistry/generate/generate.go code reports/libdns-provider-compat/providers.json libdnsregistry/providers.go
import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cert-manager-webhook-libdns/libdnsregistry"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/libdns/libdns"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

func main() {
	// Handle --version before webhook server takes over flag parsing
	if slices.Contains(os.Args, "--version") {
		fmt.Println(Version)
		os.Exit(0)
	}

	// Handle --list-providers before webhook server takes over flag parsing
	if slices.Contains(os.Args, "--list-providers") {
		providers := libdnsregistry.List()
		fmt.Printf("Compiled-in DNS providers (%d):\n", len(providers))
		for _, p := range providers {
			fmt.Printf("  - %s\n", p)
		}
		os.Exit(0)
	}

	groupName := os.Getenv("GROUP_NAME")
	if groupName == "" {
		klog.Fatal("GROUP_NAME environment variable must be specified")
	}

	cmd.RunWebhookServer(groupName, &libdnsSolver{})
}

// libdnsSolver implements the webhook.Solver interface using libdns providers
type libdnsSolver struct {
	client kubernetes.Interface

	// Present/CleanUp do a non-atomic get-modify-set against the DNS provider API.
	// Wildcard + apex certs (e.g. *.example.com + example.com) produce two Challenges
	// that share the same TXT record name (_acme-challenge.example.com), and
	// cert-manager fires their Present()/CleanUp() concurrently — without this lock,
	// two overlapping get-modify-set cycles can clobber each other's TXT value.
	mu sync.Mutex
}

// LibdnsConfig is the configuration for the libdns solver
type LibdnsConfig struct {
	// Provider is the name of the DNS provider (e.g., "cloudflare", "route53")
	Provider string `json:"provider"`

	// SecretRef references a Kubernetes Secret containing provider credentials
	SecretRef SecretReference `json:"secretRef"`

	// Zone optionally overrides the zone determined by cert-manager
	Zone string `json:"zone,omitempty"`

	// TTL is the DNS record TTL in seconds (default: 300, deSEC requires minimum 3600)
	TTL int `json:"ttl,omitempty"`
}

// SecretReference identifies a Kubernetes Secret
type SecretReference struct {
	// Name is the name of the Secret
	Name string `json:"name"`

	// Namespace is the namespace of the Secret (optional, defaults to challenge namespace)
	Namespace string `json:"namespace,omitempty"`
}

// Name returns the solver name used in Issuer configurations
func (s *libdnsSolver) Name() string {
	return "libdns"
}

// Initialize is called when the webhook first starts
func (s *libdnsSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	client, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	s.client = client

	klog.Info("libdns solver initialized")
	klog.Infof("Available providers: %v", libdnsregistry.List())
	return nil
}

// Present creates the DNS TXT record for the ACME challenge
// It handles multiple TXT values for the same name (needed for wildcard + base domain certs)
func (s *libdnsSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("Present called: fqdn=%s zone=%s key=%s", ch.ResolvedFQDN, ch.ResolvedZone, ch.Key)

	s.mu.Lock()
	defer s.mu.Unlock()

	provider, zone, ttl, err := s.getProvider(ch)
	if err != nil {
		return fmt.Errorf("failed to get provider: %w", err)
	}

	recordName := extractRecordName(ch.ResolvedFQDN, zone)
	klog.V(2).Infof("Creating TXT record: name=%s zone=%s ttl=%s", recordName, zone, ttl)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Get existing records to merge with new value
	existingRecords, err := provider.GetRecords(ctx, zone)
	if err != nil {
		klog.Warningf("Failed to get existing records (falling back to append): %v", err)
		records := []libdns.Record{
			libdns.TXT{
				Name: recordName,
				TTL:  ttl,
				Text: ch.Key,
			},
		}
		appendedRecords, appendErr := provider.AppendRecords(ctx, zone, records)
		if appendErr != nil {
			return fmt.Errorf("failed to append TXT record after get failure: %w", appendErr)
		}
		klog.Infof("Successfully appended %d TXT record(s) for %s in zone %s", len(appendedRecords), recordName, zone)
		return nil
	}

	// Collect existing TXT values for this record name
	var existingValues []string
	for _, rec := range existingRecords {
		rr := rec.RR()
		if rr.Type == "TXT" && rr.Name == recordName {
			existingValues = append(existingValues, rr.Data)
		}
	}

	// Check if our value already exists
	for _, val := range existingValues {
		if val == ch.Key {
			klog.Infof("TXT record with value already exists for %s in zone %s", recordName, zone)
			return nil
		}
	}

	// Add our new value
	allValues := append(existingValues, ch.Key)
	klog.V(2).Infof("Setting TXT records for %s: %d existing + 1 new = %d total", recordName, len(existingValues), len(allValues))

	// Build records to set using libdns.TXT
	var records []libdns.Record
	for _, val := range allValues {
		records = append(records, libdns.TXT{
			Name: recordName,
			TTL:  ttl,
			Text: val,
		})
	}

	// Use SetRecords to set all TXT values at once
	set, err := provider.SetRecords(ctx, zone, records)
	if err != nil {
		return fmt.Errorf("failed to set TXT records: %w", err)
	}

	klog.Infof("Successfully set %d TXT record(s) for %s in zone %s", len(set), recordName, zone)
	return nil
}

// CleanUp removes the DNS TXT record after validation
// It handles multiple TXT values for the same name by only removing the specific value
func (s *libdnsSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("CleanUp called: fqdn=%s zone=%s key=%s", ch.ResolvedFQDN, ch.ResolvedZone, ch.Key)

	s.mu.Lock()
	defer s.mu.Unlock()

	provider, zone, ttl, err := s.getProvider(ch)
	if err != nil {
		return fmt.Errorf("failed to get provider: %w", err)
	}

	recordName := extractRecordName(ch.ResolvedFQDN, zone)
	klog.V(2).Infof("Deleting TXT record: name=%s zone=%s key=%s", recordName, zone, ch.Key)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Get existing records to remove only the specific value
	existingRecords, err := provider.GetRecords(ctx, zone)
	if err != nil {
		klog.Warningf("Failed to get existing records (will try delete): %v", err)
		// Fall back to direct delete
		records := []libdns.Record{
			libdns.TXT{
				Name: recordName,
				Text: ch.Key,
			},
		}
		deleted, err := provider.DeleteRecords(ctx, zone, records)
		if err != nil {
			return fmt.Errorf("failed to delete TXT record: %w", err)
		}
		klog.Infof("Successfully deleted %d TXT record(s) for %s in zone %s", len(deleted), recordName, zone)
		return nil
	}

	// Collect TXT values for this record name, excluding the one we want to remove
	var remainingRecords []libdns.Record
	found := false
	for _, rec := range existingRecords {
		rr := rec.RR()
		if rr.Type == "TXT" && rr.Name == recordName {
			if rr.Data == ch.Key {
				found = true
				continue // Skip this one
			}
			remainingRecords = append(remainingRecords, libdns.TXT{
				Name: recordName,
				TTL:  ttl,
				Text: rr.Data,
			})
		}
	}

	if !found {
		klog.Infof("TXT record with value not found for %s in zone %s (may already be deleted)", recordName, zone)
		return nil
	}

	if len(remainingRecords) == 0 {
		// No remaining records, delete entirely
		records := []libdns.Record{
			libdns.TXT{
				Name: recordName,
				Text: ch.Key,
			},
		}
		deleted, err := provider.DeleteRecords(ctx, zone, records)
		if err != nil {
			return fmt.Errorf("failed to delete TXT record: %w", err)
		}
		klog.Infof("Successfully deleted %d TXT record(s) for %s in zone %s", len(deleted), recordName, zone)
	} else {
		// Set remaining records (this removes the one we want to delete)
		klog.V(2).Infof("Setting %d remaining TXT records for %s", len(remainingRecords), recordName)
		set, err := provider.SetRecords(ctx, zone, remainingRecords)
		if err != nil {
			return fmt.Errorf("failed to set remaining TXT records: %w", err)
		}
		klog.Infof("Successfully updated TXT records for %s in zone %s (%d remaining)", recordName, zone, len(set))
	}

	return nil
}

// Default TTL for DNS records (in seconds)
const defaultTTL = 300

// deSEC enforces a minimum TTL of 3600 seconds.
const desecMinTTL = 3600

// getProvider creates the DNS provider based on configuration
func (s *libdnsSolver) getProvider(ch *v1alpha1.ChallengeRequest) (libdnsregistry.Provider, string, time.Duration, error) {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, "", 0, fmt.Errorf("failed to load config: %w", err)
	}

	klog.V(2).Infof("Loading credentials for provider %s from secret %s/%s",
		cfg.Provider, cfg.SecretRef.Namespace, cfg.SecretRef.Name)

	credentials, err := s.loadCredentials(ch, cfg)
	if err != nil {
		return nil, "", 0, fmt.Errorf("failed to load credentials: %w", err)
	}

	// There are other ways to assign a map to a struct but this is *by far* the easiest
	confs, err := json.Marshal(credentials)
	if err != nil {
		return nil, "", 0, fmt.Errorf("failed to marshal credentials as json: %w", err)
	}
	klog.Infof("%s", confs)
	provider, err := libdnsregistry.New(cfg.Provider, [][]byte{confs})
	if err != nil {
		return nil, "", 0, fmt.Errorf("failed to create %s provider: %w", cfg.Provider, err)
	}

	// Determine zone
	zone := cfg.Zone
	if zone == "" {
		zone = ch.ResolvedZone
	}
	// libdns providers expect zone WITHOUT trailing dot
	zone = strings.TrimSuffix(zone, ".")
	if zone == "" {
		return nil, "", 0, fmt.Errorf("resolved zone is empty; set config.zone or verify challenge resolvedZone")
	}

	// Determine TTL
	ttl := time.Duration(cfg.TTL) * time.Second
	if cfg.TTL <= 0 {
		ttl = defaultTTL * time.Second
	}
	if cfg.Provider == "desec" && ttl < desecMinTTL*time.Second {
		klog.Infof("Provider %s requires minimum TTL of %ds, overriding configured TTL to %ds", cfg.Provider, desecMinTTL, desecMinTTL)
		ttl = desecMinTTL * time.Second
	}

	return provider, zone, ttl, nil
}

// loadConfig parses the webhook configuration from JSON
func loadConfig(cfgJSON *extapi.JSON) (*LibdnsConfig, error) {
	cfg := &LibdnsConfig{}
	if cfgJSON == nil {
		return nil, fmt.Errorf("no configuration provided")
	}
	if err := json.Unmarshal(cfgJSON.Raw, cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	if cfg.Provider == "" {
		return nil, fmt.Errorf("provider is required in config")
	}
	if cfg.SecretRef.Name == "" {
		return nil, fmt.Errorf("secretRef.name is required in config")
	}
	return cfg, nil
}

// loadCredentials fetches credentials from a Kubernetes Secret
func (s *libdnsSolver) loadCredentials(ch *v1alpha1.ChallengeRequest, cfg *LibdnsConfig) (map[string]string, error) {
	namespace := cfg.SecretRef.Namespace
	if namespace == "" {
		namespace = ch.ResourceNamespace
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	secret, err := s.client.CoreV1().Secrets(namespace).Get(
		ctx,
		cfg.SecretRef.Name,
		metav1.GetOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret %s/%s: %w", namespace, cfg.SecretRef.Name, err)
	}

	credentials := make(map[string]string)
	for key, value := range secret.Data {
		credentials[key] = string(value)
	}

	klog.V(3).Infof("Loaded %d credential keys from secret", len(credentials))
	return credentials, nil
}

// extractRecordName removes the zone suffix from FQDN to get the relative record name
func extractRecordName(fqdn, zone string) string {
	// Remove trailing dots for comparison
	fqdn = strings.TrimSuffix(fqdn, ".")
	zone = strings.TrimSuffix(zone, ".")

	// Apex record for the zone
	if fqdn == zone {
		return "@"
	}

	// Remove exact ".<zone>" suffix if present.
	name := fqdn
	if zone != "" {
		suffix := "." + zone
		if strings.HasSuffix(fqdn, suffix) {
			name = strings.TrimSuffix(fqdn, suffix)
		}
	}

	// Clean up any leading/trailing dots
	name = strings.Trim(name, ".")

	// Return relative name
	if name == "" {
		return "@"
	}
	return name
}
