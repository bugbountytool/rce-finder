package config

import (
	"testing"
)

func TestDetectsContainerAndSecretWeaknesses(t *testing.T) {
	content := []byte(`services:
  app:
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      AWS_KEY: AKIAIOSFODNN7EXAMPLE
`)
	fs := ScanFile("docker-compose.yml", content)
	ids := map[string]bool{}
	for _, f := range fs {
		ids[f.RuleID] = true
	}
	for _, want := range []string{"docker-privileged", "docker-sock-mount", "aws-access-key"} {
		if !ids[want] {
			t.Errorf("rule %s not detected; got %v", want, ids)
		}
	}
}

func TestKubernetesPrivilegeRules(t *testing.T) {
	content := []byte(`spec:
  hostNetwork: true
  securityContext:
    allowPrivilegeEscalation: true
    runAsUser: 0
    seccompProfile: Unconfined
  containers:
    - image: nginx:latest
`)
	fs := ScanFile("pod.yaml", content)
	ids := map[string]bool{}
	for _, f := range fs {
		ids[f.RuleID] = true
	}
	for _, want := range []string{"k8s-host-network", "k8s-allow-priv-escalation", "k8s-run-as-root", "k8s-seccomp-unconfined", "k8s-latest-tag"} {
		if !ids[want] {
			t.Errorf("rule %s not detected; got %v", want, ids)
		}
	}
}

func TestNoFalsePositiveOnSecureConfig(t *testing.T) {
	content := []byte(`spec:
  securityContext:
    allowPrivilegeEscalation: false
    runAsNonRoot: true
    runAsUser: 1000
  containers:
    - image: nginx:1.27.1
`)
	fs := ScanFile("pod.yaml", content)
	for _, f := range fs {
		if f.RuleID == "k8s-allow-priv-escalation" || f.RuleID == "k8s-run-as-root" || f.RuleID == "k8s-latest-tag" {
			t.Errorf("false positive on secure config: %+v", f)
		}
	}
}

func TestFileMatchRestrictsRules(t *testing.T) {
	// privileged:true in a non-YAML file should not trigger the YAML-scoped rule.
	fs := ScanFile("notes.txt", []byte("privileged: true"))
	for _, f := range fs {
		if f.RuleID == "docker-privileged" {
			t.Fatal("YAML-scoped rule fired on a .txt file")
		}
	}
}
