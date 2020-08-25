package internal

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/vault/api"
)

type Policy struct {
	Name string
}

type PolicyContainer struct {
	Container []Policy
	Client    *api.Client
}

func (pc *PolicyContainer) installPolicies(policies []Policy, policyPath string) error {
	for _, p := range policies {
		if err := pc.addPolicyToVault(p); err != nil {
			return fmt.Errorf("Could not install policy! %v", err)
		}
	}
	return nil
}

func (pc *PolicyContainer) addPolicyToVault(policy Policy) error {

	var reader io.Reader

	path := "/policies/" + policy.Name + ".hcl"
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("Could not open policy for install: %v", err)
	}
	defer file.Close()

	reader = file

	var buf bytes.Buffer

	if _, err := io.Copy(&buf, reader); err != nil {
		return fmt.Errorf("Error reading policy in buffer: %v", err)
	}

	rules := buf.String()

	name := strings.TrimSpace(strings.ToLower(policy.Name))

	if err := pc.Client.Sys().PutPolicy(name, rules); err != nil {
		return fmt.Errorf("Error uploading policy to Vault! %v", err)
	}

	return nil
}

func (pc *PolicyContainer) removeRootPolicy() []Policy {
	for i, p := range pc.Container {
		if p.Name == "root" {
			return append(pc.Container[:i], pc.Container[i+1:]...)
		}
	}
	return pc.Container
}

func (pc *PolicyContainer) deletePolicyFromVault(policy Policy) error {
	if err := pc.Client.Sys().DeletePolicy(policy.Name); err != nil {
		return fmt.Errorf("Could not delete policy: %v\nERROR: %v", policy.Name, err)
	}
	return nil
}

func (pc *PolicyContainer) appendPolicy(policy Policy) []Policy {
	pc.Container = append(pc.Container, policy)
	return pc.Container
}

func (pc *PolicyContainer) policyExist(s string) bool {
	for _, policy := range pc.Container {
		if policy.Name == s {
			return true
		}
	}
	return false
}

func (pc *PolicyContainer) exportPolicyFiles(path string) error {
	for _, p := range pc.Container {
		fName := path + p.Name + ".hcl"
		f, err := os.Create(fName)
		if err != nil {
			return fmt.Errorf("Could not write file: %v\nERROR: %v", fName, err)
		}

		defer f.Close()

		data, err := pc.Client.Sys().GetPolicy(p.Name)

		if err != nil {
			return fmt.Errorf("Could not get policy for write to file: %v\nERROR:%v", p.Name, err)
		}

		if _, err := f.WriteString(data); err != nil {
			return fmt.Errorf("Could not write to file: %v", err)
		}
	}
	return nil
}

func (pc *PolicyContainer) importVaultPolicies() error {

	pList, err := pc.Client.Sys().ListPolicies()
	if err != nil {
		return fmt.Errorf("Could not list policies: %v", err)
	}

	for _, policy := range pList {
		if policy != "root" {
			pc.appendPolicy(Policy{Name: policy})
		}
	}
	return nil
}

func (pc *PolicyContainer) importLocalPolicies(policyPath string) error {

	var localPolicies []Policy

	err := filepath.Walk(policyPath, func(p string, info os.FileInfo, err error) error {
		pP := filepath.Base(strings.TrimSpace(strings.TrimSuffix(p, ".hcl")))
		localPolicies = append(localPolicies, Policy{Name: strings.ToLower(pP)})
		return nil
	})

	if err != nil {
		return fmt.Errorf("Could not parse local policy names")
	}

	pc.Container = localPolicies[1:]

	return nil
}
