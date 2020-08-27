package internal

import (
	"fmt"
	"os"

	"github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v2"
)

func getList(c *api.Logical, path string) (s []string, err error) {
	r, err := c.List(path)

	if err != nil || r == nil {
		return nil, fmt.Errorf("Could not return list, wrong auth or no items at path: %v\n", err)
	}

	data := r.Data["keys"].([]interface{})

	s = make([]string, len(data))

	for i, v := range data {
		s[i] = fmt.Sprint(v)
	}
	return s, nil
}

func syncVaultPolicies(policyPath string, filePolicies *PolicyContainer, vaultPolicies *PolicyContainer) error {
	for _, policy := range filePolicies.Container {
		policyExist := filePolicies.exists(policy.Name)
		if !policyExist {
			if err := filePolicies.installToVault(policy); err != nil {
				return fmt.Errorf("Could not add policy in sync process! %s", err)
			}
		}
	}

	for _, policy := range vaultPolicies.Container {
		policyExist := vaultPolicies.exists(policy.Name)
		if !policyExist {
			if err := vaultPolicies.deleteFromVault(policy); err != nil {
				return fmt.Errorf("Could not delete policy that should be delete: %s,\nBecouse: %s.", policy, err)
			}
		}
	}

	return nil
}

func syncVaultUsers(yamlVault *UserContainer, vaultVault *UserContainer) error {
	for _, user := range yamlVault.UserContainer {
		userExist := vaultVault.exist(user)
		if !userExist {
			if err := yamlVault.installToVault(user); err != nil {
				return fmt.Errorf("Could not add user in sync process! %s", err)
			}
		}
	}

	for _, user := range vaultVault.UserContainer {
		userExist := yamlVault.exist(user)
		if !userExist {
			if err := vaultVault.deleteFromVault(user); err != nil {
				return fmt.Errorf("Could not remove user in sync process! %s", err)
			}
		}
	}
	return nil
}

func exportYaml(data interface{}, fName string) error {
	f, err := os.Create(fName)

	if err != nil {
		return fmt.Errorf("Could not create file %s", err)
	}

	defer f.Close()

	yamlContent, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("Could not marshal object %s", err)
	}

	if _, err := f.WriteString(string(yamlContent)); err != nil {
		return fmt.Errorf("Could not write to file %s", err)
	}
	return nil
}
