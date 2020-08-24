package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
)

func removeRootPolicy(s []string) []string {
	for i, p := range s {
		if p == "root" {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}

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

func getVaultPolicies(c *api.Client) (p []string, err error) {
	var policies []string

	pList, err := c.Sys().ListPolicies()
	removeRootPolicy(pList)

	if err != nil {
		return nil, fmt.Errorf("Could not get policies: %v", err)
	}

	policies = append(policies, pList...)

	return policies, err
}

func exportVaultPolicies(c *api.Client, policies []string) error {

	for _, p := range policies {
		fName := "policies/" + p + ".hcl"
		f, err := os.Create(fName)

		if err != nil {
			return fmt.Errorf("Could not write: %v, becouse: %v\n", fName, err)
		}

		defer f.Close()
		pContent, err := c.Sys().GetPolicy(p)

		if err != nil {
			return fmt.Errorf("Could not get policy: %v, becouse: %v\n", p, err)
		}

		_, err = f.WriteString(pContent)
		if err != nil {
			return fmt.Errorf("Could not write policy: %v, becouse: %v\n", p, err)
		}
	}
	return nil
}

func installPolicies(c *api.Client, policies []string, policyPath string) error {

	for _, p := range policies {
		if err := addVaultPolicy(c, policyPath, p); err != nil {
			return fmt.Errorf("Could not install policy!")
		}
		//		path := "policies/" + p + ".hcl"
		//		file, err := os.Open(path)
		//		if err != nil {
		//			return fmt.Errorf("Error opening policy file %s", err)
		//		}
		//		defer file.Close()
		//		reader = file
		//
		//		var buf bytes.Buffer
		//
		//		if _, err := io.Copy(&buf, reader); err != nil {
		//			return fmt.Errorf("Error reading policy!")
		//		}
		//
		//		rules := buf.String()
		//
		//		name := strings.TrimSpace(strings.ToLower(p))
		//
		//		if err := c.Sys().PutPolicy(name, rules); err != nil {
		//			return fmt.Errorf("Error uploading policy! %s", err)
		//		}
	}
	return nil
}

func syncVaultPolicies(c *api.Client, policyPath string, yamlVault *VaultContainer, vaultVault *VaultContainer) error {
	for _, policy := range yamlVault.PolicyContainer {
		policyExist := vaultVault.policyExist(policy)
		if !policyExist {
			if err := addVaultPolicy(c, policyPath, policy); err != nil {
				return fmt.Errorf("Could not add policy in sync process! %s", err)
			}
		}
	}

	for _, policy := range vaultVault.PolicyContainer {
		policyExist := yamlVault.policyExist(policy)
		if !policyExist {
			if err := deleteVaultPolicy(c, policy); err != nil {
				return fmt.Errorf("Could not delete policy that should be delete: %s,\nBecouse: %s.", policy, err)
			}
		}
	}

	return nil
}

func syncVaultUsers(c *api.Client, yamlVault *VaultContainer, vaultVault *VaultContainer) error {
	for _, user := range yamlVault.UserContainer {
		userExist := vaultVault.userExist(user)
		if !userExist {
			if err := addVaultUser(c, user); err != nil {
				return fmt.Errorf("Could not add user in sync process! %s", err)
			}
		}
	}

	for _, user := range vaultVault.UserContainer {
		userExist := yamlVault.userExist(user)
		if !userExist {
			if err := deleteVaultUser(c, user); err != nil {
				return fmt.Errorf("Could not remove user in sync process! %s", err)
			}
		}
	}
	return nil
}

func exportVaultAccess(users []string, c *api.Client) {}

func deleteVaultUser(c *api.Client, u User) error {
	cL := c.Logical()
	path := "/auth/" + method + "/users/" + u.Name
	_, err := cL.Delete(path)
	if err != nil {
		return fmt.Errorf("Could not delete user: %v\n", err)
	}
	return nil
}

func deleteVaultPolicy(c *api.Client, p string) error {
	if err := c.Sys().DeletePolicy(p); err != nil {
		return fmt.Errorf("Could not delete policy: %s,\nBecouse: %s", p, err)
	}
	return nil
}

//u.UserContainer = append(u.UserContainer[:i], u.UserContainer[i+1:]...)
func addVaultUser(c *api.Client, u User) error {
	cL := c.Logical()
	path := "/auth/" + method + "/users/" + u.Name

	data := make(map[string]interface{})
	if method == "userpass" {
		data["password"] = "temp0r!PassW0rd"
	}
	data["token_policies"] = u.Policies
	// Write
	_, err := cL.Write(path, data)
	if err != nil {
		return fmt.Errorf("Could not add becouse %v\n", err)
	}
	return nil
}

func addVaultPolicy(c *api.Client, policyPath string, policy string) error {

	var reader io.Reader

	path := policyPath + policy + ".hcl"
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("Error opening policy file %s", err)
	}
	defer file.Close()
	reader = file

	var buf bytes.Buffer

	if _, err := io.Copy(&buf, reader); err != nil {
		return fmt.Errorf("Error reading policy!")
	}

	rules := buf.String()

	name := strings.TrimSpace(strings.ToLower(policy))

	if err := c.Sys().PutPolicy(name, rules); err != nil {
		return fmt.Errorf("Error uploading policy! %s", err)
	}
	return nil
}
