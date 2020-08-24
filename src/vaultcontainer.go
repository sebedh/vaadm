package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v2"
)

type User struct {
	Name     string   `yaml:"name"`
	Policies []string `yaml:"policies"`
}

type VaultContainer struct {
	UserContainer   []User      `yaml:"users"`
	PolicyContainer []string    `yaml:"policies"`
	client          *api.Client `yaml:"-"`
}

func (vc *VaultContainer) userExist(findUser User) bool {
	for _, user := range vc.UserContainer {
		if user.Name == findUser.Name {
			return true
		}
	}
	return false
}

func (vc *VaultContainer) policyExist(s string) bool {
	for _, policy := range vc.PolicyContainer {
		if policy == s {
			return true
		}
	}
	return false
}

func (vc *VaultContainer) addContainerUser(user User) []User {
	vc.UserContainer = append(vc.UserContainer, user)
	return vc.UserContainer
}

func (vc *VaultContainer) addContainerPolicy(policy string) []string {
	vc.PolicyContainer = append(vc.PolicyContainer, policy)
	return vc.PolicyContainer
}

func (vc *VaultContainer) getContainerUser(search string) (user User, err error) {
	for _, user := range vc.UserContainer {
		if user.Name == search {
			return user, nil
		}
	}
	emptyUser := User{}
	return emptyUser, fmt.Errorf("Could not find user %v\n", search)
}

func (vc *VaultContainer) importYaml(yml []byte) error {

	if err := yaml.Unmarshal(yml, vc); err != nil {
		return fmt.Errorf("Unmarshal error %v\n", err)
	}

	return nil
}

func (vc *VaultContainer) exportYaml(fName string) error {
	f, err := os.Create(fName)

	if err != nil {
		return fmt.Errorf("Could not create file %s", err)
	}

	defer f.Close()

	yamlContent, err := yaml.Marshal(vc)
	if err != nil {
		return fmt.Errorf("Could not marshal object %s", err)
	}

	if _, err := f.WriteString(string(yamlContent)); err != nil {
		return fmt.Errorf("Could not write to file %s", err)
	}
	return nil
}

func (vc *VaultContainer) importLocalPolicies(policyPath string) error {

	var localPolicies []string

	err := filepath.Walk(policyPath, func(p string, info os.FileInfo, err error) error {
		pP := filepath.Base(strings.TrimSpace(strings.TrimSuffix(p, ".hcl")))
		localPolicies = append(localPolicies, strings.ToLower(pP))
		return nil
	})

	if err != nil {
		return fmt.Errorf("Could not parse local policy names")
	}

	vc.PolicyContainer = localPolicies[1:]

	return nil
}

// get []string of users and import one by one
func (vc *VaultContainer) importVault() error {

	vaultPolicies, err := vc.client.Sys().ListPolicies()
	vc.PolicyContainer = removeRootPolicy(vaultPolicies)

	if err != nil {
		return fmt.Errorf("Could not get policies")
	}

	cL := vc.client.Logical()

	path := "/auth/" + method + "/users"

	userList, err := getList(cL, path)

	if err != nil {
		return fmt.Errorf("Could not get users becouse: %v\n", err)
	}

	for _, uName := range userList {
		path := "/auth/" + method + "/users/" + uName

		vaultUser, err := cL.Read(path)

		if err != nil {
			return fmt.Errorf("Could not read user: %v\n ERROR: %v\n", uName, err)
		}

		tempPolicies := vaultUser.Data["token_policies"].([]interface{})
		policies := make([]string, len(tempPolicies))

		for i, p := range tempPolicies {
			policies[i] = fmt.Sprint(p)
		}

		user := User{Name: uName, Policies: policies}
		vc.addContainerUser(user)
	}
	return nil
}
