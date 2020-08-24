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
	Policies []string `yaml:"token_policies"`
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

func (vc *VaultContainer) importVault() error {
	c := vc.client.Logical()

	path := "/auth/" + method + "/users"

	users, err := getList(c, path)

	if err != nil {
		return fmt.Errorf("Could not return list of users, method activated? %v\n", err)
	}

	for _, uName := range users {
		userPath := path + "/" + uName

		data, err := c.Read(userPath)

		if err != nil {
			return fmt.Errorf("Could not read user data: %v\n", err)
		}

		content, err := yaml.Marshal(data.Data)
		if err != nil {
			return fmt.Errorf("Could not Marshal user data: %v\n", err)
		}

		user := User{Name: uName}
		if err := yaml.Unmarshal(content, &user); err != nil {
			return fmt.Errorf("Could not Unmarshal into map: %v\n", err)
		}

		vc.addContainerUser(user)
	}

	return nil

}
