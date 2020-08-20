package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v2"
)

var vaultAddr = "http://127.0.0.1:8200"
var vaultToken = "s.r3EACEfjaamu0yZnWf1xPu4Y"
var method = "userpass"

type User struct {
	Name     string   `yaml:"name"`
	Policies []string `yaml:"policies"`
}

type VaultContainer struct {
	UserContainer []User `yaml:"users"`
	//yml           []byte
}

func (vc *VaultContainer) userExist(findUser User) bool {
	for _, user := range vc.UserContainer {
		if user.Name == findUser.Name {
			return true
		}
	}
	return false
}

func (vc *VaultContainer) addUser(user User) []User {
	vc.UserContainer = append(vc.UserContainer, user)
	return vc.UserContainer
}

func (vc *VaultContainer) getUser(search string) (user User, err error) {
	for _, user := range vc.UserContainer {
		if user.Name == search {
			return user, nil
		}
	}
	emptyUser := User{}
	return emptyUser, fmt.Errorf("Could not find user %v\n", search)
}

func (vc *VaultContainer) importYaml(yml []byte) error {

	err := yaml.Unmarshal(yml, vc)

	if err != nil {
		return fmt.Errorf("Unmarshal error %v\n", err)
	}

	return nil
}

// get []string of users and import one by one
func (vc *VaultContainer) importVault(c *api.Client) error {
	cL := c.Logical()

	userList, err := listUsers(c, method)

	if err != nil {
		return fmt.Errorf("Could not retrieve all users %v\n", err)
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
		vc.addUser(user)
	}
	return nil
}

func (vc *VaultContainer) syncVaultContainer(c *api.Client) {}

func removeRootPolicy(s []string) []string {
	for i, p := range s {
		if p == "root" {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}

func listUsers(c *api.Client, method string) (u []string, err error) {
	cL := c.Logical()

	users, err := cL.List("/auth/" + method + "/users")

	if err != nil {
		return u, fmt.Errorf("Could not get user list: %v\n", err)
	}

	t := users.Data["keys"].([]interface{})

	// Is this the solution
	//y, err := json.Marshal(users.Data["keys"])
	//if err != nil {
	//      return u, fmt.Errorf("Marshal error: %v\n", err)
	//}

	u = make([]string, len(t))

	for i, v := range t {
		u[i] = fmt.Sprint(v)
	}

	return u, nil
}

func getAllPolicies(c *api.Client) (p []string, err error) {
	p, err = c.Sys().ListPolicies()
	if err != nil {
		return p, fmt.Errorf("Could not get policies: %v", err)
	}
	return removeRootPolicy(p), err
}

func exportPolicies(policies []string, c *api.Client) error {

	for _, p := range policies {
		fName := "policies/" + p + ".hcl"
		f, err := os.Create(fName)
		defer f.Close()

		if err != nil {
			return fmt.Errorf("Could not write: %v, becouse: %v\n", fName, err)
		}
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

func installPolicies(policies []string, c *api.Client) error {

	var reader io.Reader

	for _, p := range policies {
		path := "policies/" + p + ".hcl"
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

		name := strings.TrimSpace(strings.ToLower(p))

		if err := c.Sys().PutPolicy(name, rules); err != nil {
			return fmt.Errorf("Error uploading policy! %s", err)
		}
	}
	return nil
}

func syncPolicies(c *api.Client) error {

	vaultPolicies, err := getAllPolicies(c)

	if err != nil {
		return fmt.Errorf("Tried to read current policies, FAILED %s", err)
	}

	var localPolicies []string
	var tempLocalPolicies []string
	path := "policies/"
	err = filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		pP := strings.TrimSpace(strings.Trim(p, ".hcl"))
		tempLocalPolicies = append(tempLocalPolicies, pP[9:])
		return nil
	})
	if err != nil {
		return fmt.Errorf("Error could not retrieve file list: %s", err)
	}

	localPolicies = tempLocalPolicies[1:]
	var notInstalled []string

	for _, p := range localPolicies {
		for _, vp := range vaultPolicies {
			if p != vp {
				notInstalled = append(notInstalled, p)
			}
		}
	}
	fmt.Println(notInstalled)
	//if err := installPolicies(notInstalled, c); err != nil {
	//	return fmt.Errorf("Could not install policies")
	//}

	return nil
}

func exportVaultAccess(users []string, c *api.Client) {
}

func deleteUser(c *api.Client, u User) error {
	cL := c.Logical()
	path := "/auth/" + method + "/users/" + u.Name
	_, err := cL.Delete(path)
	if err != nil {
		return fmt.Errorf("Could not delete user: %v\n", err)
	}
	return nil
}

//u.UserContainer = append(u.UserContainer[:i], u.UserContainer[i+1:]...)
func addUser(c *api.Client, u User) error {
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

//func removeDuplicates(slice []interface{}) []interface{} {
//
//}

func main() {
	config := &api.Config{
		Address: vaultAddr,
	}

	client, err := api.NewClient(config)
	if err != nil {
		fmt.Println(err)
		return
	}

	client.SetToken(vaultToken)
	if err != nil {
		fmt.Println(err)
		return
	}

	var uy VaultContainer
	var uv VaultContainer

	f, err := ioutil.ReadFile("./vault-access.yaml")

	if err != nil {
		fmt.Println(err)
		return
	}

	err = uy.importYaml(f)
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := uv.importVault(client); err != nil {
		fmt.Println(err)
		return
	}

	//	if err := installPolicies(client); err != nil {
	//
	//	}
	//	if err := syncPolicies(client); err != nil {
	//		return
	//	}

	for _, user := range uy.UserContainer {
		userExist := uv.userExist(user)
		if !userExist {
			if err := addUser(client, user); err != nil {
				fmt.Println(err)
				return
			}
		}
	}

	for _, user := range uv.UserContainer {
		userExist := uy.userExist(user)
		if !userExist {
			if err := deleteUser(client, user); err != nil {
				fmt.Println(err)
				return
			}
		}
	}
}
