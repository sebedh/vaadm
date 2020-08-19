package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v2"
)

var vaultAddr = "https://vault.home.lan:8200"
var vaultToken = "s.fwsOWfVMrh86GBhRJhOU1HtJ"
var method = "userpass"

type User struct {
	Name     string   `yaml:"name"`
	Policies []string `yaml:"policies"`
	//Groups   []Group  `yaml:"groups"`
}

//type Group struct {
//	Name string `yaml:"name"`
//}

type VaultContainer struct {
	UserContainer []User `yaml:"users"`
	//GroupContainer []Group `yaml:"users"`
}

func (u *VaultContainer) addUser(user User) []User {
	u.UserContainer = append(u.UserContainer, user)
	return u.UserContainer
}

func (u *VaultContainer) getUser(search string) (user User, err error) {
	for _, user := range u.UserContainer {
		if user.Name == search {
			return user, nil
		}
	}
	emptyUser := User{}
	return emptyUser, fmt.Errorf("Could not find user %v\n", search)
}

func (u *VaultContainer) getYamlUser() error {

	data, err := ioutil.ReadFile("./vault-access.yaml")
	if err != nil {
		return fmt.Errorf("Could not read file: %v\n", err)
	}

	err = yaml.Unmarshal(data, u)

	if err != nil {
		return fmt.Errorf("Unmarshal error %v\n", err)
	}

	return nil
}

func (u *VaultContainer) getVaultUser(c *api.Client) error {
	cL := c.Logical()
	userList, err := listUsers(c, method)
	if err != nil {
		return fmt.Errorf("Could not retrieve all users %v\n", err)
	}
	for _, uName := range userList {
		path := "/auth/" + method + "/users/" + uName

		vaultUser, err := cL.Read(path)
		if err != nil {
			return fmt.Errorf("Could not retrieve all users %v\n", err)
		}

		tempPolicies := vaultUser.Data["token_policies"].([]interface{})
		policies := make([]string, len(tempPolicies))

		for i, p := range tempPolicies {
			policies[i] = fmt.Sprint(p)
		}

		user := User{Name: uName, Policies: policies}
		u.addUser(user)
	}
	return nil
}

func removeRootPolicy(s []string) []string {
	for i, p := range s {
		if p == "root" {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
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

		err = f.Close()

		if err != nil {
			return fmt.Errorf("Could not close file policy: %v, becouse: %v\n", p, err)
		}

	}
	return nil
}

func exportVaultAccess(users []string, c *api.Client) {

}

//func listGroups(c *api.Client, method string) (g []Group, err error) {
//	cL := c.Logical()
//}

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
	//	return u, fmt.Errorf("Marshal error: %v\n", err)
	//}

	u = make([]string, len(t))

	for i, v := range t {
		u[i] = fmt.Sprint(v)
	}

	return u, nil
}

func syncUserContainer(c *api.Client) {

	var u UserContainer
	err := u.getYamlUserContainer()

	if err != nil {
		fmt.Println(err)
		panic("Clould not get users from yaml file")
	}

	dU, err := u.getUser("test")

	if err != nil {
		fmt.Println(err)
		return
	}

	err = deleteUser(c, dU)
	if err != nil {
		fmt.Println(err)
		return
	}
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

	var uy UserContainer
	var uv UserContainer

	err = uy.getYamlUserContainer()
	if err != nil {
		fmt.Println(err)
		return
	}
	err = uv.getVaultUserContainer(client)
	if err != nil {
		fmt.Println(err)
		return
	}
	//	uA, err := uy.getUser("someother")
	//	if err != nil {
	//		fmt.Println(err)
	//		return
	//	}
	//	err = addUser(client, uA)
	//	if err != nil {
	//		fmt.Println(err)
	//		return
	//	}

}
