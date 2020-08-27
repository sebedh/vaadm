package internal

import (
	"fmt"

	"github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v2"
)

type User struct {
	Name     string   `yaml:"name"`
	Policies []string `yaml:"token_policies"`
}

type UserContainer struct {
	UserContainer []User `yaml:"users"`
	method        string
	Client        *api.Client `yaml:"-"`
}

func (uc *UserContainer) exist(findUser User) bool {
	for _, user := range uc.UserContainer {
		if user.Name == findUser.Name {
			return true
		}
	}
	return false
}

func (uc *UserContainer) add(user User) []User {
	uc.UserContainer = append(uc.UserContainer, user)
	return uc.UserContainer
}

func (uc *UserContainer) get(search string) (user User, err error) {
	for _, user := range uc.UserContainer {
		if user.Name == search {
			return user, nil
		}
	}
	emptyUser := User{}
	return emptyUser, fmt.Errorf("Could not find user %v\n", search)
}

func (uc *UserContainer) importYaml(yml []byte) error {

	if err := yaml.Unmarshal(yml, uc); err != nil {
		return fmt.Errorf("Unmarshal error %v\n", err)
	}

	return nil
}

func (uc *UserContainer) importVault() error {
	c := uc.Client.Logical()

	path := "/auth/" + uc.method + "/users"

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

		uc.add(user)
	}

	return nil

}

func (uc *UserContainer) installAll() error {
	for _, user := range uc.UserContainer {
		if err := uc.installToVault(user); err != nil {
			return fmt.Errorf("Could not install user %v\nERROR: %v", user.Name, err)
		}
	}
	return nil
}
func (uc *UserContainer) installToVault(user User) error {
	c := uc.Client.Logical()
	path := "/auth/" + uc.method + "/users/" + user.Name

	data := make(map[string]interface{})
	if uc.method == "userpass" {
		data["password"] = "temp0rPassW0rd"
	}
	data["token_policies"] = user.Policies
	if _, err := c.Write(path, data); err != nil {
		return fmt.Errorf("Could not install user: %v\nERROR:%v", user.Name, err)
	}
	return nil
}

func (uc *UserContainer) deleteFromVault(user User) error {
	c := uc.Client.Logical()
	path := "/auth/" + uc.method + "/users/" + user.Name
	if _, err := c.Delete(path); err != nil {
		return fmt.Errorf("Could not delete user: %v\n", err)
	}
	return nil
}
