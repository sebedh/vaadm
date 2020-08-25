package internal

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"
	"gopkg.in/yaml.v2"
)

type SSHRole struct {
	Name               string   `yaml:"name"`
	Key_type           string   `yaml:"key_type"`
	Default_user       string   `yaml:"default_user"`
	Cidr_list          []string `yaml:"cidr_list"`
	Allowed_users      []string `yaml:"allowed_users"`
	Port               int      `yaml:"port"`
	Excluded_cidr_list []string `yaml:"excluded_cidr_list"`
}

type SSHRoleContainer struct {
	SSHRoleContainer []SSHRole   `yaml:"sshroles"`
	Client           *api.Client `yaml:"-"`
}

func (r *SSHRoleContainer) appendSSHRole(sshRole SSHRole) []SSHRole {
	r.SSHRoleContainer = append(r.SSHRoleContainer, sshRole)
	return r.SSHRoleContainer
}

func (r *SSHRoleContainer) importYaml(yml []byte) error {
	if err := yaml.Unmarshal(yml, r); err != nil {
		return fmt.Errorf("Could not parse SSH yml, %s", err)
	}
	return nil
}

func (r *SSHRoleContainer) policyExist(s string) bool {
	for _, sshrole := range r.SSHRoleContainer {
		if sshrole.Name == s {
			return true
		}
	}
	return false
}

func (r *SSHRoleContainer) importVault() error {
	c := r.Client.Logical()

	rolesPath := "/ssh/roles"

	roles, err := getList(c, rolesPath)

	if err != nil {
		return fmt.Errorf("Could not return list of roles, none installed? %v\n", err)
	}

	for _, roleName := range roles {
		rolePath := rolesPath + "/" + roleName

		data, err := c.Read(rolePath)

		if err != nil {
			return fmt.Errorf("Could not read role: %v\n", err)
		}

		content, err := yaml.Marshal(data.Data)
		if err != nil {
			return fmt.Errorf("Could not parse yaml")
		}

		m := make(map[interface{}]interface{})

		if err := yaml.Unmarshal(content, &m); err != nil {
			return fmt.Errorf("Could not unmarshal into map, %s", err)
		}

		var excluded_cidr_list []string
		var allowed_users []string
		var cidr_list []string
		var port int

		if m["excluded_cidr_list"] != nil {
			excluded_cidr_list = strings.Split(m["excluded_cidr_list"].(string), ",")
		}

		if m["allowed_users"] != nil {
			allowed_users = strings.Split(m["allowed_users"].(string), ",")
		}

		if m["cidr_list"] != nil {
			cidr_list = strings.Split(m["cidr_list"].(string), ",")
		}

		if m["port"] != nil {
			port = m["port"].(int)
		}
		_ = excluded_cidr_list
		role := SSHRole{
			Name:               roleName,
			Key_type:           m["key_type"].(string),
			Allowed_users:      allowed_users,
			Default_user:       m["default_user"].(string),
			Cidr_list:          cidr_list,
			Excluded_cidr_list: excluded_cidr_list,
			Port:               port,
		}

		r.appendSSHRole(role)

	}

	return nil
}

func (r *SSHRoleContainer) installSSHRoles() error {
	for _, role := range r.SSHRoleContainer {
		if err := r.addRoleToVault(role); err != nil {
			return fmt.Errorf("Could not install role!: %v, %v", r, err)
		}
	}
	return nil
}

func (r *SSHRoleContainer) addRoleToVault(role SSHRole) error {
	c := r.Client.Logical()
	path := "/ssh/roles/" + role.Name

	data := make(map[string]interface{})

	data["key_type"] = role.Key_type
	data["default_user"] = role.Default_user
	data["allowed_users"] = strings.Join(role.Allowed_users, ",")
	data["cidr_list"] = strings.Join(role.Cidr_list, ",")
	data["excluded_cidr_list"] = strings.Join(role.Excluded_cidr_list, ",")
	data["port"] = role.Port

	if _, err := c.Write(path, data); err != nil {
		return fmt.Errorf("Could not write role")
	}

	return nil
}

func (r *SSHRoleContainer) deleteRoleFromVault(role SSHRole) error {
	c := r.Client.Logical()

	path := "/ssh/roles/" + role.Name

	if _, err := c.Delete(path); err != nil {
		return fmt.Errorf("Could not delete SSH Role: %v\n%v", role.Name, err)
	}
	return nil
}
