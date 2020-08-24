package main

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

type RoleContainer struct {
	SSHRoleContainer []SSHRole   `yaml:"sshroles"`
	client           *api.Client `yaml:"-"`
}

func (r *RoleContainer) Append(sshRole SSHRole) []SSHRole {
	r.SSHRoleContainer = append(r.SSHRoleContainer, sshRole)
	return r.SSHRoleContainer
}

func (r *RoleContainer) importYaml(yml []byte) error {
	if err := yaml.Unmarshal(yml, r); err != nil {
		return fmt.Errorf("Could not parse SSH yml, %s", err)
	}
	return nil
}

func (r *RoleContainer) importVault() error {
	c := r.client.Logical()

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

		r.Append(role)

	}

	return nil
}
