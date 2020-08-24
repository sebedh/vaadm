package main

import (
	"fmt"
	"io/ioutil"

	"github.com/hashicorp/vault/api"
)

var (
	vaultAddr    = "http://127.0.0.1:8200"
	vaultToken   = "s.Ymj4lZ9fALdDysnEKXv245sT"
	method       = "userpass"
	policyPath   = "../policies/"
	userYaml     = "../vault-access.yaml"
	rolesYaml    = "../ssh-roles.yaml"
	exportedYaml = "../vault-export.yaml"
	ssh_path     = "ssh/"
)

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

	//var uy VaultContainer
	uv := VaultContainer{client: client}

	//f, err := ioutil.ReadFile(userYaml)

	//if err != nil {
	//	fmt.Println(err)
	//	return
	//}

	//if err := uy.importLocalPolicies(policyPath); err != nil {
	//	fmt.Println(err)
	//	return
	//}

	//err = uy.importYaml(f)
	//if err != nil {
	//	fmt.Println(err)
	//	return
	//}
	//
	//if err := uv.importVault(); err != nil {
	//	fmt.Println(err)
	//	return
	//}
	//fmt.Println("vault container:", uv)

	sshcontainer := RoleContainer{client: client}

	f, err := ioutil.ReadFile(rolesYaml)
	if err != nil {
		fmt.Println("Could not open roles YAML: ", err)
		return
	}

	if err := sshcontainer.importYaml(f); err != nil {
		fmt.Println(err)
		return
	}

	for _, role := range sshcontainer.SSHRoleContainer {
		fmt.Println(role)
	}

	if err := exportYaml(&uv, exportedYaml); err != nil {
		fmt.Println(err)
		return
	}

	//
	//	if err := syncVaultPolicies(client, policyPath, &uy, &uv); err != nil {
	//		fmt.Println(err)
	//		return
	//	}

}
