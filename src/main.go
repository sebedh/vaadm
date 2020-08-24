package main

import (
	"fmt"

	"github.com/hashicorp/vault/api"
)

var (
	vaultAddr    = "http://127.0.0.1:8200"
	vaultToken   = "s.Ej1WTWm7cd3F10vzaFaTWPDV"
	method       = "userpass"
	policyPath   = "../policies/"
	userYaml     = "../vault-access.yaml"
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
	//var uv VaultContainer
	uv := VaultContainer{client: client}

	//f, err := ioutil.ReadFile(userYaml)

	if err != nil {
		fmt.Println(err)
		return
	}

	//if err := uy.importLocalPolicies(policyPath); err != nil {
	//	fmt.Println(err)
	//	return
	//}

	//	err = uy.importYaml(f)
	//	if err != nil {
	//		fmt.Println(err)
	//		return
	//	}
	//
	if err := uv.importVault(); err != nil {
		fmt.Println(err)
		return
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
