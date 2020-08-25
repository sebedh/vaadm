# Vault Admin

This tools helps Vault operators maintain version control on SSH Roles, Policies and Users.

For know only ldap and userpass auth method is tested.

# How To Use

Carefull using this at first, it can delete users, policies and ssh roles.

Vault Admin will read your vault-access yaml and ssh-roles yaml and scan the roles and users that should exist on Vault. It will delete users that exists on Vault but not in your Yaml. 

It will also read your policy directory and sync it with the external Vault.

