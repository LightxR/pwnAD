# pwnAD

Status : currently in active development

pwnAD is a tool that focuses on Active Directory exploitation, mainly using LDAP and kerberos protocols at the moment but others protocols and features might be added in the future (hopefully).

The tool still contains bugs and some features are not fully operational (for now, better specify a username even when authenticating with certificates). <br>
So, don't hesitate to open an issue or make a pull request, I will gladly take it into account as soon as I can.



# Table of content

- [pwnAD](#pwnAD)
    - [Table of content](#table-of-content)
    - [Features](#features)
      - [Supported authentication](#supported-authentication)
    - [Installation](#installation)
    - [Usage](#usage)
    - [LDAP actions](#ldap-actions)
      - [add](#add)
      - [remove](#remove)
      - [get](#get)
      - [modify](#modify)
      - [query](#query)
    - [Special modules](#special-modules)
      - [shadow](#shadow)
    - [Kerberos actions](#kerberos-actions)
      - [getTGT](#gettgt)
      - [getST](#getst)
      - [getNTHash](#getnthash)
    - [Interactive mode](#interactive-mode)
      - [infos](#infos)
      - [start_tls](#start_tls)
      - [rebind](#rebind)
      - [switch_user](#switch_user)
    - [Credits](#credits)

# Features

The main features are :
- Many supported authentications (see after)
- LDAP enumeration and exploitation
- LDAP connection supports LDAP signing and channel binding (simple and NTLM authentication) thanks to [ldap3-bleeding-edge](https://pypi.org/project/ldap3-bleeding-edge) package. We will switch back to ldap3 main branch when the required PR are merged.
- Kerberos actions (getTGT, getST, getNThash) supports certificate authentication, thanks to PKINIT
- [Interactive shell !](#interactive-mode) (because it's cool)


## Supported authentications

|       LDAP    (get/add/remove/modify/query)            |    Flags                 |   Comments                                       | 
|---                                                     |---                       |---                                               |
|       NTLM (cleartext password)                        |   `-p`                   | Fall back to simple authentication when failing  |
|       NTLM (hash)                                      |   `-H`                   |                                                  |   
|       Kerberos (cleartext password)                    |   `-p` `-k`              |                                                  |       
|       Kerberos (hash)                                  |   `-H` `-k`              |                                                  |    
|       Kerberos (aeskey)                                |   `--aes-key`            |                                                  |      
|       Kerberos (ccache)                                |   `-k`                   | Try to to load ccache from KRB5CCNAME env        |      
|       Schannel (certificate)                           |   `-pfx`                 |                                                  |      
|       Schannel (certificate)                           |   `-cert` `-key`         |                                                  |      


|       Kerberos    (getTGT, getST, getNThash)           |    Flags                 |                                                  |       
|---                                                     |---                       |---                                               |
|       Kerberos (cleartext password)                    |   `-p`                   |                                                  |       
|       Kerberos (hash)                                  |   `-H`                   |                                                  |      
|       Kerberos (aeskey)                                |   `--aes-key`            |                                                  |     
|       Kerberos (ccache)                                |   `-k`                   |  for getST function only                         |       
|       Kerberos (certificate via PKINIT)                |   `-pfx`                 |                                                  |      
|       Kerberos (certificate via PKINIT)                |   `-cert` `-key`         |                                                  |       


# Installation

```
pipx install "git+https://github.com/LightxR/pwnAD"
```

# Usage

```
pwnAD -h
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


The tool takes an action as positionnal argument :
- LDAP actions : add, remove, get, modify, query
- Special modules : shadow (more modules in the future, feel free to propose some if you have any idea)
- Kerberos actions : getTGT, getST, getNThash

# LDAP actions

## add


```
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


## remove

```
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


## get

```
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


## modify

```
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

## query

Performs a raw LDAP query. 

```
pwnAD [robco.corp\administrator]> query -h
usage: pwnAD query [-h] search_filter attributes

positional arguments:
  search_filter  Filter to be applied on LDAP query
  attributes     Attributes to be applied on LDAP query

options:
  -h, --help     show this help message and exit
```


# Special modules

## shadow

This module is an implementation of Certipy shadow.

```
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


# Kerberos actions

## getTGT

Standard getTGT from impacket but with PKINIT if certificate authentication is provided.

```
pwnAD [robco.corp\administrator]> getTGT
[*] Trying to get TGT...
[*] Saving ticket in administrator.ccache
```


## getST

Standard getST from impacket but with PKINIT if certificate authentication is provided.

```
pwnAD [robco.corp\administrator]> getST -spn host/dc01
[*] Getting ST for user
[*] Saving ticket in administrator@host_dc01@ROBCO.CORP.ccache
```


## getNThash

getNThash allows you to retreive NThash from a user when you own his certificate. Magic is done with PKINIT.
```
pwnAD [u:ROBCO\Administrator]> getNThash 
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for administrator
[*] Got NThash for administrator: 7c8beec53973ada7cc96009c5e68f5fc
```


# Interactive mode

Because it is always more convenient, the interactive mode is here. 
Use the `-i` or `--interactive` flag along with connection details to start the interactive mode.

```
pwnAD -i --dc-ip 192.168.100.5 -u administrator -p 'Veryprotected123!' --tls                                       

 ____ ____ ____ ____ ____ 
||p |||w |||n |||A |||D ||
||__|||__|||__|||__|||__||
|/__\|/__\|/__\|/__\|/__\|

Version 0.0.1 by @LightxR 


pwnAD [robco.corp\administrator]> 
```

Once started, you can type `help` or press tabulation to show the available actions :
```
pwnAD [robco.corp\administrator]> 
add           getNThash     getTGT        modify        rebind        shadow        switch_user   
get           getST         infos         query         remove        start_tls  
```


Autocompletion is active and you should be able to access available commands and functions by pressing tabulation once again :
```
pwnAD [robco.corp\administrator]> add 
add RBCD             add dcsync           add groupMember      add write_gpo_dacl   
add computer         add genericAll       add user  
```

One of the most significant advantage of using the interactive shell is that you just need to focus on the actions you want to perform.
You are connected as lowpriv user ? Just type getTGT and you get a TGT for that user.

```
pwnAD [robco.corp\lowpriv]> getTGT 
[*] Trying to get TGT...
[*] Saving ticket in lowpriv.ccache
```

You want a TGT from another user ? Just type getTGT with the credentials of that other user (if you are targeting the same DC/domain)
```
pwnAD [robco.corp\administrator]> getTGT -u lowpriv2 -p Veryprotected123!
[*] Trying to get TGT...
[*] Saving ticket in lowpriv2.ccache
```

Everything looks simple.


## infos

`Infos` command display the current LDAP connection details.

```
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

## start_tls

When you are connected on standard port 389 (LDAP) and not port 636 (LDAPS), some actions requiring secure connection (like modifing a user password) won't be possible.
You can manually start a TLS connection with `start_tls` and therefore be allowed to performed these actions.
This functionnality might be implemented in the future to be performed automatically.

```
pwnAD [robco.corp\administrator]> modify password lowpriv Veryprotected123!
[-] Server unwilling to perform the operation: LDAPUnwillingToPerformResult - 53 - unwillingToPerform - None - 0000001F: SvcErr: DSID-031A124C, problem 5003 (WILL_NOT_PERFORM), data 0
 - modifyResponse - None

pwnAD [robco.corp\administrator]> start_tls 
[*] Sending StartTLS command...
[*] StartTLS succeded, you are now connected through a TLS channel

pwnAD [robco.corp\administrator]> modify password lowpriv Veryprotected123!
[*] Successfully changed lowpriv password to: Veryprotected123!
```

## rebind

Sometimes, your connection can timeout. 
Instead of launching the interactive shell once again, juste type `rebind`


```
pwnAD [robco.corp\administrator]> shadow list lowpriv
[-] An error has occured : socket sending error[Errno 104] Connection reset by peer

pwnAD [robco.corp\administrator]> rebind
[*] Successfully performed a connection rebind.

pwnAD [robco.corp\administrator]> shadow list lowpriv
[*] Targeting user lowpriv
[*] Listing Key Credentials for lowpriv
[*] DeviceID:1d8669ab-6a68-a58c-6b46-606e3623f579 | Creation Time (UTC): 2025-02-03 11:13:41.298149
```


## switch_user

Once again, instead of exiting current interactive session and executing a new pwnAD command, just switch user with new connection details.
What is nice here is that you don't have to pass domain and ip address arguments if you are targetting the same host/domain

```
pwnAD -i -u administrator -p 'Veryprotected123!' --dc-ip 192.168.99.10 -d robco.corp

 ____ ____ ____ ____ ____ 
||p |||w |||n |||A |||D ||
||__|||__|||__|||__|||__||
|/__\|/__\|/__\|/__\|/__\|

Version 0.1 by @LightxR 

"Jack of all trades, master of none."

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
pwnAD [robco.corp\lowpriv]> 

```

## Others features

When you are using the interactive shell, you can execute OS command by prefixing `!`

```
pwnAD [robco.corp\administrator]> !ls
LICENSE	 pwnAD   README.md  setup.py  stimpack.recipe
```

It can be useful for setting KRB5CCNAME variable for example without exiting your interactive session.


# Credits

`pwnAD` has been built on inspiration from the following tool architectures or by implementing directly some functionalities.
`pwnAD` code has been commented in this way to pay credit to the contributors of the open source community, so if any comment is missing please let me know.


- [ly4k](https://twitter.com/ly4k_) for [Certipy](https://github.com/ly4k/Certipy)
- [CravateRouge](https://cravaterouge.bsky.social) for [bloodyAD](https://github.com/CravateRouge/bloodyAD)
- [p0dalirius](https://twitter.com/podalirius_) and [Shutdown](https://twitter.com/_nwodtuhs) for [PyWhisker](https://github.com/ShutdownRepo/pywhisker), [rbcd.py](https://github.com/fortra/impacket/blob/master/examples/rbcd.py) and many others contributions.
- [Dirk-jan](https://twitter.com/_dirkjan) for [PKINITtools](https://github.com/dirkjanm/PKINITtools)
- [AlmondOffsec](https://offsec.almond.consulting) for [PassTheCert](https://github.com/AlmondOffSec/PassTheCert)
- [Fortra](https://github.com/fortra) and all the [contributors](https://github.com/fortra/impacket/graphs/contributors) for [Impacket](https://github.com/fortra/impacket)
