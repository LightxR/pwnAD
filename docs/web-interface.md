# Web Interface

pwnAD ships an optional browser-based interface for interactive Active Directory
exploration and abuse. It reuses the same authenticated LDAP connection as the
CLI, exposing browsing, object editing, DACL operations, DNS, Shadow Credentials
and ADCS enumeration through a local web UI.

## Starting the Web Interface

Add the `--web` flag to any valid authentication command:

```bash
pwnAD --web --dc-ip 192.168.1.10 -d domain.local -u administrator -p 'Password123!'
```

By default the server binds to `127.0.0.1:5000`:

```
[*] Starting pwnAD web server
[*] Press CTRL+C to stop the server
```

Then open <http://127.0.0.1:5000> in your browser.

### Options

| Flag         | Default     | Description                     |
|--------------|-------------|---------------------------------|
| `--web`      | *(off)*     | Start the web interface instead of the CLI |
| `--web-host` | `127.0.0.1` | Bind address for the web server |
| `--web-port` | `5000`      | Bind port for the web server    |

## Security Considerations

!!! danger "The web interface has no authentication"
    Anyone who can reach the listening socket gets **full write access to
    Active Directory** with the privileges of the account you authenticated
    with (password resets, account/computer creation, group membership, DACL
    edits, Shadow Credentials, …). Treat the port as equivalent to your
    credentials.

- **Keep the default `127.0.0.1` bind.** Only change `--web-host` if you fully
  control network access to the machine (e.g. behind a VPN or SSH tunnel). Never
  expose it on an untrusted network.
- To reach it from another host, prefer an **SSH tunnel** over binding publicly:

    ```bash
    ssh -L 5000:127.0.0.1:5000 operator@jumpbox
    ```

- Requests are served single-threaded on purpose: the underlying `ldap3`
  connection is shared and not thread-safe, so operations are serialised.

## Features

- **Browse** — navigate the directory tree, search objects, inspect and edit
  attributes, enable/disable accounts, reset passwords, restore deleted objects.
- **Writable** — enumerate objects the current principal can write to
  (computed via `allowedAttributesEffective` / `sDRightsEffective`).
- **DACL** — read, add and remove ACEs; change object owners.
- **DNS** — list and manage ADIDNS records.
- **Shadow Credentials** — add/list/remove `msDS-KeyCredentialLink` entries.
- **ADCS** — enumerate certificate authorities and templates.

## Stopping the Server

Press `CTRL+C` in the terminal running pwnAD to shut the server down.
