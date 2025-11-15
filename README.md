
# SRP - Small Reverse Proxy

## Features

- Authentication with rate limit
- Fast (under 1ms, can handle 50MB/s or 1000pps easily)
- Probably has like 20 memory leaks and rce exploits
- Username & password auth
- Cross platform
- Per-user allocation limit
- Tests

## Usage

```sh
./srp register <username> <password>
```

```sh
./srp deletelogin <username> <password>
```

```sh
./srp claim <port>
```

```sh
./srp unclaim <username> <password>
```

```sh
./srp forward
```

```sh
./srp serve
```

## Config format

### srps.conf

```conf
host=127.0.0.1:6969

# Port forwarding restrictions
min_port=20000
max_port=21000
ports_per_login=10
logins_per_ip=3

# Restricted ports (comma-separated, can only be used via config file assignment)
# Example: restricted_ports=22,80,443,3306
restricted_ports=
```

### forwards.conf

```conf
# Address of the SRP server
server=127.0.0.1:6969

# Login
passwd=Omena0:bingchilling

# Forwards
# <remote port> -> <local port>
forwards=[
    20001 -> 8000
]
```

## Data storage format

### logins.conf

Live list of logins in format:

```spec
<username>:<passwd hash>:<creation timestamp>[|<claimed ports csv>]
```

Editing the file should apply changes without restarting server.
The server should edit this file to add/remove accounts/claimed ports
