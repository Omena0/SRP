
# SRP - Small Reverse Proxy

## Features

- Authentication with rate limit
- Fast (under 1ms, can handle 50MB/s or 1000pps easily)
- Probably has like 20 memory leaks and rce exploits

## Todo

- Username & password auth
- Public web panel?
- Tests
- Per-user allocation limit
- Bandwidth/packet rate limit?
- Log file config
- Make sure it actually works

## Usage

```sh
./srp forward <localport>[:<globalport>] <login>
```

Or by using `forwards.conf`:

```sh
./srp forward
```

Server side:

```sh
./srp serve <host> <login>
```

Or by using `srps.conf`:

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
logins_per_ip=5

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
