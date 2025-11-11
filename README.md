
# SRP - Small Reverse Proxy

High-performance, low-latency reverse proxy for tunneling Minecraft servers through a VPS. Optimized for gaming with minimal overhead and automatic reconnection.

## Features

- **Ultra-low latency** - TCP_NODELAY enabled, optimized socket buffers
- **Password authentication** - Secure tunnel connections
- **Rate limiting** - Protects against brute force (3 attempts, 1 min timeout, 1 sec delay)
- **Auto-reconnect** - Forward mode automatically reconnects on disconnection
- **Cross-platform** - Works on Windows and Linux
- **Minimal overhead** - Direct socket forwarding with no extra processing

## Building

### Windows (MSVC or GCC)
```sh
gcc -O3 -Wall -march=native -o srp.exe main.c -lws2_32
```

### Linux
```sh
gcc -O3 -Wall -march=native -o srp main.c -pthread
```

### Using Make
```sh
make
```

## Usage

### On the Minecraft Server (behind NAT)

Forward local Minecraft server to the VPS tunnel:

```sh
srp forward <local-port> <tunnel-ip:port> <password>
```

**Example:**
```sh
# Forward local MC server on port 25565 to VPS at 203.0.113.10:7777
srp forward 25565 203.0.113.10:7777 mysecretpassword
```

This will:
1. Connect to the tunnel server at `203.0.113.10:7777`
2. Authenticate with the password
3. Connect to local Minecraft server at `127.0.0.1:25565`
4. Forward all traffic bidirectionally
5. Auto-reconnect if connection drops

### On the VPS (public server)

Start the proxy server to accept tunnel and client connections:

```sh
srp serve <bind-addr:port> <password>
```

**Example:**
```sh
# Listen on all interfaces, port 25565 (for MC clients) and 7777 (for tunnel)
srp serve 0.0.0.0:7777 mysecretpassword
```

This will:
1. Listen for the tunnel connection (authenticated with password)
2. Accept Minecraft client connections on the same port
3. Bridge traffic between clients and the tunnel

**Important:** You need to run TWO instances on the VPS:
```sh
# Terminal 1: Accept tunnel connection (port 7777)
srp serve 0.0.0.0:7777 mysecretpassword

# Terminal 2: Accept Minecraft clients (port 25565) - only after tunnel is established
# Note: The current version handles both on the same port, but for production,
# you may want to modify to use separate ports for tunnel and clients
```

## Complete Setup Example

### Step 1: On your VPS (public IP: 203.0.113.10)
```sh
# Start the tunnel server
./srp serve 0.0.0.0:25565 mysecretpassword
```

### Step 2: On your home Minecraft server (behind NAT)
```sh
# Forward local MC server (port 25565) through the tunnel
./srp forward 25565 203.0.113.10:25565 mysecretpassword
```

### Step 3: Players connect to
```
203.0.113.10:25565
```

## Security Notes

- **Use a strong password** - This is your only authentication
- **Rate limiting** - After 3 failed auth attempts, IP is blocked for 60 seconds
- **Retry delay** - 1 second delay between authentication attempts
- **Timeout** - Auth must complete within 5 seconds

## Performance Tuning

The proxy is optimized for gaming with:
- `TCP_NODELAY` - Disables Nagle's algorithm for instant packet transmission
- Large socket buffers (256KB) - Handles burst traffic
- Efficient I/O multiplexing (select/epoll depending on platform)
- Zero-copy forwarding where possible

For even lower latency:
1. Use a VPS close to your players
2. Ensure the VPS has low latency to your home connection
3. Use a VPS with good peering/routing
4. Consider using a kernel with BBR congestion control

## Troubleshooting

**"Authentication failed"**
- Ensure passwords match exactly on both ends
- Check for typos or extra spaces

**"Connection refused"**
- Verify the VPS is running and port is open
- Check firewall rules (allow TCP on the specified port)
- Ensure Minecraft server is running locally

**"Rate limited"**
- Wait 60 seconds after failed authentication attempts
- Verify you're using the correct password

**High latency**
- Run `ping` tests to verify base latency
- Check VPS CPU usage (shouldn't be bottleneck)
- Ensure no packet loss on the route

## Architecture

```
[MC Client] <---> [VPS:srp serve] <---> [srp forward] <---> [MC Server]
                       ^                      ^
                       |                      |
                  Public IP            Behind NAT/Firewall
```

The tunnel is established from inside the NAT (forward mode), so no port forwarding is needed on your home network.

## License

Public Domain / MIT - Use however you want!
