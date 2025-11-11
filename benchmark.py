#!/usr/bin/env python3
"""
SRP Benchmark Script
Tests latency, throughput, packet rates, and data integrity through the reverse proxy
"""

import socket
import time
import threading
import statistics
import sys
import hashlib
import random

# Configuration
LOCAL_SERVER_PORT = 8000
VPS_CLIENT_PORT = 8080
NUM_REQUESTS = 1000
PAYLOAD_SIZE = 1024  # 1KB per request
CONCURRENT_CONNECTIONS = 10

class SimpleServer:
    """Simple echo server for testing"""
    def __init__(self, port):
        self.port = port
        self.running = False
        self.sock = None
        self.thread = None
        
    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        time.sleep(0.5)  # Give server time to start
        
    def _run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', self.port))
        self.sock.listen(5)
        print(f"✓ Test server listening on port {self.port}")
        
        while self.running:
            try:
                self.sock.settimeout(1.0)
                client, addr = self.sock.accept()
                threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()
            except socket.timeout:
                continue
            except:
                break
                
    def _handle_client(self, client):
        try:
            while True:
                data = client.recv(4096)
                if not data:
                    break
                client.sendall(data)  # Echo back
        except:
            pass
        finally:
            client.close()
            
    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()

def measure_latency(host, port, num_requests):
    """Measure round-trip latency with data integrity checking"""
    latencies = []
    integrity_errors = 0
    
    print(f"\n[Latency Test] Sending {num_requests} requests...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    
    # Warmup
    for _ in range(10):
        payload = str(random.randint(0, 999999)).encode().ljust(64, b'X')
        sock.sendall(payload)
        sock.recv(len(payload))
    
    # Actual test
    for i in range(num_requests):
        # Create unique payload with sequence number and checksum
        seq = str(i).zfill(8)
        data = f"{seq}:" + "X" * 50
        checksum = hashlib.md5(data.encode()).hexdigest()[:8]
        payload = f"{data}:{checksum}".encode()
        
        start = time.perf_counter()
        sock.sendall(payload)
        response = sock.recv(len(payload))
        end = time.perf_counter()
        
        if len(response) == len(payload):
            # Verify data integrity
            if response != payload:
                integrity_errors += 1
                print(f"  ✗ Integrity error at request {i + 1}")
            else:
                latency_ms = (end - start) * 1000
                latencies.append(latency_ms)
        else:
            integrity_errors += 1
            
        if (i + 1) % 100 == 0:
            print(f"  Progress: {i + 1}/{num_requests} (Errors: {integrity_errors})")
    
    sock.close()
    
    if integrity_errors > 0:
        print(f"  ⚠ Data integrity errors: {integrity_errors}/{num_requests} ({integrity_errors*100/num_requests:.2f}%)")
    else:
        print(f"  ✓ Data integrity: Perfect (0 errors)")
    
    return latencies

def measure_throughput(host, port, duration_seconds=10):
    """Measure throughput with data integrity checking"""
    total_bytes = 0
    integrity_errors = 0
    request_count = 0
    start_time = time.time()
    
    print(f"\n[Throughput Test] Running for {duration_seconds} seconds...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.settimeout(1.0)
    
    while time.time() - start_time < duration_seconds:
        try:
            # Create payload with checksum
            seq = str(request_count).zfill(16)
            data = seq + ("D" * (PAYLOAD_SIZE - 32))
            checksum = hashlib.md5(data.encode()).hexdigest()[:16]
            payload = (data + checksum).encode()
            
            sock.sendall(payload)
            response = sock.recv(len(payload))
            
            # Verify integrity
            if response != payload:
                integrity_errors += 1
            
            total_bytes += len(payload) + len(response)
            request_count += 1
            
            if request_count % 1000 == 0:
                print(f"  Progress: {request_count} requests, {integrity_errors} errors")
        except socket.timeout:
            continue
        except Exception as e:
            print(f"  Connection closed: {e}")
            break
    
    elapsed = time.time() - start_time
    sock.close()
    
    if integrity_errors > 0:
        print(f"  ⚠ Data integrity errors: {integrity_errors}/{request_count} ({integrity_errors*100/request_count:.2f}%)")
    else:
        print(f"  ✓ Data integrity: Perfect (0 errors)")
    
    return total_bytes, elapsed

def measure_concurrent(host, port, num_connections, requests_per_conn):
    """Measure performance with concurrent connections and data integrity"""
    results = []
    integrity_errors = [0] * num_connections
    
    def worker(conn_id):
        latencies = []
        errors = 0
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port))
            
            for i in range(requests_per_conn):
                # Create unique payload per connection and request
                data = f"C{conn_id:02d}R{i:04d}:" + "Y" * 230
                checksum = hashlib.md5(data.encode()).hexdigest()[:16]
                payload = (data + checksum).encode()
                
                start = time.perf_counter()
                sock.sendall(payload)
                response = sock.recv(len(payload))
                end = time.perf_counter()
                
                # Check integrity
                if response != payload:
                    errors += 1
                else:
                    latencies.append((end - start) * 1000)
            
            sock.close()
            results.append(latencies)
            integrity_errors[conn_id] = errors
        except Exception as e:
            print(f"Connection {conn_id} error: {e}")
    
    print(f"\n[Concurrent Test] {num_connections} connections, {requests_per_conn} requests each...")
    
    threads = []
    start = time.time()
    
    for i in range(num_connections):
        t = threading.Thread(target=worker, args=(i,))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
    
    elapsed = time.time() - start
    
    total_errors = sum(integrity_errors)
    if total_errors > 0:
        print(f"  ⚠ Data integrity errors: {total_errors}")
    elif results:  # Only print if we got results
        print(f"  ✓ Data integrity: Perfect (0 errors)")
    
    return results, elapsed

def print_results(test_name, latencies):
    """Print statistics"""
    if not latencies:
        print(f"\n{test_name}: No data collected")
        return
        
    print(f"\n{test_name}:")
    print(f"  Requests:     {len(latencies)}")
    print(f"  Min:          {min(latencies):.3f} ms")
    print(f"  Max:          {max(latencies):.3f} ms")
    print(f"  Mean:         {statistics.mean(latencies):.3f} ms")
    print(f"  Median:       {statistics.median(latencies):.3f} ms")
    print(f"  Std Dev:      {statistics.stdev(latencies) if len(latencies) > 1 else 0:.3f} ms")
    
    # Percentiles
    sorted_lat = sorted(latencies)
    p50 = sorted_lat[len(sorted_lat) * 50 // 100]
    p95 = sorted_lat[len(sorted_lat) * 95 // 100]
    p99 = sorted_lat[len(sorted_lat) * 99 // 100]
    print(f"  P50:          {p50:.3f} ms")
    print(f"  P95:          {p95:.3f} ms")
    print(f"  P99:          {p99:.3f} ms")

def main():
    print("=" * 60)
    print("SRP Reverse Proxy Benchmark")
    print("=" * 60)
    
    # Start test server
    server = SimpleServer(LOCAL_SERVER_PORT)
    server.start()
    
    try:
        # Wait for proxy to be ready
        print("\nWaiting for proxy to be ready...")
        time.sleep(2)
        
        # Test connection
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(2)
            test_sock.connect(('127.0.0.1', VPS_CLIENT_PORT))
            test_sock.close()
            print("✓ Proxy connection successful")
        except Exception as e:
            print(f"✗ Cannot connect to proxy on port {VPS_CLIENT_PORT}")
            print(f"  Error: {e}")
            print("\nMake sure both server and forward agent are running:")
            print(f"  Server:  ./srp serve 0.0.0.0:{VPS_CLIENT_PORT} 0.0.0.0:1234 bing")
            print(f"  Forward: ./srp forward {LOCAL_SERVER_PORT} 127.0.0.1:1234 bing")
            return
        
        # Run benchmarks
        print("\n" + "=" * 60)
        
        # 1. Latency test
        latencies = measure_latency('127.0.0.1', VPS_CLIENT_PORT, NUM_REQUESTS)
        print_results("Latency Test (Round-trip through proxy)", latencies)
        
        # 2. Throughput test
        total_bytes, elapsed = measure_throughput('127.0.0.1', VPS_CLIENT_PORT, 10)
        throughput_mbps = (total_bytes * 8) / (elapsed * 1_000_000)
        print(f"\nThroughput Test:")
        print(f"  Total bytes:  {total_bytes:,} bytes")
        print(f"  Duration:     {elapsed:.2f} seconds")
        print(f"  Throughput:   {throughput_mbps:.2f} Mbps")
        print(f"  Requests/sec: {(total_bytes / PAYLOAD_SIZE / 2) / elapsed:.0f}")
        
        # 3. Concurrent connections test
        results, elapsed = measure_concurrent('127.0.0.1', VPS_CLIENT_PORT, CONCURRENT_CONNECTIONS, 100)
        all_latencies = [lat for conn_lats in results for lat in conn_lats]
        total_reqs = len(all_latencies)
        print_results(f"Concurrent Test ({CONCURRENT_CONNECTIONS} connections)", all_latencies)
        print(f"  Total time:   {elapsed:.2f} seconds")
        print(f"  Requests/sec: {total_reqs / elapsed:.0f}")
        
        print("\n" + "=" * 60)
        print("Benchmark Complete!")
        print("=" * 60)
        
    finally:
        server.stop()

if __name__ == '__main__':
    main()
