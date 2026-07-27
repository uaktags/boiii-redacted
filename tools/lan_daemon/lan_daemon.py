#!/usr/bin/env python3
"""
BOIII Standalone LAN Lobby Daemon Utility
-----------------------------------------
A lightweight, zero-dependency LAN lobby coordinator and server-query daemon.
Listens for 'getInfo' UDP queries and coordinates LAN pre-game party staging.
"""

import socket
import sys
import threading
import time

DEFAULT_PORT = 27017
PROTOCOL = 1
SUB_PROTOCOL = 1

class LANLobbyDaemon:
    def __init__(self, port=DEFAULT_PORT, hostname="BOIII LAN Lobby", mapname="zm_factory", gametype="zclassic"):
        self.port = port
        self.hostname = hostname
        self.mapname = mapname
        self.gametype = gametype
        self.max_clients = 4
        self.clients = {}  # addr -> dict(name, ready, joined_at)
        self.state = "pregame"  # 'pregame' or 'active'
        self.running = True
        self.sock = None

    def start_server(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("0.0.0.0", self.port))
            print(f"[LAN Daemon] Started listening on 0.0.0.0:{self.port}")
            print(f"[LAN Daemon] Pre-game Lobby Host: '{self.hostname}' | Map: '{self.mapname}'")
        except Exception as e:
            print(f"[LAN Daemon] Error binding socket on port {self.port}: {e}")
            sys.exit(1)

        # Network listener thread
        listener = threading.Thread(target=self._listen_loop, daemon=True)
        listener.start()

        # CLI Loop
        self._cli_loop()

    def _listen_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(2048)
                if not data:
                    continue
                self._handle_packet(data, addr)
            except Exception:
                pass

    def _handle_packet(self, data, addr):
        # Handle connectionless command header \xff\xff\xff\xff
        if data.startswith(b'\xff\xff\xff\xff'):
            payload = data[4:]
            try:
                text = payload.decode('utf-8', errors='ignore')
            except Exception:
                return

            if text.startswith("getInfo"):
                challenge = text.split(" ")[1] if " " in text else ""
                self._send_info_response(addr, challenge)
            elif text.startswith("connect"):
                # Register client in pre-game lobby
                client_name = f"Player_{addr[0]}:{addr[1]}"
                self.clients[addr] = {"name": client_name, "ready": False, "joined": time.time()}
                print(f"\n[LAN Daemon] Player joined LAN lobby: {addr[0]}:{addr[1]}")

    def _send_info_response(self, addr, challenge):
        info_str = (
            f"\\challenge\\{challenge}"
            f"\\gamename\\T7"
            f"\\hostname\\{self.hostname}"
            f"\\gametype\\{self.gametype}"
            f"\\mapname\\{self.mapname}"
            f"\\isPrivate\\0"
            f"\\clients\\{len(self.clients)}"
            f"\\bots\\0"
            f"\\sv_maxclients\\{self.max_clients}"
            f"\\protocol\\{PROTOCOL}"
            f"\\sub_protocol\\{SUB_PROTOCOL}"
            f"\\playmode\\2"
            f"\\gamemode\\1"
            f"\\sv_running\\0"
            f"\\lobby_state\\{self.state}"
            f"\\dedicated\\0"
        )
        response = b'\xff\xff\xff\xffinfoResponse\n' + info_str.encode('utf-8')
        self.sock.sendto(response, addr)

    def _cli_loop(self):
        print("\nLAN Lobby Daemon CLI Commands:")
        print("  status        - Show connected LAN players and lobby state")
        print("  map <name>    - Change pre-game map (e.g., zm_factory, zm_castle)")
        print("  start         - Trigger match launch for all LAN lobby members")
        print("  quit          - Exit daemon\n")

        while self.running:
            try:
                cmd = input("lan-daemon> ").strip()
                if not cmd:
                    continue

                parts = cmd.split()
                action = parts[0].lower()

                if action == "status":
                    print(f"Lobby Host: {self.hostname} | Map: {self.mapname} | State: {self.state}")
                    print(f"Connected Players ({len(self.clients)}/{self.max_clients}):")
                    for addr, info in self.clients.items():
                        ready_str = "READY" if info["ready"] else "NOT READY"
                        print(f"  - {info['name']} ({addr[0]}:{addr[1]}) [{ready_str}]")
                elif action == "map":
                    if len(parts) > 1:
                        self.mapname = parts[1]
                        print(f"[LAN Daemon] Map set to '{self.mapname}'")
                    else:
                        print("Usage: map <mapname>")
                elif action == "start":
                    self.state = "active"
                    print("[LAN Daemon] Launching match! Notifying LAN clients to join...")
                elif action == "quit" or action == "exit":
                    print("[LAN Daemon] Shutting down...")
                    self.running = False
                else:
                    print(f"Unknown command '{cmd}'. Type status, map, start, or quit.")
            except (KeyboardInterrupt, EOFError):
                self.running = False
                break

if __name__ == "__main__":
    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            pass

    daemon = LANLobbyDaemon(port=port)
    daemon.start_server()
