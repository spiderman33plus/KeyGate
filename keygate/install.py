"""
KeyGate -- Script de instalacion
Author: Victor Martin Sotoca
License: Apache 2.0
"""
import subprocess, sys, os

DEPS = ["cryptography"]

def run(cmd):
    subprocess.run(cmd, check=True)

print("KeyGate -- Instalacion")
print("=" * 40)

print("Instalando dependencias...")
run([sys.executable, "-m", "pip", "install", "--break-system-packages", "-q"] + DEPS)
print("Dependencias instaladas.\n")

kg_server = os.path.abspath("server/server.py")
kg_client = os.path.abspath("client/client.py")

print("Para usar KeyGate facilmente, añade estos aliases a tu shell:\n")
print(f'  alias kg-server="python3 {kg_server}"')
print(f'  alias kg="python3 {kg_client}"')
print()
print("Empezar:\n")
print("  1. En tu PC (servidor):")
print(f"     python3 {kg_server} token create")
print(f"     python3 {kg_server} start\n")
print("  2. En el PC que se conecta (cliente):")
print(f"     python3 {kg_client} --host TU_IP --token kg_xxx ping\n")
