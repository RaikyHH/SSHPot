#!/usr/bin/env python3
"""
Generate SSH host key for the honeypot.
"""

import paramiko

def generate_host_key(filename='ssh_host_rsa_key'):
    """Generate RSA host key for SSH server."""
    print(f"Generating RSA host key: {filename}")

    # Generate RSA key
    key = paramiko.RSAKey.generate(2048)

    # Save private key
    key.write_private_key_file(filename)
    print(f"Private key saved to: {filename}")

    # Print public key
    print(f"Public key fingerprint: {key.get_fingerprint().hex()}")
    print(f"Key generated successfully!")

if __name__ == "__main__":
    generate_host_key()
