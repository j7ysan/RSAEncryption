import argparse
from key_manager import (
    generate_keys,
    encrypt_file,
    decrypt_file,
    verify_data_key_with_rsa,
)

def main():
    parser = argparse.ArgumentParser(description="Lab 2: Key Management Toolkit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("gen-keys", help="Generate RSA keys and initial data key")
    enc = subparsers.add_parser("encrypt", help="Encrypt sample data with current data key")
    enc.add_argument("--infile", default="data/plain.txt", help="Input file to encrypt")
    enc.add_argument("--outfile", default="data/cipher.bin", help="Output encrypted file")
    dec = subparsers.add_parser("decrypt", help="Decrypt sample data with current data key")
    dec.add_argument("--infile", default="data/cipher.bin", help="Encrypted file to decrypt")
    dec.add_argument("--outfile", default="data/decrypted.txt", help="Output plaintext file")
    subparsers.add_parser("verify", help="Verify (encrypt) current data key with RSA public key")
    subparsers.add_parser("output", help="Output (response) of the digital signature after RSA encryption")
    args = parser.parse_args()

    if args.command == "gen-keys":
        generate_keys()
    elif args.command == "encrypt":
        encrypt_file(args.infile, args.outfile)
    elif args.command == "decrypt":
        decrypt_file(args.infile, args.outfile)
    elif args.command == "verify":
        verify_data_key_with_rsa()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()