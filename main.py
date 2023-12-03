import sys, os
import rsa, oaep

def usage() -> None:
    print("python3 main.py <command>")
    print()
    print("command:")
    print("     generate_keys <key_size> <prefix_path>")
    print("     encrypt <public_key_path> <private_key_path>")
    print("     decrypt <private_key_path> <public_key_path>")
    print()
    print("Note that the decrypt command also verifies the signature of the cypher, displaying an error message if it fails to do so.")
    print()
    print("Examples:")
    print("""
    python3 main.py generate_keys 2048 sender_

    python3 main.py generate_keys 2048 receiver_

    cat rsa_example.txt 
    | python3 main.py encrypt sender_private_key.rsa receiver_public_key.rsa

    cat rsa_example.txt 
    | python3 main.py encrypt sender_private_key.rsa receiver_public_key.rsa 
    | python3 main.py decrypt receiver_private_key.rsa sender_public_key.rsa
    """)
    print()

def next_arg(args: list[str]) -> str:
    if len(args) == 0:
        usage()
        exit(1)
    argument = args[0]
    args.pop(0)
    return argument

def arg_is_empty(args: list[str]) -> bool:
    return len(args) == 0

def read_from_stdin() -> str:
    text = open(0).read()
    return text

def print_to_stdout(*a) -> None:
    print(*a, file=sys.stdout, end="")

def main() -> None:
    args = sys.argv
    program = next_arg(args)
    command = next_arg(args)

    if command == "generate_keys":
        key_size = 2048
        prefix_path = ""
        if not arg_is_empty(args):
            key_size = int(next_arg(args))

        if not arg_is_empty(args):
            prefix_path = next_arg(args)

        public_key, private_key = rsa.create_key(key_size)
        public_key_str = f"{public_key.mod} {public_key.key}"
        private_key_str = f"{private_key.mod} {private_key.key}"
        with open(prefix_path + "public_key.rsa", "w") as f:
            f.write(public_key_str)
        with open(prefix_path + "private_key.rsa", "w") as f:
            f.write(private_key_str)
        print_to_stdout(f"Public key save in {prefix_path + 'public_key.rsa'}\n")
        print_to_stdout(f"Private key save in {prefix_path + 'private_key.rsa'}\n")

    elif command == "encrypt":
        sender_private_key_path = next_arg(args)
        receiver_public_key_path = next_arg(args)
        sender_private_key = rsa.read_key(sender_private_key_path)
        receiver_public_key = rsa.read_key(receiver_public_key_path)

        text = bytes(read_from_stdin(), "utf-8")
        oaep_len = receiver_public_key.mod.bit_length() // 8
        text_oaep = int.from_bytes(oaep.encode(text, oaep_len), "big")
        cypher, sign = rsa.encrypt_and_sign(text_oaep, sender_private_key, receiver_public_key)
        print_to_stdout(f"{cypher} {sign}")

    elif command == "decrypt":
        if len(args) < 2:
            usage()
            exit(1)

        receiver_private_key_path = next_arg(args)
        sender_public_key_path = next_arg(args)

        receiver_private_key = rsa.read_key(receiver_private_key_path)
        sender_public_key = rsa.read_key(sender_public_key_path)

        txt = read_from_stdin()
        cypher, sign = [int(t) for t in txt.split(" ")]
        verify, msg = rsa.decrypt_message_and_verify(cypher, sign, receiver_private_key, sender_public_key)

        if (not verify):
            print_to_stdout("Failed to verify message\n")
            exit(1)

        oaep_len = receiver_private_key.mod.bit_length() // 8
        msg_decoded = oaep.decode(msg.to_bytes(oaep_len, "big"), oaep_len)
        print_to_stdout(str(msg_decoded, "utf-8"))

    else:
        usage()
        exit(1)


if __name__ == "__main__":
    main()
