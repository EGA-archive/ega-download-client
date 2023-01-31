import hashlib
import subprocess


def run(command: str, input: str = None, verbose: bool = True):
    parsed_command = command.split(' ')
    proc = subprocess.Popen(parsed_command,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            )
    if input:
        stdout, stderr = proc.communicate(input.encode())
    else:
        stdout, stderr = proc.communicate()

    if verbose:
        print('$ ' + command)
        print(stdout.decode())
        print(stderr.decode())

    return proc.returncode, stdout.decode(), stderr.decode()


def md5(filepath):
    hash_md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        chunk_size_in_bytes = 4096
        for chunk in iter(lambda: f.read(chunk_size_in_bytes), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()