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
