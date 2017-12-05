import subprocess


def execute_cmd(cmd, text=None):
    # subprocess.run came in version 3.5
    proc = subprocess.Popen(
        cmd,
        shell=False,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stdin=None if text is None else subprocess.PIPE,
    )
    if text is None:
        stdout, stderr = proc.communicate()
    else:
        stdout, stderr = proc.communicate(input=text.encode())

    if proc.returncode == 0:
        return True, stdout.decode()
    else:
        return False, stderr.decode()
