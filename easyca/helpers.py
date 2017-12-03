import subprocess


def execute_cmd(cmd):
    # subprocess.run came in version 3.5
    proc = subprocess.Popen(
        cmd,
        shell=False,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE
    )
    stdout, stderr = proc.communicate()

    if proc.returncode == 0:
        return True, stdout.decode()
    else:
        return False, stderr.decode()
