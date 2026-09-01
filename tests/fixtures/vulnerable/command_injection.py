"""Must-detect: user input reaches a shell."""
import os
import subprocess


def ping(host):
    os.system("ping -c 1 " + host)


def backup(name):
    subprocess.Popen(f"tar czf {name}.tgz /data", shell=True)
