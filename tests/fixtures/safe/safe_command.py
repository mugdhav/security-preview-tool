"""Must-NOT-detect: argument vector, no shell."""
import shlex
import subprocess


def ping(host):
    subprocess.run(["ping", "-c", "1", host], shell=False)


def run_cmd(name):
    subprocess.run(shlex.split(name), shell=False)
