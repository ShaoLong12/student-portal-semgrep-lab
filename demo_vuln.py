import hashlib
import subprocess


def run(cmd):
    return subprocess.call(cmd, shell=True)


def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()
