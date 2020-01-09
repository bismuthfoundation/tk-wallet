#  offline mode of ipfs, no daemon, cli access

import subprocess
import os
import json
import glob
import platform

def is_windows():
    if "Windows" in platform.system():
        return True
    else:
        return False

def init():
    acceptable = ["Error: ipfs configuration file already exists!", "initializing IPFS node at"]

    command_line = "ipfs init"
    pipe = subprocess.Popen(command_line, shell=True, stdout=subprocess.PIPE).stdout
    output = pipe.read().decode()
    pipe.close()

    for entry in acceptable:
        if entry in output:
            return output
    else:
        return False


def store(file):
    command_line = f'ipfs add "{file}"'
    print(command_line)
    pipe = subprocess.Popen(command_line, shell=True, stdout=subprocess.PIPE).stdout
    output = pipe.read().decode()
    pipe.close()

    returned = output.split()
    result = {"operation": returned[0], "hash": returned[1], "filename": " ".join(returned[2:])}
    return result

def get(hash, filename):
    if not os.path.exists("downloaded"):
        os.mkdir("downloaded")

    command_line = f"ipfs get {hash} --output=downloaded/{filename}"
    pipe = subprocess.Popen(command_line, shell=True, stdout=subprocess.PIPE).stdout
    output = pipe.read().decode()
    pipe.close()

    result = output.split()
    #result = {"operation": returned[0], "hash": returned[1], "filename": returned[2]}
    return result

def show_all():
    if os.path.exists("references"):
        found = glob.glob("references/*")

        for entry in found:
            with open(entry) as infile:
                contents = json.loads(infile.read())
                yield (contents)


def seek_local_hash(hash):
    if os.path.exists("references"):
        with open(f"references/{hash}.json") as infile:
            return json.loads(infile.read())

def seek_local_file(file):
    if os.path.exists("references"):
        found = glob.glob("references/*")
        for entry in found:
            with open(entry) as infile:
                contents = json.loads(infile.read())
                if contents["filename"] == file:
                    return os.path.basename(entry)

def save_local(data):
    if not os.path.exists("ipfs/references"):
        os.mkdir("ipfs/references")

    with open(f'ipfs/references/{data["hash"]}.json', "w") as infile:
        infile.write(json.dumps(data))


if __name__ == "__main__":
    print(init())
    store = store("test.txt")
    print(store)
    save_local(store)

    for entry in show_all():
        print(entry)

    print(seek_local_file("test.txt"))

    sought = seek_local_hash("QmWfVY9y3xjsixTgbd9AorQxH7VtMpzfx2HaWtsoUYecaX")
    print(sought)

    get(sought["hash"], sought["filename"])
