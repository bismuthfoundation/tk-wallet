import subprocess
import os
import json
import glob


def init():
    command_line = "ipfs init"
    pipe = subprocess.Popen(command_line, shell=True, stdout=subprocess.PIPE).stdout
    output = pipe.read().decode()
    pipe.close()

    return output


def store(file):
    command_line = f"ipfs add {file}"
    pipe = subprocess.Popen(command_line, shell=True, stdout=subprocess.PIPE).stdout
    output = pipe.read().decode()
    pipe.close()

    returned = output.split()
    result = {"operation": returned[0], "hash": returned[1], "filename": returned[2]}
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
    if os.path.exists("stored"):
        found = glob.glob("stored/*")

        for entry in found:
            with open(entry) as infile:
                contents = json.loads(infile.read())
                yield (contents)


def seek_local(file):
    if os.path.exists("stored"):
        with open(f"stored/{file}.json") as infile:
            return json.loads(infile.read())

def save(data):
    if not os.path.exists("stored"):
        os.mkdir("stored")

    with open(f'stored/{data["hash"]}.json', "w") as infile:
        infile.write(json.dumps(data))


if __name__ == "__main__":
    print(init())
    store = store("test.txt")
    print(store)
    save(store)

    for entry in show_all():
        print(entry)

    print(seek_local("QmWfVY9y3xjsixTgbd9AorQxH7VtMpzfx2HaWtsoUYecaX"))

    get("QmWfVY9y3xjsixTgbd9AorQxH7VtMpzfx2HaWtsoUYecaX", "test.txt")
