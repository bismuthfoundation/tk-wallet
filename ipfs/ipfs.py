import subprocess


def init():
    command_line = "ipfs init"
    pipe = subprocess.Popen(
        command_line, shell=True, stdout=subprocess.PIPE
    ).stdout
    output = pipe.read().decode()
    pipe.close()

    return output

def store(file):
    command_line = f"ipfs add {file}"
    pipe = subprocess.Popen(
        command_line, shell=True, stdout=subprocess.PIPE
    ).stdout
    output = pipe.read().decode()
    pipe.close()

    returned = output.split()
    result = {"operation": returned[0],
              "hash": returned[1],
              "filename": returned[2]}
    return result

if __name__ == "__main__":
    print(init())
    print(store("test.txt"))
