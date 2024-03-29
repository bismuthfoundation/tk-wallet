#  offline mode of ipfs, no daemon, cli access

import subprocess
import os
import json
import glob
import platform

def is_windows():
    return "Windows" in platform.system()


def init():
    acceptable = ["Error: ipfs configuration file already exists!", "initializing IPFS node at"]
    command_line = "ipfs init"
    
    try:
        # Using 'with' ensures that resources are cleaned up promptly
        with subprocess.Popen(command_line, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            # It's a good practice to capture both stdout and stderr
            stdout, stderr = process.communicate()  # This waits for the subprocess to finish
            
            # Decoding to convert bytes to string for easier handling
            output = stdout.decode()
            error = stderr.decode()

            # Error handling: Check if there was an error during the execution
            if process.returncode != 0:
                print(f"Command failed with error: {error}")
                return False

            # Checking for acceptable phrases in the output
            for entry in acceptable:
                if entry in output:
                    return output

    except subprocess.CalledProcessError as e:
        print(f"An error occurred while initializing IPFS: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False

    # If none of the acceptable entries were found in the output
    else:
        return False


def store(file):
    command_line = f'ipfs add "{file}"'
    print(command_line)
    
    try:
        # Use 'with' for resource management and to ensure the subprocess is properly cleaned up
        with subprocess.Popen(command_line, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            # Communicate with the process to read its output and wait for it to terminate
            stdout, stderr = process.communicate()
            
            # Check for errors in execution
            if process.returncode != 0:
                # Decoding stderr to provide a meaningful error message
                error_message = stderr.decode()
                print(f"Command failed with error: {error_message}")
                return {"error": error_message}

            # Decoding stdout since we have confirmed the command was successful
            output = stdout.decode()

    except subprocess.CalledProcessError as e:
        print(f"An error occurred while adding the file to IPFS: {e}")
        return {"error": str(e)}
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return {"error": str(e)}
    
    # Assuming the command always prints the expected output format on success
    returned = output.split()
    # Protect against index errors by checking the length of returned
    if len(returned) >= 3:
        result = {"operation": returned[0], "hash": returned[1], "filename": " ".join(returned[2:])}
    else:
        result = {"error": "Unexpected output format."}

    return result

def get(hash, filename):
    # Ensure the directory 'downloaded' exists
    os.makedirs("downloaded", exist_ok=True)

    command_line = f"ipfs get {hash} --output=downloaded/{filename}"
    
    try:
        # Use 'with' for proper cleanup of subprocess resources
        with subprocess.Popen(command_line, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            stdout, stderr = process.communicate()  # Wait for command to complete
            
            # Check for subprocess errors
            if process.returncode != 0:
                error_message = stderr.decode()
                print(f"Command failed with error: {error_message}")
                return {"error": error_message}

            # If command succeeds, decode stdout (though ipfs get might not use it)
            output = stdout.decode()

    except subprocess.CalledProcessError as e:
        print(f"An error occurred while retrieving the file from IPFS: {e}")
        return {"error": str(e)}
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return {"error": str(e)}

    # Assuming 'ipfs get' does not produce a meaningful stdout for parsing
    # and since the operation is simply to retrieve a file, success can
    # be assumed from a lack of errors.
    return output.split()

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
