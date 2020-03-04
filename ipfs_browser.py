import sqlite3

class file:
    def __init__(self, operation, h, filename):
        self.operation = operation
        self.h = h
        self.filename = filename

connection = sqlite3.connect("D:/bismuth/static/ledger.db")
cursor = connection.cursor()

cursor.execute("SELECT * FROM transactions WHERE operation = ?", ("ipfs",))
results = cursor.fetchall()

print(results)
print(len(results))

files = []
for result in results:
    print(result[11])
    split = result[11].split(",")
    files.append(file(split[0].split("=")[1], split[1].split("=")[1], split[2].split("=")[1]))


for file in files:
    print(file.operation)
    print(file.h)
    print(file.filename)