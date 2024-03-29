import sqlite3

class file:
    def __init__(self, operation, h, filename):
        self.operation = operation
        self.h = h
        self.filename = filename

def connect_to_database(db_path):
    """Establish a connection to the SQLite database."""
    connection = sqlite3.connect(db_path)
    return connection

def fetch_transactions(connection):
    """Fetch IPFS transactions from the database."""
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM transactions WHERE operation = ?", ("ipfs",))
    results = cursor.fetchall()
    return results

def parse_transaction_to_file(transaction):
    """Parse a transaction record into a File object."""
    split = transaction.split(",")
    return file(split[0].split("=")[1], split[1].split("=")[1], split[2].split("=")[1])

def extract_files_from_transactions(transactions):
    """Extract and return File objects from transaction records."""
    files = []
    for transaction in transactions:
        file_info = parse_transaction_to_file(transaction[11])
        files.append(file_info)
    return files

def main():
    db_path = "D:/bismuth/static/ledger.db"
    connection = connect_to_database(db_path)
    
    try:
        transactions = fetch_transactions(connection)
        print(f"Total transactions found: {len(transactions)}")
        
        files = extract_files_from_transactions(transactions)
        
        for f in files:
            print(f.operation, f.h, f.filename)
            
    finally:
        connection.close()

if __name__ == "__main__":
    main()