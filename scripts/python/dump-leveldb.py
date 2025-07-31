# pre-requisites:
#   sudo apt install python3-plyvel

import sys
import plyvel

# Check if a command-line argument was provided
if len(sys.argv) < 2:
    print(f"Usage: python3 {sys.argv[0]} /path/to/leveldb_directory")
    sys.exit(1)

# Get the database path from the first argument
db_path = sys.argv[1]

try:
    db = plyvel.DB(db_path, create_if_missing=False)
    print(f"--- Dumping keys and values from {db_path} ---")

    count = 0
    # Use 'iterator(include_value=False)' if you only need keys
    for key, value in db.iterator():
        # Use .hex(sep=' ') to format the hex output with spaces
        key_hex = key.hex(sep=' ')
        value_hex = value.hex(sep=' ')
        
        print(f"Key: {key_hex}\nValue: {value_hex}\n")
        count += 1
    
    print(f"--- Found {count} total keys ---")

    db.close()

except Exception as e:
    print(f"An error occurred: {e}")
    sys.exit(1)
