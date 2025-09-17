#!/usr/bin/env python3

import os
import sys

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <filename> <directory>", file=sys.stderr)
        sys.exit(1)

    filename, directory = sys.argv[1], sys.argv[2]

    os.makedirs(directory, exist_ok=True)
    filepath = os.path.join(directory, f"{filename}.block")

    # create the file if it doesn't exist, update timestamp if it does
    with open(filepath, "a"):
        os.utime(filepath, None)

    return 0

if __name__ == "__main__":
    sys.exit(main())
