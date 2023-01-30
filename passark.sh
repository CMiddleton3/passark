#!/bin/bash

# Check if no arguments were passed
if [ $# -eq 0 ]; then
  echo "Error: No arguments passed."
  echo "Usage: "
  python3 passark.py --help
  exit 1
fi

# Pass all arguments to the Python script
python3 passark.py "$@"