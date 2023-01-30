#!/bin/bash

echo "This Setup will Copy mkpass to yoru bin folder to make it usable system wide"

# Prompt to continue
read -p "Do you want to continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "No changes have been made. exiting"
  exit 0
fi

echo "Moving mkpass to User bin folder"
# Copy the mkpass file to the home folder
cp mkpass "${HOME}"/bin/

# Replace {{passark_path}} with the current directory
sed -i 's|{{passark_path}}|'"$(pwd)"'|g' "${HOME}"/bin/mkpass

echo "adding execute permissions for mkpass"
# Add execute permissions for the file
chmod +x "${HOME}"/bin/mkpass
echo ""
echo "Done!"