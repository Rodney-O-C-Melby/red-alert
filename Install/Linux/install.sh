#!/bin/bash
system=""

# run command piping errors to null
sudo pacman --noconfirm -S exploitdb python3 python-pip nmap sqlite3 2>/dev/null
# if last command was successfull then do.
if [ $? -eq 0 ]; then
    system="Package Manager: pacman"
fi
sudo apt-get -y install exploitdb python3 python3-pip nmap sqlite3 2>/dev/null
if [ $? -eq 0 ]; then
    system="Package Manager: apt-get"
fi
sudo brew install exploitdb python3 python3-pip nmap sqlite3 2>/dev/null
if [ $? -eq 0 ]; then
    system="Package Manager: Homebrew"
fi

# give user cap permissions to run nmap without sudo
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
if [ $? -eq 0 ]; then
  echo "Granted ${USER} the rights to use nmap without sudo."
else
  echo "Failed to setcap for ${USER} on nmap. Use sudo or root."
fi
# install pip requirements
pip install -r "${PWD}/Install/Linux/requirements.txt"

# user owns all files, and execute permission to 
sudo chown -R $USER:$USER "${PWD}"
sudo chmod +x "${PWD}/redalert"

# Instructions to add to PATH
echo ""
echo "RUN THE BELOW COMMAND IN TERMINAL TO ADD THIS PROGRAM TO THE PATH ENVIROMENT VARIABLE."
echo ""
echo "echo 'export PATH=\${PATH}:${PWD}' >> ~/.bashrc"
echo ""
echo "OR RUN DIRECTLY FROM THIS DIRECTORY!"

# echo package manager
echo ""
echo "${system}"
