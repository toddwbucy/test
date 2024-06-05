#!/bin/bash

# Set initial variables
PLATFORM_KEY="rhel"
TERM=xterm

# Check the OS version and update RELEASE_VERSION and package manager
if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [[ $ID == "rhel" ]]; then
        MAJOR_VERSION=$(echo $VERSION_ID | cut -d. -f1)
        if [[ $MAJOR_VERSION == "7" ]]; then
            RELEASE_VERSION="7"
            PKG_MANAGER="yum"
        elif [[ $MAJOR_VERSION == "8" ]]; then
            RELEASE_VERSION="8"
            PKG_MANAGER="yum"
        elif [[ $MAJOR_VERSION == "9" ]]; then
            RELEASE_VERSION="9"
            PKG_MANAGER="dnf"
        else
            echo "Unsupported RHEL major version: $MAJOR_VERSION"
            exit 1
        fi
    else
        echo "This script is only supported on RHEL."
        exit 1
    fi
else
    echo "/etc/os-release file not found."
    exit 1
fi

# Import the RPM key
sudo rpm --import https://dist.scaleft.com/GPG-KEY-OktaPAM-2023

# Create the yum repository file
cat <<EOL | sudo tee /etc/yum.repos.d/oktapam-stable.repo
[oktapam-stable]
name=Okta PAM Stable - $PLATFORM_KEY $RELEASE_VERSION
baseurl=https://dist.scaleft.com/repos/rpm/stable/$PLATFORM_KEY/$RELEASE_VERSION/\$basearch
gpgcheck=1
repo_gpgcheck=1
enabled=1
gpgkey=https://dist.scaleft.com/GPG-KEY-OktaPAM-2023
EOL

# Remove the old scaleft repo
sudo rm -f /etc/yum.repos.d/scaleft.repo

# Clean the package manager cache
sudo $PKG_MANAGER clean all

# Re-import the GPG key
sudo rpm --import https://dist.scaleft.com/GPG-KEY-OktaPAM-2023

# Update the package cache and accept the new GPG key with -y option
sudo $PKG_MANAGER makecache -y

# Print a message indicating the script has finished
echo "Advanced Server Access server agent repository has been added and cache updated."
