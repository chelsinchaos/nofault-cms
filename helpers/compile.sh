#!/bin/bash

# Function to detect the OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="Linux"
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            DISTRO=$ID
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macOS"
        DISTRO="macOS"
    else
        echo "Unsupported OS: $OSTYPE"
        exit 1
    fi
}

# Function to detect CPU architecture
detect_arch() {
    ARCH=$(uname -m)
}

# Function to install dependencies on macOS
install_dependencies_macos() {
    echo "Installing dependencies for macOS..."
    # Install Homebrew if not installed
    if ! command -v brew &> /dev/null; then
        echo "Homebrew not found. Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    # Install dependencies
    brew install openssl docker wireguard-tools
}

# Function to install dependencies on Debian-based systems
install_dependencies_debian() {
    echo "Installing dependencies for Debian-based system..."
    sudo apt-get update
    sudo apt-get install -y build-essential libssl-dev libcrypto++-dev docker.io wireguard
}

# Function to install dependencies on CentOS
install_dependencies_centos() {
    echo "Installing dependencies for CentOS..."
    sudo yum install -y gcc gcc-c++ openssl-devel docker wireguard-tools
}

# Function to install dependencies on Fedora
install_dependencies_fedora() {
    echo "Installing dependencies for Fedora..."
    sudo dnf install -y gcc gcc-c++ openssl-devel docker wireguard-tools
}

# Function to compile the script
compile_script() {
    echo "Compiling the script..."
    g++ -std=c++11 -O2 -o script script.cpp -lcrypto -lssl -ldl
    if [ $? -ne 0 ]; then
        echo "Compilation failed."
        exit 1
    fi
}

# Function to encrypt the executable
encrypt_executable() {
    echo "Encrypting the executable..."
    openssl enc -aes-256-cbc -in script -out script.enc -k your_secret_key
    if [ $? -ne 0 ]; then
        echo "Encryption failed."
        exit 1
    fi
}

# Function to create self-extracting executable
create_self_extracting_executable() {
    echo "Creating self-extracting executable..."
    {
        echo '#!/bin/bash'
        echo 'openssl enc -aes-256-cbc -d -in <(tail -n +4 "$0") -out script_decrypted -k your_secret_key'
        echo 'chmod +x script_decrypted'
        echo './script_decrypted'
        echo 'exit 0'
    } > script
    cat script.enc >> script
    chmod +x script
}

# Main script execution
detect_os
detect_arch

echo "Operating System: $OS"
echo "Distribution: $DISTRO"
echo "Architecture: $ARCH"

case "$OS" in
    "macOS")
        install_dependencies_macos
        ;;
    "Linux")
        case "$DISTRO" in
            "ubuntu"|"debian"|"kali"|"tails")
                install_dependencies_debian
                ;;
            "centos")
                install_dependencies_centos
                ;;
            "fedora")
                install_dependencies_fedora
                ;;
            *)
                echo "Unsupported Linux distribution: $DISTRO"
                exit 1
                ;;
        esac
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

compile_script
encrypt_executable
create_self_extracting_executable

echo "Setup complete. You can now run './script' to execute the program."
