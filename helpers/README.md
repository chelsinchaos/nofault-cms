# README

## Compiling the C++ Script into an Encrypted Self-Extracting Executable

This guide provides step-by-step instructions for compiling the provided C++ script into an encrypted self-extracting executable on various platforms, including macOS with an M1 Max chip and several Linux distributions for both x86 and ARM architectures.

---

### Table of Contents

- [Prerequisites](#prerequisites)
- [Compiling on macOS with M1 Max Chip](#compiling-on-macos-with-m1-max-chip)
- [Compiling on Linux Distributions](#compiling-on-linux-distributions)
  - [Ubuntu (x86 and ARM)](#ubuntu-x86-and-arm)
  - [CentOS (x86 and ARM)](#centos-x86-and-arm)
  - [Fedora (x86 and ARM)](#fedora-x86-and-arm)
  - [Kali Linux (x86 and ARM)](#kali-linux-x86-and-arm)
  - [Tails OS (x86 and ARM)](#tails-os-x86-and-arm)
  - [Debian (x86 and ARM)](#debian-x86-and-arm)
- [Notes](#notes)

---

## Prerequisites

Before proceeding, ensure you have the following installed on your system:

- **OpenSSL**: For encryption and decryption.
- **Docker**: For interacting with Docker containers.
- **WireGuard (wg-quick)**: For managing WireGuard VPN connections.
- **GCC and G++ compilers**: For compiling the C++ script.
- **Development Libraries**: Such as `libssl-dev`, `libcrypto++-dev`, and `libdl`.

---

## Compiling on macOS with M1 Max Chip

Follow these steps to compile and create a self-extracting executable on macOS with an M1 Max chip.

### 1. Install Necessary Dependencies

Use Homebrew to install the required dependencies:

- Install OpenSSL, Docker, and WireGuard tools:

  `brew install openssl docker wireguard-tools`

### 2. Compile the Script

Compile the script using the following command:

`g++ -std=c++11 -O2 -o script script.cpp -lcrypto -lssl -ldl`

This will create an executable file named `script` in the current directory.

### 3. Encrypt the Executable

Use OpenSSL to encrypt the executable:

`openssl enc -aes-256-cbc -in script -out script.enc -k your_secret_key`

Replace `your_secret_key` with a strong password or key.

### 4. Create a Self-Extracting Executable

Create a self-extracting executable:

`cat script.enc | openssl enc -aes-256-cbc -d -out script -k your_secret_key`

This will create a new executable file named `script` that will decrypt and run the original executable when executed.

### 5. Make the Executable Run

Set the execute permission:

`chmod +x script`

### 6. Package the Self-Extracting Executable

Package the executable into a `.dmg` file:

`hdiutil create -srcfolder . -volname "Script" -format UDRW -ov script.dmg`

This will create a `.dmg` file named `script.dmg` in the current directory.

---

## Compiling on Linux Distributions

Below are the steps for compiling and creating a self-extracting executable on various Linux distributions for both x86 and ARM architectures.

### General Steps

1. **Install Necessary Dependencies**
2. **Compile the Script**
3. **Encrypt the Executable**
4. **Create a Self-Extracting Executable**
5. **Make the Executable Run**

---

### Ubuntu (x86 and ARM)

#### 1. Install Dependencies

- Update package lists:

  `sudo apt-get update`

- Install build essentials and libraries:

  `sudo apt-get install build-essential libssl-dev libcrypto++-dev docker.io wireguard`

#### 2. Compile the Script

`g++ -std=c++11 -O2 -o script script.cpp -lcrypto -lssl -ldl`

#### 3. Encrypt the Executable

`openssl enc -aes-256-cbc -in script -out script.enc -k your_secret_key`

#### 4. Create a Self-Extracting Executable

`cat script.enc | openssl enc -aes-256-cbc -d -out script -k your_secret_key`

#### 5. Make the Executable Run

`chmod +x script`

---

### CentOS (x86 and ARM)

#### 1. Install Dependencies

- Install GCC, G++, and development libraries:

  `sudo yum install gcc gcc-c++ openssl-devel docker wireguard-tools`

#### 2. Compile the Script

`g++ -std=c++11 -O2 -o script script.cpp -lcrypto -lssl -ldl`

#### 3. Encrypt the Executable

`openssl enc -aes-256-cbc -in script -out script.enc -k your_secret_key`

#### 4. Create a Self-Extracting Executable

`cat script.enc | openssl enc -aes-256-cbc -d -out script -k your_secret_key`

#### 5. Make the Executable Run

`chmod +x script`

---

### Fedora (x86 and ARM)

#### 1. Install Dependencies

- Install GCC, G++, and development libraries:

  `sudo dnf install gcc gcc-c++ openssl-devel docker wireguard-tools`

#### 2. Compile the Script

`g++ -std=c++11 -O2 -o script script.cpp -lcrypto -lssl -ldl`

#### 3. Encrypt the Executable

`openssl enc -aes-256-cbc -in script -out script.enc -k your_secret_key`

#### 4. Create a Self-Extracting Executable

`cat script.enc | openssl enc -aes-256-cbc -d -out script -k your_secret_key`

#### 5. Make the Executable Run

`chmod +x script`

---

### Kali Linux (x86 and ARM)

#### 1. Install Dependencies

- Update package lists:

  `sudo apt-get update`

- Install build essentials and libraries:

  `sudo apt-get install build-essential libssl-dev libcrypto++-dev docker.io wireguard`

#### 2. Compile the Script

`g++ -std=c++11 -O2 -o script script.cpp -lcrypto -lssl -ldl`

#### 3. Encrypt the Executable

`openssl enc -aes-256-cbc -in script -out script.enc -k your_secret_key`

#### 4. Create a Self-Extracting Executable

`cat script.enc | openssl enc -aes-256-cbc -d -out script -k your_secret_key`

#### 5. Make the Executable Run

`chmod +x script`

---

### Tails OS (x86 and ARM)

**Note:** Tails OS is a live operating system focused on privacy and security. Installing additional software may not be persistent across reboots unless configured accordingly.

#### 1. Install Dependencies

- Update package lists:

  `sudo apt-get update`

- Install build essentials and libraries:

  `sudo apt-get install build-essential libssl-dev libcrypto++-dev docker.io wireguard`

#### 2. Compile the Script

`g++ -std=c++11 -O2 -o script script.cpp -lcrypto -lssl -ldl`

#### 3. Encrypt the Executable

`openssl enc -aes-256-cbc -in script -out script.enc -k your_secret_key`

#### 4. Create a Self-Extracting Executable

`cat script.enc | openssl enc -aes-256-cbc -d -out script -k your_secret_key`

#### 5. Make the Executable Run

`chmod +x script`

---

### Debian (x86 and ARM)

#### 1. Install Dependencies

- Update package lists:

  `sudo apt-get update`

- Install build essentials and libraries:

  `sudo apt-get install build-essential libssl-dev libcrypto++-dev docker.io wireguard`

#### 2. Compile the Script

`g++ -std=c++11 -O2 -o script script.cpp -lcrypto -lssl -ldl`

#### 3. Encrypt the Executable

`openssl enc -aes-256-cbc -in script -out script.enc -k your_secret_key`

#### 4. Create a Self-Extracting Executable

`cat script.enc | openssl enc -aes-256-cbc -d -out script -k your_secret_key`

#### 5. Make the Executable Run

`chmod +x script`

---

## Notes

- **Replace `your_secret_key`**: Make sure to replace `your_secret_key` with a strong password or key, and keep it secure.
- **ARM Architecture**: For ARM architecture, you may need to use a cross-compiler to compile the script. You can use tools like `gcc-arm-none-eabi` or `gcc-aarch64-linux-gnu` to compile the script for ARM architecture.
- **Permissions**: Some commands may require superuser privileges. Use `sudo` where necessary.
- **Docker and WireGuard**: Ensure that Docker and WireGuard are properly installed and configured on your system.
- **Security Considerations**: Be cautious when handling encryption keys and passwords. Do not hardcode sensitive information in your scripts.

---

**That's it!** You now have a self-extracting executable that can be distributed and executed on various operating systems and architectures.