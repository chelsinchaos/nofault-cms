#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <unistd.h>
#include <sys/wait.h>

// Hardcoded RSA 4096-bit private key (PEM format)
const char* private_key_pem = R"(
-----BEGIN RSA PRIVATE KEY-----
... (Your RSA 4096-bit private key in PEM format goes here) ...
-----END RSA PRIVATE KEY-----
)";

// Hardcoded passphrase for the private key
const char* private_key_passphrase = "your_private_key_passphrase";

// Function to load the RSA private key from a PEM string
RSA* load_private_key(const std::string& private_key_pem, const std::string& passphrase) {
    BIO* bio = BIO_new_mem_buf(private_key_pem.data(), -1);
    RSA* rsa_private_key = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, (void*)passphrase.c_str());
    BIO_free(bio);
    if (!rsa_private_key) {
        std::cerr << "Failed to load private key: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
    }
    return rsa_private_key;
}

// Function to decrypt data using RSA private key
std::string rsa_decrypt(const std::string& encrypted_data, RSA* rsa_private_key) {
    int rsa_size = RSA_size(rsa_private_key);
    unsigned char* decrypted = new unsigned char[rsa_size];
    int result = RSA_private_decrypt(encrypted_data.size(), (const unsigned char*)encrypted_data.data(),
                                     decrypted, rsa_private_key, RSA_PKCS1_OAEP_PADDING);
    if (result == -1) {
        std::cerr << "RSA decryption failed: " << ERR_error_string(ERR_get_error(), NULL) << std::endl;
        delete[] decrypted;
        return "";
    }
    std::string decrypted_data((char*)decrypted, result);
    delete[] decrypted;
    return decrypted_data;
}

// Function to decrypt AES-encrypted data
void aes_decrypt(const std::string& encrypted_data, const std::string& key, std::string& decrypted_data) {
    if (encrypted_data.size() < AES_BLOCK_SIZE) {
        std::cerr << "Invalid encrypted data size" << std::endl;
        return;
    }

    // Extract Initialization Vector (IV)
    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, encrypted_data.data(), AES_BLOCK_SIZE);

    std::string ciphertext = encrypted_data.substr(AES_BLOCK_SIZE);

    AES_KEY aes_key;
    if (AES_set_decrypt_key((const unsigned char*)key.data(), key.size() * 8, &aes_key) < 0) {
        std::cerr << "Failed to set AES decryption key" << std::endl;
        return;
    }

    // Decrypt the ciphertext
    unsigned char* decrypted = new unsigned char[ciphertext.size()];
    int decrypted_length = 0;

    AES_cbc_encrypt((const unsigned char*)ciphertext.data(), decrypted, ciphertext.size(), &aes_key, iv, AES_DECRYPT);

    // Remove PKCS#7 padding
    int padding_length = decrypted[ciphertext.size() - 1];
    if (padding_length > 0 && padding_length <= AES_BLOCK_SIZE) {
        decrypted_length = ciphertext.size() - padding_length;
    } else {
        decrypted_length = ciphertext.size();
    }

    decrypted_data = std::string((char*)decrypted, decrypted_length);
    delete[] decrypted;
}

// Function to read a file into a string
std::string read_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return "";
    }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return content;
}

// Function to check if a Docker container is running
bool is_container_running(const std::string& container_name) {
    std::string command = "docker inspect --format='{{.State.Running}}' " + container_name + " 2>/dev/null";
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        std::cerr << "Failed to run command: " << command << std::endl;
        return false;
    }
    char buffer[128];
    std::string result = "";
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        result += buffer;
    }
    pclose(pipe);
    if (result.find("true") != std::string::npos) {
        return true;
    } else {
        return false;
    }
}

// Function to check if a Docker container is healthy
bool is_container_healthy(const std::string& container_name) {
    std::string command = "docker inspect --format='{{.State.Health.Status}}' " + container_name + " 2>/dev/null";
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        std::cerr << "Failed to run command: " << command << std::endl;
        return false;
    }
    char buffer[128];
    std::string result = "";
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        result += buffer;
    }
    pclose(pipe);
    if (result.find("healthy") != std::string::npos) {
        return true;
    } else {
        return false;
    }
}

// Function to establish WireGuard VPN connection
int establish_wireguard_vpn(const std::string& config_path) {
    std::string command = "sudo wg-quick up " + config_path;
    int ret = system(command.c_str());
    if (ret != 0) {
        std::cerr << "Failed to establish WireGuard VPN connection" << std::endl;
    }
    return ret;
}

// Function to tear down WireGuard VPN connection
int teardown_wireguard_vpn(const std::string& config_path) {
    std::string command = "sudo wg-quick down " + config_path;
    int ret = system(command.c_str());
    if (ret != 0) {
        std::cerr << "Failed to tear down WireGuard VPN connection" << std::endl;
    }
    return ret;
}

int main() {
    // Load the private key
    RSA* rsa_private_key = load_private_key(private_key_pem, private_key_passphrase);
    if (!rsa_private_key) {
        return 1;
    }

    // Read the encrypted .env file
    std::string encrypted_env = read_file(".env.enc"); // Encrypted .env file
    if (encrypted_env.empty()) {
        RSA_free(rsa_private_key);
        return 1;
    }

    int rsa_size = RSA_size(rsa_private_key);

    // Extract the encrypted symmetric key
    std::string encrypted_symmetric_key = encrypted_env.substr(0, rsa_size);

    // Decrypt the symmetric key
    std::string symmetric_key = rsa_decrypt(encrypted_symmetric_key, rsa_private_key);
    if (symmetric_key.empty()) {
        RSA_free(rsa_private_key);
        return 1;
    }

    // The rest of the data is the AES-encrypted .env content
    std::string encrypted_env_data = encrypted_env.substr(rsa_size);

    // Decrypt the AES-encrypted data
    std::string decrypted_env_data;
    aes_decrypt(encrypted_env_data, symmetric_key, decrypted_env_data);

    if (decrypted_env_data.empty()) {
        std::cerr << "Failed to decrypt .env data" << std::endl;
        RSA_free(rsa_private_key);
        return 1;
    }

    // Parse the decrypted .env data and set environment variables
    std::istringstream iss(decrypted_env_data);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.empty() || line[0] == '#') {
            continue; // Skip empty lines and comments
        }
        auto pos = line.find('=');
        if (pos == std::string::npos) {
            continue; // Skip malformed lines
        }
        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);
        setenv(key.c_str(), value.c_str(), 1);
    }

    // Clean up RSA key
    RSA_free(rsa_private_key);

    // Retrieve necessary environment variables
    char* container_name_c = getenv("CONTAINER_NAME");
    char* image_name_c = getenv("IMAGE_NAME");
    char* wireguard_config_path_c = getenv("WIREGUARD_CONFIG_PATH");

    if (!container_name_c || !image_name_c || !wireguard_config_path_c) {
        std::cerr << "Missing necessary environment variables" << std::endl;
        return 1;
    }

    std::string container_name = container_name_c;
    std::string image_name = image_name_c;
    std::string wireguard_config_path = wireguard_config_path_c;

    // Check if the container is running
    if (!is_container_running(container_name)) {
        std::cout << "Container is not running, attempting to start..." << std::endl;
        std::string command = "docker start " + container_name;
        int ret = system(command.c_str());
        if (ret != 0) {
            std::cerr << "Failed to start container: " << container_name << std::endl;
            // Establish WireGuard VPN to pull new image
            if (establish_wireguard_vpn(wireguard_config_path) == 0) {
                // Pull new image
                command = "docker pull " + image_name;
                ret = system(command.c_str());
                if (ret == 0) {
                    std::cout << "Successfully pulled new image: " << image_name << std::endl;
                } else {
                    std::cerr << "Failed to pull new image: " << image_name << std::endl;
                }
                teardown_wireguard_vpn(wireguard_config_path);
            }
        } else {
            std::cout << "Successfully started container: " << container_name << std::endl;
        }
    } else {
        // Check if the container is healthy
        if (!is_container_healthy(container_name)) {
            std::cout << "Container is not healthy, attempting to restart..." << std::endl;
            std::string command = "docker restart " + container_name;
            int ret = system(command.c_str());
            if (ret != 0) {
                std::cerr << "Failed to restart container: " << container_name << std::endl;
                // Establish WireGuard VPN to pull new image
                if (establish_wireguard_vpn(wireguard_config_path) == 0) {
                    // Pull new image
                    command = "docker pull " + image_name;
                    ret = system(command.c_str());
                    if (ret == 0) {
                        std::cout << "Successfully pulled new image: " << image_name << std::endl;
                    } else {
                        std::cerr << "Failed to pull new image: " << image_name << std::endl;
                    }
                    teardown_wireguard_vpn(wireguard_config_path);
                }
            } else {
                std::cout << "Successfully restarted container: " << container_name << std::endl;
            }
        } else {
            std::cout << "Container is running and healthy." << std::endl;
        }
    }

    return 0;
}
