#!/bin/bash

# Set up logging
LOG_FILE="script.log"
LOG_LEVEL="INFO"

# Function to log messages
log_message() {
    local level=$1
    local message=$2
    echo "$(date) [$level] $message" >> $LOG_FILE
}

# Function to execute the healer.cpp script
execute_cpp_script() {
    log_message "INFO" "Executing healer."
   ./cpp_script
    log_message "INFO" "Healer script executed successfully!"
}

# Function to retrieve a new version of the C++17 script
retrieve_new_cpp_script() {
    log_message "INFO" "Retrieving new version of the local Docker container."
    curl -s -o new_cpp_script https://private_server/new_cpp_script
    log_message "INFO" "A new version of the local Docker container has been retrieved successfully!"
}

# Main function
main() {
    execute_cpp_script
    retrieve_new_cpp_script
}

main