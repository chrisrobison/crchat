#!/bin/bash

# Get current timestamp in desired format
timestamp=$(date +"%Y%m%d%H%M")

# Source file
src_file="/home/cdr/cdr2/crchat/chat_history.jsonl"

# Destination directory
dest_dir="/home/cdr/cdr2/crchat/chats"

# Create destination directory if it doesn't exist
mkdir -p "$dest_dir"

# Copy and rename file
/bin/cp "$src_file" "$dest_dir/chats-${timestamp}.log"

cp /home/cdr/cdr2/crchat/tools/default.txt "$src_file"

