#!/usr/bin/env bash
# Script to identify if there are any changes to users or permissions

# Prompt user for the directories or files to monitor
read -p "Enter the directories (separated by spaces): " -a MONITORED_PATHS

# Prompt user for the time interval in minutes
while true; do
    read -p "Enter the time interval in minutes: " TIME_INTERVAL
    if [[ "$TIME_INTERVAL" =~ ^[0-9]+$ ]]; then
        break
    else
        echo "Please enter a valid number."
    fi
done

echo "Checking for user additions and permission changes in the last $TIME_INTERVAL minutes..."

# Identify any new users created in the specified time interval
echo "New users created in the last $TIME_INTERVAL minutes:"
getent passwd {1000..60000} | awk -F: '{print $1, $3, $6}' | while read -r user uid dir; do
    if find / -maxdepth 1 -type d -cmin -"$TIME_INTERVAL" -name "$user" &>/dev/null; then
        echo "$user ($uid)"
    fi
done

# Identify any permission changes in the specified paths in the specified time interval
for path in "${MONITORED_PATHS[@]}"; do
    find "$path" -cmin -"$TIME_INTERVAL" -exec ls -ld {} \; 2>/dev/null
done