curl -sL https://raw.githubusercontent.com/minimaded/backup_scripts/main/run_backup.sh | bash -s -- -r "root" -d "/mnt/ExtSSD" -n "PiWiFi" -c "repoclean" -f "freshboot" -s "shrink_rm_logs"

curl -sL https://raw.githubusercontent.com/minimaded/backup_scripts/main/raspap_update.sh | bash -s -- -b "/mnt/ExtSSD/BackUp" -p "noprompt"
