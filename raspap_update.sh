#!/bin/bash

set -eo pipefail

user_name="$( sudo ls "/home" | tail -n 1 )"
logfile_name="/home/${user_name}/Log Files/raspap_log.txt"
script_name="RaspAP update"

do_all() {
    internet_check

    if [[ "${no_prompt}" == "noprompt" ]]; then
        compress_oldfiles
        update_raspap
        delete_oldfiles
        clear_vnstat
        _status 0 "RaspAP update completed"
        raspap_reboot
        _reboot 10
    else
        echo -n "Download RaspAP update? [y/N] " | tee /dev/tty | relog | log_file
        read -r response < /dev/tty
        echo "${response}" | logfile
        case "${response}" in
            [yY][eE][sS]|[yY])
                compress_oldfiles
                update_raspap
        esac
        echo -n "Continue update script? [y/N] " | tee /dev/tty | relog | log_file
        read -r response < /dev/tty
        echo "${response}" > logfile
        case "${response}" in
            [yY][eE][sS]|[yY])
                delete_oldfiles
                clear_vnstat
                _status 0 "RaspAP update completed"
        esac
        echo -n "Reboot? [y/N] " | tee /dev/tty | relog | log_file
        read -r response < /dev/tty
        echo "${response}" > logfile
        case "${response}" in
            [yY][eE][sS]|[yY])
                raspap_reboot
                _reboot 10
                exit 0
        esac
    fi
}

comment_done() {
    calling_function="${FUNCNAME[ 1 ]}"
    sed -i "0,/${calling_function}/s//#${calling_function}/" "${script_path}" || _status 1 "Failed to comment ${calling_function} function done"
}

_done() {
    _status 0 "${script_name} done"
    warnings="$( echo "$( grep "\[Warning\]" "${logfile_name}" )" )" || _status 1 "Failed to get warnings from log file"
    if [ -n "${warnings}" ] ; then
        echo
        echo "The following warnings occurred..."
        echo
        echo "${warnings}"
    fi
    echo
    echo -n "Press any key to exit..."
    read -r -s -n 1 any_key
    echo
    exit 0
}

_notdone() {
    echo
    echo -n "${script_name} failed...Press any key to exit"
    read -r -s -n 1 any_key
    echo
    exit 1
}

_colors() {
    if [[ -t 1 ]]; then
        ncolors="$(tput colors)"
        if [[ -n "${ncolors}" && "${ncolors}" -ge 8 ]]; then
            text_red="$(tput setaf 1)"
            text_green="$(tput setaf 2)"
            text_yellow="$(tput setaf 3)"
            text_blue="$(tput setaf 4)"
            text_magenta="$(tput setaf 5)"
            text_cyan="$(tput setaf 6)"
            text_error="$(tput setaf 7)$(tput setab 1)$(tput bold)"
            text_reset="$(tput sgr0)"
        else
            text_red=""
            text_green=""
            text_yellow=""
            text_blue=""
            text_magenta=""
            text_cyan=""
            text_error=""
            text_reset=""
        fi
    fi
}

_status() {
    case $1 in
        0)
            echo -e "[$text_green""Success""$text_reset]$text_green $2$text_reset"  | relog
        ;;
        1)
            echo -e "[$text_red"" Error ""$text_reset] $text_error$2$text_reset" | relog
        _notdone
        ;;
        2)
            echo -e "[$text_yellow""Warning""$text_reset]$text_yellow $2$text_reset" | relog
        ;;
        3)
            echo -e "[$text_cyan""Perform""$text_reset]$text_cyan $2$text_reset"  | relog
        ;;
    esac
}

_sleep() {
    count=0
    total=$1
    _status 3 "Waiting ${total} seconds"
    while [ "${count}" -lt "${total}" ]; do
        printf "\rPlease wait %ds  " $(( total - count ))
        sleep 1
        (( ++count ))
    done
    echo
    _status 0 "Waited ${total} seconds, continuing..."
}

_reboot() {
    count=0
    total=$1
    while [ "${count}" -lt "${total}" ]; do
        printf "\rRebooting in %ds  " $(( total - count ))
        sleep 1
        (( ++count ))
    done
    echo
    _status 0 "Rebooting"
    #sudo reboot
    exit 0
}

log_file() {
    while read -r line; do
        case "${line}" in
            "Please wait *" | "Rebooting in *")
                echo "test"
            ;;
            *)
                echo "${line}" | sed 's/\x1b\[[0-9;]*m\|\x1b[(]B\x1b\[m//g' | sudo tee -a "${logfile_name}" > /dev/null || _status 1 "Failed to append log file"
            ;;
        esac
    done
}

relog() {
    while read -r line; do
        timestamp="$( date +"%Y-%m-%d %H:%M:%S" )"
        echo "[${timestamp}] ${line}"
    done
}

internet_check() {
    _status 3 "Checking for an internet connection"
    for i in {1..60}; do
        if ping -c1 www.google.com &>/dev/null ; then
           _status 0 "Connected to the internet"
            break
        else
            _status 2 "Waiting for an internet connection..."
            sleep 1
        fi
        if [ "${i}" -gt 59 ] ; then
           _status 1 "Unable to connect to the internet"
        fi
    done
}

parse_params() {
    backup_destination=""
    backup_saveas=""
    PARAMS=""
    while (( "$#" )); do
        case "$1" in
            -b)
                if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
                    backup_destination="$2"
                    backup_mount="$( findmnt -T "${backup_destination}" -o SOURCE )" || _status 1 "Invalid backup destination"
                    [ -d "${backup_destination}/RaspAP Backups" ] || ( sudo -u "${user_name}" mkdir "${backup_destination}/RaspAP Backups" || _status 1 "Failed to create backup directory" )
                    shift 2
                else
                    _status 1 "Argument for backup destination is missing"
                fi
            ;;
            -p)
                if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
                    no_prompt="$2"
                    if [[ "${no_prompt}" == "noprompt" ]]; then
                        shift 2
                    else
                        _status 1 "Invalid no prompt option"
                    fi
                else
                    _status 1 "Argument for prompt is missing"
                fi
            ;;
            -*) # unsupported flags
                _status 1 "Unsupported flag $1"
            ;;
            *) # preserve positional arguments
                PARAMS="$PARAMS $1"
                shift
            ;;
        esac
    done
    _status 0 "Parameters parsed" | tee /dev/tty | log_file
    if [ -n "${backup_destination}" ]; then
        backup_saveas="${backup_destination}/RaspAP Backups/RaspAP-$(date '+%Y-%m-%d-%H%M%S')"
        _status 3 "Saving RaspAP backup to ${backup_saveas}" | tee /dev/tty | log_file
    fi
}

compress_oldfiles() {
    [ -z "${backup_destination}" ] && return
    _status 3 "Backing up old files"
    old_folders="$(find '/etc/' -maxdepth 1 -iname 'raspap*' -o -iname 'dnsmasq.d' -o -iname 'hostapd')"$'\n'"$(find '/etc/network/' -maxdepth 1 -iname 'interfaces.d')"$'\n'"$(find '/var/www/' -maxdepth 1 -iname 'html*')" || _status 1 "Failed to find old folders"
    for old_folder in $old_folders; do
        sudo tar -rf "${backup_saveas}.tar" "${old_folder}" &> /dev/null || _status 1 "Failed to compress old folders"
    done
    sudo tar -rf "${backup_saveas}.tar" "/etc/dhcpcd.conf" &> /dev/null || _status 1 "Failed to compress dhcpcd.conf"
    _status 0 "Old files backed up"
}

update_raspap() {
    _status 3 "Updating RaspAP"
    curl -sL https://install.raspap.com | bash -s -- -o 0 -a 0 -y -u || _status 1 "Failed to run RaspAP install script"

    sudo mkdir -p "/tmp/raspap_files" || _status 1 "Failed to create temporary RaspAP directory"
    sudo tar -xf "/boot/raspap_files.tar.gz" -C "/tmp" || _status 1 "Failed to decompress temporary RaspAP files"

    ( sudo cp "/tmp/raspap_files/dhcpcd.conf" "/etc/" && sudo chown root:netdev "/etc/dhcpcd.conf" ) || _status 1 "Failed to copy dhcpcd.conf"

    ( sudo cp "/tmp/raspap_files/090_raspap.conf" "/etc/dnsmasq.d/" && sudo chown root:root "/etc/dnsmasq.d/090_raspap.conf" ) || _status 1 "Failed to copy 090_raspap.conf"
    ( sudo cp "/tmp/raspap_files/090_wlan0.conf" "/etc/dnsmasq.d/" && sudo chown root:root "/etc/dnsmasq.d/090_wlan0.conf" ) || _status 1 "Failed to copy 090_wlan0.conf"
    ( sudo cp "/tmp/raspap_files/090_wlan1.conf" "/etc/dnsmasq.d/" && sudo chown root:root "/etc/dnsmasq.d/090_wlan1.conf" ) || _status 1 "Failed to copy 090_wlan1.conf"

    ( sudo cp "/tmp/raspap_files/hostapd.conf" "/etc/hostapd/" && sudo chown root:root "/etc/hostapd/hostapd.conf" ) || _status 1 "Failed to copy hostapd.conf"
    ( sudo cp "/tmp/raspap_files/wlan0.conf" "/etc/hostapd/" && sudo chown root:root "/etc/hostapd/wlan0.conf" ) || _status 1 "Failed to copy wlan0.conf"
    ( sudo cp "/tmp/raspap_files/wlan1.conf" "/etc/hostapd/" && sudo chown root:root "/etc/hostapd/wlan1.conf" ) || _status 1 "Failed to copy wlan1.conf"

    ( sudo cp "/tmp/raspap_files/wlan0" "/etc/network/interfaces.d/" && sudo chown root:root "/etc/network/interfaces.d/wlan0" ) || _status 1 "Failed to copy wlan0"
    ( sudo cp "/tmp/raspap_files/wlan1" "/etc/network/interfaces.d/" && sudo chown root:root "/etc/network/interfaces.d/wlan1" ) || _status 1 "Failed to copy wlan1"

    ( sudo cp "/tmp/raspap_files/hostapd.ini" "/etc/raspap/" && sudo chown root:root "/etc/raspap/hostapd.ini" ) || _status 1 "Failed to copy hostapd.ini"
    ( sudo cp "/tmp/raspap_files/raspap.auth" "/etc/raspap/" && sudo chown root:root "/etc/raspap/raspap.auth" ) || _status 1 "Failed to copy raspap.auth"
    ( sudo cp "/tmp/raspap_files/raspap.php" "/etc/raspap/" && sudo chown www-data:www-data "/etc/raspap/raspap.php" ) || _status 1 "Failed to copy raspap.php"

    ( sudo cp "/tmp/raspap_files/defaults" "/etc/raspap/networking/" && sudo chown www-data:www-data "/etc/raspap/networking/defaults" ) || _status 1 "Failed to copy defaults"

    set_iptables
    _status 0 "RaspAP updated"
}

set_iptables() {
    _status 3 "Adding iptable rules"
    sudo rm -f "/etc/iptables/rules.v4" || _status 1 "Failed to delete old ip4table rules"
    sudo rm -f "/etc/iptables/rules.v6" || _status 1 "Failed to delete old ip6table rules"

    sudo iptables -F || _status 1 "Failed to delete ip4table rules"
    sudo iptables -P INPUT DROP || _status 1 "Failed to set ip4table input rule"
    sudo iptables -P OUTPUT DROP || _status 1 "Failed to set ip4table output rule"
    sudo iptables -P FORWARD DROP || _status 1 "Failed to set ip4table forward rule"
    sudo ip6tables -F || _status 1 "Failed to delete ip6table rules"
    sudo ip6tables -P INPUT DROP || _status 1 "Failed to set ip6table input rule"
    sudo ip6tables -P OUTPUT DROP || _status 1 "Failed to set ip6table output rule"
    sudo ip6tables -P FORWARD DROP || _status 1 "Failed to set ip6table forward rule"
    sudo iptables -I INPUT -i lo -j ACCEPT || _status 1 "Failed to set ip4table input rule"
    sudo iptables -I OUTPUT -o lo -j ACCEPT || _status 1 "Failed to set ip4table input rule"
    sudo iptables -I INPUT -i wlan0 -j ACCEPT || _status 1 "Failed to set ip4table input rule"
    sudo iptables -I OUTPUT -o wlan0 -j ACCEPT || _status 1 "Failed to set ip4table input rule"
    sudo bash -c "iptables-save > /etc/iptables/rules.v4" || _status 1 "Failed to save ip4table rules"
    sudo bash -c "ip6tables-save > /etc/iptables/rules.v6" || _status 1 "Failed to save ip6table rules"
    _status 0 "iptable rules added"
}

delete_oldfiles() {
    _status 3 "Deleting old files"
    sudo find "/var/www" -maxdepth 1 -iname "html.*" -type d | xargs -r sudo rm -r || _status 1 "Failed to delete html backups"
    sudo find "/etc/" -maxdepth 1 -iname "raspap.*" -type d | xargs -r sudo rm -r || _status 1 "Failed to delete raspap backups"
    _status 0 "Old files deleted"
}

clear_vnstat() {
    _status 3 "Clearing vnStat"
    vnstat_current || _status 1 "Failed to get current vnStat version"
    case "${vnstat_version}" in
        "1.18-2" )
            sudo rm /var/lib/vnstat/* || _status 1 "Failed to remove vnStat directory"
            sudo systemctl restart vnstat.service || _status 1 "Failed to restart vnStat service"
            sudo -u vnstat vnstat -i eth0 -u || _status 1 "Failed to add eth0 to vnStat"
            sudo -u vnstat vnstat -i wlan0 -u || _status 1 "Failed to add wlan0 to vnStat"
            sudo -u vnstat vnstat -i wlan1 -u || _status 1 "Failed to add wlan1 to vnStat"
        ;;
        "2.6-3" )
            sudo rm /var/lib/vnstat/* || _status 1 "Failed to remove vnStat directory"
            sudo systemctl restart vnstat.service || _status 1 "Failed to restart vnStat service"
        ;;
    esac
    _status 0 "vnStat cleared"
}

vnstat_current() {
    vnstat_version="$( sudo dpkg-query -l | grep "vnstat" | tr -s " " | cut -d " " -f 3 )" || _status 1 "Failed to get vnStat version"
    case "${vnstat_version}" in
        "" )
            _status 3 "vnStat not installed..."
        ;;
        "2.6-3" | "1.18" )
            _status 3 "vnStat ${vnstat_version} installed..."
        ;;
        "*" )
            _status 2 "vnStat ${vnstat_version} not supported..."
        ;;
    esac
}

raspap_reboot() {
    sudo -u "${user_name}" mkdir -p "/home/${user_name}/.config/autostart" || _status 1 "Failed to add autostart directory"
    cat > "/home/${user_name}/.config/autostart/raspapreboot.desktop" << EOF || _status 1 "Failed to create raspapreboot autostart file"
[Desktop Entry]
Encoding=UTF-8
Type=Application
Name=RaspAPReboot
Exec=lxterminal -e bash -c 'sudo "/home/${user_name}/raspapreboot.sh";$SHELL'
Terminal=true
EOF

    sudo chmod a+r "/home/${user_name}/.config/autostart/raspapreboot.desktop" || _status 1 "Failed to change raspapreboot autostart file properties"

    cat << EOF | sudo -u "${user_name}" tee "/home/${user_name}/raspapreboot.sh" >/dev/null || _status 1 "Failed to add raspapreboot script"
#!/bin/bash

set -eo pipefail

do_all() {
    _reboot 30
    echo_warnings
}

_status () {
    case \$1 in
        0)
            echo -e  "[Success] ""\$2" | relog
        ;;
        1)
            echo -e  "[ Error ] ""\$2" | relog
            echo -n "Press any key to exit"
            read -r -s -n 1 any_key
            echo
            exit 1
        ;;
    esac
}

log_file() {
    while read -r line; do
        case "\${line}" in
            "Please wait *" | "Rebooting in *")
            ;;
            *)
               echo "\${line}" | sudo tee -a "${logfile_name}" > /dev/null || _status 1  "Failed to append log file"
            ;;
        esac
    done
}

relog() {
    while read -r line; do
        timestamp="\$( date +"%Y-%m-%d %H:%M:%S" )"
        echo "[\${timestamp}] \${line}"
    done
}

_reboot() {
    count=0
    total=\$1
    while [ "\${count}" -lt "\${total}" ]; do
        printf "\rRebooting in %ds  " \$(( total - count ))
        sleep 1
        (( ++count ))
    done
    echo
    sed -i "0,/_reboot/s//#_reboot/" "/home/${user_name}/raspapreboot.sh" || _status 1  "Failed to comment reboot function done"
    _status 0 "Rebooting"
    sudo reboot
    exit 0
}

echo_warnings() {
    _status 0 "RaspAP update done"
    warnings="\$( echo "\$( grep "\[Warning\]" "${logfile_name}" )" )" || _status 1  "Failed to get warnings from log file"
    if [ -n "\${warnings}" ] ; then
        echo
        echo "The following warnings occurred..."
        echo
        echo "\${warnings}"
    fi
    sudo rm -f "/home/${user_name}/raspapreboot.sh" || _status 1   "Failed to remove raspapreboot script"
    sudo rm -f "/home/${user_name}/.config/autostart/raspapreboot.desktop" || _status 1  "Failed to remove raspapreboot autostart file"
    echo
    echo -n "Press any key to exit..."
    read -r -s -n 1 any_key
    echo
    exit 0
}

do_all | tee /dev/tty | log_file
EOF

    sudo chmod +x "/home/${user_name}/raspapreboot.sh" || _status 1 "Failed to make reboot script executable"
}

_colors
script_path="$( readlink -f "$0" )"
parse_params "$@"
_status 0 "Username is ${user_name}" | tee /dev/tty | log_file
do_all | tee /dev/tty | log_file
