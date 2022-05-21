#!/bin/bash

set -eo pipefail

user_name="$( sudo ls "/home" | tail -n 1 )"
script_name="Backup"

do_all() {
    internet_check
    check_tools
    clean_repository
    copy_system
    fresh_boot
    pi_shrink
    zero_free "p1"
    zero_free "p2"
    compress_zip
    _done
}

_done() {
    _status 0 "${script_name} done"
    warnings="$( echo "$( grep "\[Warning\]" "${backup_saveas}.log" )" )" || _status 1 "Failed to get warnings from log file"
    if [ -n "${warnings}" ] ; then
        echo
        echo "The following warnings occurred..."
        echo
        echo "${warnings}"
    fi
    echo
    echo -n "Press any key to exit..."
    pause
    echo
    exit 0
}

_notdone() {
    echo
    echo -n "${script_name} failed...Press any key to exit"
    pause
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
    sudo reboot
    exit 0
}

log_file() {
    while read -r line; do
        case "${line}" in
            "Please wait *" | "Rebooting in *")
            ;;
            *)
                echo "${line}" | sed 's/\x1b\[[0-9;]*m\|\x1b[(]B\x1b\[m//g' | sudo tee -a "${backup_saveas}.log" > /dev/null || _status 1 "Failed to append log file"
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
    backup_name=""
    backup_saveas=""
    do_freshboot=""
    do_shrink=""
    PARAMS=""
    while (( "$#" )); do
        case "$1" in
            -r)
                if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
                    backup_source="$2"
                    if [[ "${backup_source}" == "root" ]]; then
                        backup_source="$( sudo lsblk -oMOUNTPOINT,PKNAME -rn | awk '$1 ~ /^\/$/ { print $2 }' )"
                        shift 2
                    else
                        source_mount="$( df --output=source "/dev/${backup_source}" )" || _status 1 "Invalid backup source"
                        if [[ "$( echo "${source_mount}" | head -n 1 )" == "Filesystem" ]] && [[ "$(echo "${source_mount}" | tail -n 1 )" == "devtmpfs" ]]; then
                            shift 2
                        else
                            _status 1 "Invalid backup source"
                        fi
                    fi
                else
                    _status 1 "Argument for backup source is missing"
                fi
            ;;
            -d)
                if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
                    backup_destination="$2"
                    backup_mount="$( findmnt -T "${backup_destination}" -o SOURCE )" || _status 1 "Invalid backup destination"
                    if [[ "$( echo "${backup_mount}" | head -n 1 )" == "SOURCE" ]]; then
                        if [[ "$(echo "${backup_mount}" | tail -n 1 )" == *"${backup_source}"* ]]; then
                            _status 1 "Backup destination is on source device"
                        else
                            [ -d "${backup_destination}/BackUp" ] || ( sudo -u "${user_name}" mkdir "${backup_destination}/BackUp" || _status 1 "Failed to create backup directory" )
                            shift 2
                        fi
                    else
                        _status 1 "Invalid backup destination"
                    fi
                else
                    _status 1 "Argument for backup destination is missing"
                fi
            ;;
            -n)
                if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
                    backup_name="$2"
                    if [[ "${backup_name}" =~ ^[A-Za-z_]+$ ]]; then
                        shift 2
                    else
                        _status 1 "Invalid backup name"
                    fi
                else
                    _status 1 "Argument for backup name is missing"
                fi
            ;;
            -c)
                if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
                    do_repoclean="$2"
                    if [[ "${do_repoclean}" == "repoclean" ]]; then
                        shift 2
                    else
                        _status 1 "Invalid repoclean option"
                    fi
                else
                    _status 1 "Argument for repoclean is missing"
                fi
            ;;
            -f)
                if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
                    do_freshboot="$2"
                    if [[ "${do_freshboot}" == "freshboot" ]]; then
                        shift 2
                    else
                        _status 1 "Invalid freshboot option"
                    fi
                else
                    _status 1 "Argument for freshboot is missing"
                fi
            ;;
            -s)
                if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
                    do_shrink="$2"
                    if [[ "${do_shrink}" == "shrink_only" ]]; then
                        rm_logs=""
                        do_shrink="shrink"
                        shift 2
                    elif [[ "${do_shrink}" == "shrink_rm_logs" ]]; then
                        rm_logs="p"
                        do_shrink="shrink"
                        shift 2
                    else
                        _status 1 "Invalid shrink option"
                    fi
                else
                    _status 1 "Argument for shrink is missing"
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
    if [ -z "${backup_source}" ]; then
        _status 1 "No backup source supplied"
    fi
    if [ -n "${backup_destination}" ] && [ -n "${backup_name}" ]; then
        backup_saveas="${backup_destination}/BackUp/${backup_name}-$(date '+%Y-%m-%d-%H%M%S')"
    elif [ -z "${backup_destination}" ]; then
        _status 1 "No backup destination supplied"
    elif [ -z "${backup_name}" ]; then
        _status 1 "No backup name supplied"
    fi
    _status 0 "Parameters parsed" | tee /dev/tty | log_file
    _status 3 "Using /dev/${backup_source} as backup source" | tee /dev/tty | log_file
    _status 3 "Saving backup to ${backup_saveas}" | tee /dev/tty | log_file
}

check_tools() {
    _status 3 "Checking for required tools"
    req_tools="parted losetup tune2fs md5sum e2fsck resize2fs"
    for command in $req_tools; do
        command -v "${command}" >/dev/null 2>&1
        if (( $? != 0 )); then
            echo
            echo -n "${command} is required, press \"y\" to install... "
            read -r response < /dev/tty
            echo
            case "$response" in
                [yY][eE][sS]|[yY])
                    sudo apt-get install "${command}"
                ;;
                *)
                    _status 1 "${command} is required"
                ;;
            esac
        fi
    done
    _status 0 "All required tools installed"
}

clean_repository() {
    [[ "${do_repoclean}" != "repoclean" ]] && return
    _status 3 "Cleaning out the local repository"
    sudo apt-get clean || _status 2 "Failed to clean the local repository"
    _status 0 "Local repository cleaned"
}

copy_system() {
    source_size="$( sudo blockdev --getsize64 /dev/"${backup_source}" )"
    free_space="$( sudo df "${backup_destination}" | tail -1 | awk '{print $2-$3}' )"
    [ $(("${source_size}" * 11 / 10000)) -gt "${free_space}" ] && _status 1 "Not enough free space on destination device"
    [ $(("${source_size}" * 15 / 10000)) -gt "${free_space}" ] && _status 2 "There may not be enough free space on destination device"
    if [[ "${source_size}" -lt 1000000 ]]; then
        _status 3 "Copying system - $(printf '%.2f\n' "$(echo "${source_size}/1000000" | bc -l)")MB to back up"
    else
        _status 3 "Copying system - $(printf '%.2f\n' "$(echo "${source_size}/1000000000" | bc -l)")GB to back up"
    fi
    dd_copy="$( sudo dd bs=1M if="/dev/${backup_source}" of="${backup_saveas}.img" status=progress conv=fsync oflag=direct 3>&1 1>&2 2>&3 | tee >(cat - >&2) )" || status 1 "Failed to copy system to backup destination"
    _status 0 "System copied - $( echo "${dd_copy}" | tail -1 )"
}

fresh_boot() {
    [[ "${do_freshboot}" != "freshboot" ]] && return
    _status 3 "Adding files for fresh boot"
    mnt_dir="$( mktemp -d )"
    mkdir -p "${mnt_dir}" || _status 1 "Failed to create temporary mount directory"
    loop_mnt="$( sudo losetup --partscan --find --show "${backup_saveas}.img" )" || _status 1 "Failed to create loop device"
    sudo mount "${loop_mnt}p1" "${mnt_dir}" || _status 1 "Failed to mount copied system image"
    vnstat_current || _status 1 "Failed to get current vnStat version"
    case "${vnstat_version}" in
    
        "1.18-2" )
            cat << EOF | sudo tee -a "${mnt_dir}/freshboot.sh" >/dev/null || _status 1 "Failed to add vnStat 1.18-2 fresh boot commands"
#!/bin/bash

sudo rm /var/lib/vnstat/*
sudo systemctl restart vnstat.service
sudo -u vnstat vnstat -i eth0 -u
sudo -u vnstat vnstat -i wlan0 -u
sudo -u vnstat vnstat -i wlan1 -u
sed -i 's| systemd.run=/boot/freshboot.sh||g' /boot/cmdline.txt
sed -i 's| systemd.run_success_action=reboot||g' /boot/cmdline.txt
sed -i 's| systemd.unit=kernel-command-line.target||g' /boot/cmdline.txt

sudo /usr/bin/raspi-config --expand-rootfs

exit 0
EOF
        ;;
        "2.6-3" )
            cat << EOF | sudo tee -a "${mnt_dir}/freshboot.sh" >/dev/null || _status 1 "Failed to add vnStat 2.6-3 fresh boot commands"
#!/bin/bash

sudo rm /var/lib/vnstat/*
sudo systemctl restart vnstat.service
sed -i 's| systemd.run=/boot/freshboot.sh||g' /boot/cmdline.txt
sed -i 's| systemd.run_success_action=reboot||g' /boot/cmdline.txt
sed -i 's| systemd.unit=kernel-command-line.target||g' /boot/cmdline.txt

sudo /usr/bin/raspi-config --expand-rootfs

exit 0
EOF
        ;;
        "" | "*" )
            cat << EOF | sudo tee -a "${mnt_dir}/freshboot.sh" >/dev/null || _status 1 "Failed to add non vnStat fresh boot commands"
#!/bin/bash

sed -i 's| systemd.run=/boot/freshboot.sh||g' /boot/cmdline.txt
sed -i 's| systemd.run_success_action=reboot||g' /boot/cmdline.txt
sed -i 's| systemd.unit=kernel-command-line.target||g' /boot/cmdline.txt

sudo /usr/bin/raspi-config --expand-rootfs

exit 0
EOF
        ;;
    esac
    
    sudo chmod +x "${mnt_dir}/freshboot.sh" || _status 1 "Failed to make freshboot.sh executable"
    
    sudo sed -i "1 s|$| systemd\.run=\/boot\/freshboot\.sh|" "${mnt_dir}/cmdline.txt" || _status 1 "Failed to add freshboot.sh to cmdline.txt"
    sudo sed  -i "1 s|$| systemd\.run_success_action=reboot|" "${mnt_dir}/cmdline.txt" || _status 1 "Failed to add systemd.run_success_action=reboot to cmdline.txt"
    sudo sed  -i "1 s|$| systemd\.unit=kernel-command-line\.target|" "${mnt_dir}/cmdline.txt" || _status 1 "Failed to add systemd.unit=kernel-command-line.target to cmdline.txt"
    
    sudo umount "${mnt_dir}" || _status 1 "Failed to unmount copied system image"
    sudo losetup -D || _status 1 "Failed to detach loop device"
    _status 0 "Files for fresh boot added"
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

pi_shrink() {
    [[ "${do_shrink}" != "shrink" ]] && return
    _status 3 "Downloading PiShrink script"
    wget -qO - "https://raw.githubusercontent.com/minimaded/backup_scripts/main/pishrink.sh" > "/tmp/pishrink.sh" || _status 1 "Failed to get PiShrink script"
    sudo chmod +x "/tmp/pishrink.sh"
    _status 3 "Shrinking system copy with PiShrink"
    sudo "/tmp/pishrink.sh" "-s${rm_logs}" "${backup_saveas}.img" || _status 1 "Failed to shrink system copy with PiShrink"
    _status 0 "System copy shrunk with PiShrink"
}

zero_free() {
    part_n=$1
    _status 3 "Zeroing free space on ${part_n} to improve compression"
    mnt_dir="$( mktemp -d )"
    mkdir -p "${mnt_dir}" || _status 1 "Failed to create temporary mount directory"
    loop_mnt="$( sudo losetup --partscan --find --show "${backup_saveas}.img" )" || _status 1 "Failed to create loop device"
    sudo mount "${loop_mnt}${part_n}" "${mnt_dir}" || _status 1 "Failed to mount copied system image"
    for i in {1..2}; do
        if [[ "${i}" -eq 1 ]]; then
            pass_l="coarse"
            pass_u="Coarse"
            dd_bs="1M"
        elif [[ "${i}" -eq 2 ]]; then
            pass_l="fine"
            pass_u="Fine"
            dd_bs="1K"
        fi
        k_to_clean="$( sudo df -k "${loop_mnt}${part_n}" -BKB | tail -1 | awk '{print $2-$3}' )"
        if [[ "${k_to_clean}" -lt 1000 ]]; then
            _status 3 "${pass_u} - There is ${k_to_clean}KB to clean for ${part_n}"
        elif [[ "${k_to_clean}" -lt 1000000 ]]; then
            _status 3 "${pass_u} - There is $(printf '%.2f\n' "$(echo "${k_to_clean}/1000" | bc -l)")MB to clean for ${part_n}"
        else
            _status 3 "${pass_u} - There is $(printf '%.2f\n' "$(echo "${k_to_clean}/1000000" | bc -l)")GB to clean for ${part_n}"
        fi
        dd_zero="$( sudo dd bs="${dd_bs}" if=/dev/zero of="${mnt_dir}/delete_me_${pass_l}" status=progress conv=fsync iflag=nocache oflag=direct 3>&1 1>&2 2>&3 | tee >(cat - >&2) )" || \
        _status 0 "Free space zeroed - $( echo "${dd_zero}" | tail -1 )"
        sync
        sync
    done
    _status 3 "Deleting dummy files"
    sudo rm -f -v "${mnt_dir}/delete_me_coarse" || _status 1 "Failed to delete coarse dummy file"
    sudo rm -f -v "${mnt_dir}/delete_me_fine" || _status 1 "Failed to delete fine dummy file"
    sync
    sync
    sudo umount "${mnt_dir}" || _status 1 "Failed to un-mount copied system image"
    sudo losetup -D || _status 1 "Failed to detach loop device"
    _status 0 "Zeroed free space on ${part_n}"
}

compress_zip() {
    _status 3 "Compressing backup"
    gzip_result="$( sudo gzip -v "${backup_saveas}.img" 3>&1 1>&2 2>&3 | tee >(cat - >&2) )" || _status 1 "Failed to compress backup"
    compressed_size="$( du -bh "${backup_saveas}.img.gz" | cut -f1 )" || _status 1 "Failed to compress backup size"
    _status 0 "Backup compressed - $( echo "${gzip_result}" | awk -F  ":\t" '/1/ {print $2}' | awk '{print $5 " " $1}' ) ${compressed_size}"
}

_colors
script_path="$( readlink -f "$0" )"
parse_params "$@"
_status 0 "Username is ${user_name}" | tee /dev/tty | log_file
do_all | tee /dev/tty | log_file
