#!/bin/bash

set -eo pipefail

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
    _status 0 "Backup done"
    warnings="$( grep "warning" "${backup_saveas}.log" )"
    echo
    if [ -n "${warnings}" ] ; then
        echo "The following warnings occured..."
        echo
        echo "${warnings}"
    fi
    echo
    read -r -p "Press any key to exit... " -n1 -s 
    exit 0
}

_notdone() {
    echo "Backup failed..."
    exit 1
}

_colors() {
    ansi_red="\033[0;31m"
    ansi_green="\033[0;32m"
    ansi_yellow="\033[0;33m"
    ansi_raspberry="\033[0;35m"
    ansi_error="\033[1;37;41m"
    ansi_reset="\033[m"
}

_status() {
    case $1 in
        0)
        echo -e "[$ansi_green \u2713 ok $ansi_reset] $ansi_green $2 $ansi_reset"  | relog
        ;;
        1)
        echo -e "[$ansi_red \u2718 error $ansi_reset] $ansi_error $2 $ansi_reset" | relog
        _notdone
        ;;
        2)
        echo -e "[$ansi_yellow \u26a0 warning $ansi_reset] $ansi_yellow $2 $ansi_reset" | relog
        ;;
    esac
}

_sleep() {
    count=0
    total=$1
    while [ "${count}" -lt "${total}" ]; do
        printf "\rPlease wait %ds  " $(( total - count ))
        sleep 1
        count=$(( count + 1 ))
    done
    echo
}

log_file() {
    while read -r log_line; do
        echo "${log_line}"| sed -i 's/\x1b\[[0-9;]*m\|\x1b[(]B\x1b\[m//g' | sudo tee -a "${backup_saveas}.log"
    done
}

_reboot() {
    count=0
    total=$1
    while [ "${count}" -lt "${total}" ]; do
        printf "\rRebooting in %ds  " $(( total - count ))
        sleep 1
        count=$(( count + 1 ))
    done
    echo
    sudo reboot
    exit 0
}

relog() {
    while read -r line; do
        timestamp="$( date +"%Y-%m-%d %H:%M:%S" )"
        echo "[${timestamp}] ${line}"
    done
}

internet_check() {
    for i in {1..60}; do
        if ping -c1 www.google.com &>/dev/null ; then
           _status 0 "Connected to the internet"
            break
        else
            echo "Waiting for an internet connection..."
            sleep 1
        fi
        if [ "${i}" -gt 59 ] ; then
           _status 2 "Not connected to the internet, waiting..."
            echo
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
            -d)
                if [ -n "$2" ] && [ "${2:0:1}" != "-" ]; then
                    backup_destination="$2"
                    backup_mount="$(df --output=source "${backup_destination}")" || _status 1 "Invalid backup destination"
                    if [[ "$(echo "${backup_mount}" | head -n 1)" == "Filesystem" ]]; then
                        if [[ "$(echo "${backup_mount}" | tail -n 1)" =~ "root" ]]; then
                            _status 1 "Backup destination is on root file system"
                        else
                            echo "${backup_destination}"
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
                    if [[ "${do_shrink}" == "shrink" ]]; then
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
    if [ -n "${backup_destination}" ] && [ -n "${backup_name}" ]; then
        backup_saveas="${backup_destination}/BackUp/${backup_name}-$(date '+%Y-%m-%d-%H%M%S')"
        _status 0 "Saving backup to ${backup_saveas}"
    elif [ -z "${backup_destination}" ]; then
        _status 1 "No backup destination supplied"
    elif [ -z "${backup_name}" ]; then
        _status 1 "No backup name supplied"
    fi
}

check_tools() {
    req_tools="parted losetup tune2fs md5sum e2fsck resize2fs"
    for command in $req_tools; do
        command -v "${command}" >/dev/null 2>&1
        if (( $? != 0 )); then
            echo
            echo "${command} is required, press \"y\" to install"
            read -p "" -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]
                then
                    echo
                    sudo apt-get install "${command}"
                else
                    echo
                    _status 1 "${command} is required"
                fi
                echo
        fi
    done
}

clean_repository() {
    echo
    _status 0 "Cleaning out the local repository"
    sudo apt-get clean || _status 2 "Failed to clean the local repository"
    _status 0 "Cleaned out the local repository"
}

copy_system() {
    system_root="$(sudo lsblk -oMOUNTPOINT,PKNAME -rn | awk '$1 ~ /^\/$/ { print $2 }')"
    system_size="$(sudo blockdev --getsize64 /dev/"${system_root}")"
    free_space="$(sudo df "${backup_destination}"| tail -1 | awk '{print $2-$3}')"
    [ $(("${system_size}" * 11 / 10240)) -gt "${free_space}" ] && _status 1 "Not enough free space on destination device"
    [ $(("${system_size}" * 15 / 10240)) -gt "${free_space}" ] && _status 2 "There may not be enough free space on destination device"
    echo
    _status 0 "Copying system - $((system_size / 1073741824))G to back up"
    dd_copy="$(sudo dd bs=1M if="/dev/${system_root}" of="${backup_saveas}.img" status=progress conv=fsync oflag=direct 3>&1 1>&2 2>&3 | tee >(cat - >&2))" || status 1 "Failed to copy system to backup destination"
    _status 0 "System copied $( echo "${dd_copy}" | tail -1 )"
}

fresh_boot() {
    [[ "${do_freshboot}" != "freshboot" ]] && return
    echo
    _status 0 "Adding files for fresh boot"
    mnt_dir=$(mktemp -d)
    mkdir -p "$mnt_dir" || _status 1 "Failed to create temporary mount directory"
    loop_mnt=$(sudo losetup --partscan --find --show "${backup_saveas}.img") || _status 1 "Failed to create loop device"
    sudo mount "${loop_mnt}p1" "$mnt_dir" || _status 1 "Failed to mount copied system image"
    vnstat_current || _status 1 "Failed to get current vnStat version"
    case "${vnstat_version}" in
    
        "1.18-2" )
            cat << EOF | sudo tee -a "${mnt_dir}/freshboot.sh" >/dev/null || _status 1 "Failed to add vnStat 1.18-2 fresh boot commands"
#!/bin/bash

rm /var/lib/vnstat/*
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

rm /var/lib/vnstat/*
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
    
    sudo umount "$mnt_dir" || _status 1 "Failed to unmount copied system image"
    sudo losetup -D || _status 1 "Failed to detach loop device"
    _status 0 "Files for fresh boot added"
}

vnstat_current() {
    vnstat_version="$(sudo dpkg-query -l | grep "vnstat" | tr -s " " | cut -d " " -f 3)" || _status 1 "Failed to get vnStat version"
    case "${vnstat_version}" in
        "" )
            _status 0 "vnStat not installed..."
        ;;
        "2.6-3" | "1.18" )
            _status 0 "vnStat ${vnstat_version} installed..."
        ;;
        "*" )
            _status 2 "vnStat ${vnstat_version} not supported..."
        ;;
    esac
}

pi_shrink() {
    [[ "${do_shrink}" != "shrink" ]] && return
    echo
    _status 0 "Downloading PiShrink Script"
    wget -qO - "https://raw.githubusercontent.com/minimaded/backup_scripts/main/pishrink.sh" > "/tmp/pishrink.sh" || _status 1 "Failed to get PiShrink script"
    sudo chmod +x "/tmp/pishrink.sh"
    echo
    _status 0 "Shrinking system copy with PiShrink"
    sudo "/tmp/pishrink.sh" -s "${backup_saveas}.img" || _status 1 "Failed to shrink system copy with PiShrink"
    _status 0 "System copy shrunk with PiShrink"
}

zero_free() {
    echo
    _status 0 "Zeroing free space on ${part_n} to improve compression"
    part_n=$1
    mnt_dir=$(mktemp -d)
    mkdir -p "$mnt_dir" || _status 1 "Failed to create temporary mount directory"
    loop_mnt=$(sudo losetup --partscan --find --show "${backup_saveas}.img") || _status 1 "Failed to create loop device"
    sudo mount "${loop_mnt}${part_n}" "$mnt_dir" || _status 1 "Failed to mount copied system image"
    m_to_clean=$(sudo df -k "${loop_mnt}${part_n}" -BM | tail -1 | awk '{print $2-$3}')"M"
    _status 0 "There is ${m_to_clean} to clean for ${part_n}"
    dd_zero="$(sudo dd bs=1M if=/dev/zero of="${mnt_dir}/delete_me" status=progress conv=fsync iflag=nocache oflag=direct 3>&1 1>&2 2>&3 | tee >(cat - >&2))" || \
    _status 0 "Free space zeroed $( echo "${dd_zero}" | tail -1 )"
    sync
    sync
    _status 0 "Delete dummy file"
    sudo rm -f -v "${mnt_dir}/delete_me" || _status 1 "Failed to delete dummy file"
    sync
    sync
    sudo umount "$mnt_dir" || _status 1 "Failed to unmount copied system image"
    sudo losetup -D || _status 1 "Failed to detach loop device"
    _status 0 "Zeroed free space on ${part_n}"
}

compress_zip() {
    echo
    _status 0 "Compressing backup"
    sudo gzip -v "${backup_saveas}.img" || _status 1 "Failed to compress backup"
    _status 0 "Backup compressed"
}

_colors
script_path="$( readlink -f "$0" )"
user_name="$( sudo ls "/home" | tail -n 1 )"
_status 0 "Username is ${user_name}" | tee -a | log_file
parse_params "$@"
#do_all | tee -a | log_file
