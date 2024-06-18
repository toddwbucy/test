# Script Name: linux_patcher
#
# Version: 2.5.5
#
# Author: michael.quintero@rackspace.com
#
# Description: This script can help automate much of not all of the standard patching process. It features an option set for running on full auto, or even just a quick QC check, and generates a log file in the $CHANGE directory. 
# Has logic to determine if the patch and reboot has already occurred and will continue with the reamining portion of the patch process, after reboot. This version supports Redhat versions 7-9, Amazon Linux, and Debian/Ubuntu.
#
# ALWAYS USE THE FULL KERNEL NAME WHEN SPECIFYING A KERNEL TO USE!!!! For example, with RHEL distros, you will set the -k flag with 'kernel-4.18.0-513.24.1.el8_9'. Do not use '4.18.0-513.24.1.el8_9' or nothing will happen!
#
# Usage: When running the script, you need to be root. Also, you will ALWAYS need to set the '-c' change switch.
#
# By design as a failsafe, the QC function is set to run if you invoke 'linux_patcher -c CHG0123456' with no other switches. I have left the '-q' switch for the user to intentionally invoke though, for increased usability. 
#
# To ONLY create the patchme script, run 'bash linux_patcher -c CHG0123456 -k $MY_KERNEL'
#
# To ONLY install a specified kernel on the system and not perform any patching, run 'bash linux_patcher -c CHG0123456 -k $MY_KERNEL -a'. 
#
# To reboot immediately after the kernel install or patch run, you need to specify such using '-r', like so 'bash linux_patcher -c CHG0123456 -r -k $MY_KERNEL -a' or 'bash linux_patcher -c CHG0123456 -r -a', respectively.
#
# The script will NOT reboot on its own!!!!!!!!!!!!!!!!!!!!!! The '-r' flag needs to be set to do so.
#
# Lastly, if you want to perform patching of the instance...which for redhat is just the security packages and for Ubuntu is all packages, run 'bash linux_patcher -c CHG0123456 -a'.
# After performing a manual patch, you can run with the  '-p' switch if you don't reboot, to generate the maintenance report, 'bash linux_patcher -c CHG0123456 -p' or if you do reboot, you can use the '-a' switche, and the script will pick up where it left off.


#!/bin/bash

#Better be the root user otherwise, no dice!
if [[ "$EUID" -ne 0 ]]; then
   echo "YOU NEED TO RUN THE SCRIPT AS ROOT, TRY AGAIN!" 
   exit 1
fi

# Gotta figure out who you are. This is a big dog function.
distro_ball() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        dis_version=$VERSION_ID
        dis_name=$ID
        echo "DETECTED DISTRIBUTION: $dis_name, VERSION: $dis_version"
    else
        echo "CANNOT DETERMINE THE DISTRIBUTION OR VERSION."
        return 1
    fi

# Primary identification logic for the distros lives here. Tread carefully...the global variable 'package_manager' lives here.
    case $dis_name in
        rhel|centos|fedora|amzn|ol)
            export package_manager="yum"
            if [[ "$dis_name" == "amzn" || "$dis_name" == "ol" ]]; then
                echo "$(grep "^PRETTY_NAME=" /etc/os-release | cut -d'"' -f2)"
            else
                echo "Red Hat Version : $(cat /etc/redhat-release)"
            fi
            echo "Current Kernel: $(uname -r)"
            next_kernel=$(yum check-update kernel | grep -E 'kernel.x86_64*' | awk '{print $2}')
            [[ -z "$next_kernel" ]] && echo "No new kernel version available." || echo "Next Kernel Version: ${next_kernel}"
            $package_manager updateinfo list security installed | grep RHSA > /root/$CHANGE/security_installed.before
            ;;
        debian|ubuntu)
            export package_manager="apt"
            echo "$(grep "^PRETTY_NAME=" /etc/os-release | cut -d'"' -f2)"
            echo "Current Kernel: $(uname -r)"
            next_kernel=$(apt-get update > /dev/null; apt-get --just-print upgrade | grep -i linux-image)
            [[ -z "$next_kernel" ]] && echo "No new kernel version available." || echo "Next Kernel Version: ${next_kernel}"
            ;;
        *)
            echo "UNSUPPORTED DISTRIBUTION: $dis_name"
            return 1
            ;;
    esac
}

# Function where most of the updating happens. Used to be called, Falcon_checker, but it's been exapanded to take on more work.
modernize() {
    if [[ -n "$Kernel" ]]; then
        if [[ "$package_manager" == "yum" ]]; then
            echo "Installing specific kernel version $Kernel on RHEL-based distribution."
            $package_manager install $Kernel -y
        elif [[ "$package_manager" == "apt" ]]; then
            echo "Installing specific kernel version $Kernel on Debian-based distribution."
            $package_manager install $Kernel -y
        else
            echo "Unsupported package manager or distribution."
        fi
        return
    fi

    if pgrep -f "/opt/CrowdStrike/falcond" > /dev/null 2>&1; then
        echo "FALCONCTL IS RUNNING. CHECKING KERNEL VERSION COMPATABILITY."
        next_kernel_version=$($package_manager check-update kernel | grep -E 'kernel.x86_64*' | awk '{print $2}')

        if [[ -z "$next_kernel_version" ]]; then
            echo "NO KERNEL UPDATES FOUND. RUNNING $package_manager update-minimal WITH KERNEL EXCLUSION."
            $package_manager update-minimal --security --exclude=kernel* -y
            return 
        fi

        falcon_check_output=$(/opt/CrowdStrike/falcon-kernel-check -k "$next_kernel_version" 2>&1)
        if echo "$falcon_check_output" | grep -q "is not supported by Sensor"; then
            echo "THE NEWEST AVAILABLE KERNEL VERSION IS NOT SUPPORTED BY FALCON SENSOR. RUNNING $package_manager UPDATE WITH KERNEL EXCLUSION."
            $package_manager update-minimal --security --exclude=kernel* -y
        elif echo "$falcon_check_output" | grep -q "CROWDSTRIKE NOT FOUND"; then
            echo "CROWDSTRIKE COMMAND FAILURE: CROWDSTRIKE NOT FOUND."
            $package_manager update --security -y
        else
            echo "NEXT KERNEL VERSION IS SUPPORTED BY FALCON SENSOR. RUNNING FULL $package_manager UPDATE."
            $package_manager update --security -y
        fi
    else
        echo "FALCONCTL IS NOT FOUND OR RUNNING. PERFORMING REGULAR SYSTEM UPDATES."
        if [ "$package_manager" = "yum" ]; then
            $package_manager update --security -y
        elif [ "$package_manager" = "apt" ]; then
            $package_manager update && $package_manager upgrade -y
        fi
    fi
}

# Had to split the logic for creating security update CYA files in the change directory, from the before and after markers to reduce redunduancy by having to include trhe logic more than once. 
# So I opted to call once in the post_reboot_operations
post_security_op() {
    if [[ "$package_manager" == "yum" ]]; then
        echo "RUNNING OPERATIONS FOR RED HAT/AMAZON/ORACLE LINUX"
        $package_manager updateinfo list security installed | grep RHSA > /root/$CHANGE/security_installed.after
    elif [[ "$package_manager" == "apt" ]]; then
        echo "RUNNING OPERATIONS FOR DEBIAN/UBUNTU"
        maintdate=$(date "+%Y-%m-%d")
        grep " installed " /var/log/dpkg.log | grep "$maintdate" | awk '{print $4, $5}' | uniq | sort > /root/$CHANGE/security_installed.after
    else
        echo "UNSUPPORTED PACKAGE MANAGER: $package_manager"
        return 1
    fi
}

# For before/after comparisons, called in the pre_reboot_operations() function
before_markers() {
    ss -ntlp | awk '{print $6}' | awk -F ':' '{print $NF}' | sort | uniq > /root/$CHANGE/netstat_running.before
    ps -e -o ppid,pid,cmd | egrep '^\s+1\s+' > /root/$CHANGE/ps_running.before
    systemctl list-units --type=service > /root/$CHANGE/systemctl_running.before
    mount > /root/$CHANGE/mount.before
    uname -r > /root/$CHANGE/kernel.before
    echo "(Crowdstrike Running?): $(/opt/CrowdStrike/falconctl -g --rfm-state 2>/dev/null || echo "CROWDSTRIKE NOT FOUND RUNNING ON THIS SYSTEM!!!")" > /root/$CHANGE/crowdstrike.before
    echo "Hostname: $(hostname)" && echo "IP Address: $(hostname -I)" > /root/$CHANGE/hostname_info.before
    echo "/etc/hosts checksum: $(md5sum /etc/hosts | cut -d ' ' -f1)" > /root/$CHANGE/hosts_info.before 
    echo "/etc/resolv.conf checksum: $(md5sum /etc/resolv.conf | cut -d ' ' -f1)" > /root/$CHANGE/resolv_info.before
}

# For before/after comparisons, but has a little more info for the report. Is called in the post_reboot_operations()
after_markers() {
    ss -ntlp | awk '{print $6}' | awk -F ':' '{print $NF}' | sort | uniq > /root/$CHANGE/netstat_running.after
    ps -e -o ppid,pid,cmd | egrep '^\s+1\s+' > /root/$CHANGE/ps_running.after
    systemctl list-units --type=service > /root/$CHANGE/systemctl_running.after
    mount > /root/$CHANGE/mount.after
    uname -r > /root/$CHANGE/kernel.after
    grep .service /root/$CHANGE/systemctl_running.before | awk '{print $1,$2,$3,$4}' | sort > /root/$CHANGE/systemctl_running.before.1
    grep .service /root/$CHANGE/systemctl_running.after | awk '{print $1,$2,$3,$4}' | sort > /root/$CHANGE/systemctl_running.after.1
    grep ^/dev /root/$CHANGE/mount.before > /root/$CHANGE/mount.before.1
    grep ^/dev /root/$CHANGE/mount.after > /root/$CHANGE/mount.after.1
    echo "(Crowdstrike Running?): $(/opt/CrowdStrike/falconctl -g --rfm-state 2>/dev/null || echo "CROWDSTRIKE NOT FOUND RUNNING ON THIS SYSTEM!!!")" > /root/$CHANGE/crowdstrike.after
    diff -U0 /root/$CHANGE/systemctl_running.before.1 /root/$CHANGE/systemctl_running.after.1
    diff -U0 /root/$CHANGE/mount.before.1 /root/$CHANGE/mount.after.1
    echo "Hostname: $(hostname)" && echo "IP Address: $(hostname -I)" > /root/$CHANGE/hostname_info.after
    echo "/etc/hosts checksum: $(md5sum /etc/hosts | cut -d ' ' -f1)" > /root/$CHANGE/hosts_info.after
    echo "/etc/resolv.conf checksum: $(md5sum /etc/resolv.conf | cut -d ' ' -f1)" > /root/$CHANGE/resolv_info.after
}

# To see changes/updates to the instance in a neat little report. A log file is generated in the change directory btw. This function is called in the post_reboot_operations()
maintenance_report() {
    maintdate=$(date "+%d %b %Y")
    
    if [ -z "$CHANGE" ]; then
        echo "CHANGE VARIABLE IS NOT SET, EXITING."
        return 1
    fi

    LOG_FILE="/root/$CHANGE/maintenancelog.txt"

# See the below in the echo block. This is where we get the amount of packages installed.
count_packages_installed_last_update() {
    if [[ "$package_manager" == "yum" ]]; then
        rpm -qa --last 2>/dev/null | grep "$maintdate" | uniq | wc -l
    elif [[ "$package_manager" == "apt" ]]; then
        maintdate=$(date "+%Y-%m-%d")
        grep " installed " /var/log/dpkg.log | grep "$maintdate" | awk '{print $4, $5}' | uniq | wc -l
    else
        echo "UNSUPPORTED PACKAGE MANAGER: $package_manager"
    fi
}

# See just a tad futher below in the echo block. This is where we list the packages installed. If we don't want this info, just comment out lines 202 and 203. I felt it was important to include such verbose info, as a CYA.
packages_installed_last_update() {
    if [[ "$package_manager" == "yum" ]]; then
        rpm -qa --last 2>/dev/null | grep "$maintdate" | sort | uniq
    elif [[ "$package_manager" == "apt" ]]; then
        maintdate=$(date "+%Y-%m-%d")
        grep " installed " /var/log/dpkg.log | grep "$maintdate" | awk '{print $4, $5}' | sort | uniq
    else
        echo "UNSUPPORTED PACKAGE MANAGER: $package_manager"
    fi
}

    {
        echo "===== Maintenance report for $(hostname -s) ====="
        echo "(Current date): $(date)"
        echo "(Server running since): $(uptime -s)"
        /opt/CrowdStrike/falconctl -g --rfm-state 2>/dev/null | grep -q 'rfm-state=false' && echo "(Is Crowdstrike running): Yes" || echo "(Is Crowdstrike running): No"
        echo "(Packages installed during maintenance): $(count_packages_installed_last_update)"
        echo "(Previous running kernel version): $(cat /root/$CHANGE/kernel.before)"
        echo "(Current running kernel version): $(uname -r)"
        echo "(Kernel packages installed during maintenance):
        $(packages_installed_last_update)"
        hostname_changed=$(diff <(grep 'Hostname' /root/$CHANGE/hostname_info.before) <(grep 'Hostname' /root/$CHANGE/hostname_info.after) > /dev/null && echo "No" || echo "Yes")
        hosts_changed=$(diff <(grep '/etc/hosts checksum' /root/$CHANGE/hosts_info.before) <(grep '/etc/hosts checksum' /root/$CHANGE/hosts_info.after) > /dev/null && echo "No" || echo "Yes")
        resolv_conf_changed=$(diff <(grep '/etc/resolv.conf checksum' /root/$CHANGE/resolv_info.before) <(grep '/etc/resolv.conf checksum' /root/$CHANGE/resolv_info.after) > /dev/null && echo "No" || echo "Yes")
        echo "(Hostname changed?): $hostname_changed"
        echo "(Hosts file changed?): $hosts_changed"
        echo "(Resolv.conf change?): $resolv_conf_changed"
    } | tee -a "$LOG_FILE"
}

# Big dawg function, for those times when you just want the instance to give a quick diagnostic report, in relation to patching.
QC() {
    clear
colors=(31 32 33 34 35 36)

animate_text() {
    local text="QC SEQUENCE INITIATED..."
    local delay=0.2
    local duration=3
    local end_time=$((SECONDS + duration))

    echo -ne "\r\033[K"

    while [ $SECONDS -lt $end_time ]; do
        for color in "${colors[@]}"; do
            if [ $SECONDS -ge $end_time ]; then
                break
            fi
            echo -ne "\033[${color}m${text}\033[0m"
            sleep $delay
            echo -ne "\r\033[K"
        done
    done
}

animate_text

# This is a failsafe, in the event the '-c' switch doesn't set, for whatever reason, the change directory
[ ! -d "/root/$CHANGE" ] && mkdir -p "/root/$CHANGE"

    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case $ID in
            ubuntu|debian)
                package_manager="apt"
                ;;
            rhel|amzn|ol) # Added 'ol' for Oracle Linux
                package_manager="yum"
                ;;
            *)
                echo "DISTRIBUTION $ID NOT SUPPORTED BY THIS SCRIPT."
                test_repos_result="FAILED"
                return 1
                ;;
        esac
    else
        echo "UNABLE TO DETERMINE DISTRIBUTION."
        test_repos_result="FAILED"
        return 1
    fi

# The patcheme section. I decided to leave in-line for now, but will probably modularize into a function which is only called with the switch.
# Speaking of which, if a user specifies a '-k' flag with a kernel, we'll generate the patchme files for Qualys
    if [ ! -z "$Kernel" ]; then  
        echo "KERNEL VERSION SPECIFIED: $Kernel. GENERATING patchme.sh..."

        if [[ "$ID" == "rhel" || "$ID" == "amzn" || "$ID" == "ol" ]]; then
            cat <<EOF > /root/$CHANGE/patchme.sh
#!/bin/bash
newkernel="$Kernel"
$package_manager install kernel-$Kernel -y
reboot
EOF
        elif [[ "$ID" == "ubuntu" || "$ID" == "debian" ]]; then
            cat <<EOF > /root/$CHANGE/patchme.sh
#!/bin/bash
newkernel="$Kernel"
apt-get update
apt-get install $Kernel -y
reboot
EOF
        else
            echo "DISTRIBUTION NOT SUPPORTED FOR KERNEL PATCHING"
            return 1
        fi

        chmod +x /root/$CHANGE/patchme.sh
        echo -e "\033[32mpatchme.sh SCRIPT SUCCESSFULLY GENERATED.\033[0m"
        return 
    fi

    export PYTHONWARNINGS="ignore"
    local test_repos_result="PASSED"
    local disk_space_check_result="PASSED"


# I had to add distro identification within the QC function as QC is called on its own. the distro_ball() function sin't invoked with QC.
# This was done to ensure the independence of the QC function
check_kernel_updates() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
    else
        echo "UNABLE TO IDENTIFY THE DISTRIBUTION IN USE"
        return 1
    fi

    case $ID in
        ubuntu|debian)
            apt-get update > /dev/null 2>&1
            updates=$(apt list --upgradable 2>&1 | grep 'linux-image') 
            [[ -z "$updates" ]] && echo "NO KERNEL UPDATES AVAILABLE" || echo "$updates"
            ;;
        rhel|amzn|ol)
            yum list kernel --showduplicates | tail -5
            ;;
        *)
            echo "DISTRIBUTION $ID NOT SUPPORTED BY THIS SCRIPT."
            return 1
            ;;
    esac
}

clear
    echo
    echo "--------------------------------"
    echo "TESTING REPOSITORY FUNCTIONALITY"
    echo "--------------------------------"
    echo

if [[ "$package_manager" == "yum" ]]; then
    clean_cmd="${package_manager} makecache"
else
    clean_cmd="apt-get check && apt-get autoclean"
fi

echo "Executing: $clean_cmd"
if ! $clean_cmd; then
    echo -e "\033[31mQC FAILED: ISSUE MAKING CACHE. POSSIBLY DUE TO PERMISSION ISSUES, CORRUPTED CACHE FILES, OR PACKAGE MANAGER CONFIGURATION ERRORS\033[0m"
    test_repos_result="FAILED"
else
    echo -e "\033[32mQC REPOSITORY FUNCTIONALITY TEST PASSED.\033[0m"
fi

if [ "$test_repos_result" = "FAILED" ]; then
    return 1
fi

    echo "------------------------------"
    echo "CLEARING PACKAGE MANAGER CACHE"
    echo "------------------------------"
    echo "Executing: ${package_manager} clean all"
    if ! bash -c "${package_manager} clean all"; then
        echo -e "\033[31mQC FAILED: ISSUES CLEANING CACHE.\033[0m"
        test_repos_result="FAILED"
        return 1
    fi

    echo "-------------------"
    echo "CHECKING DISK SPACE"
    echo "-------------------"
    local var_space=$(df -BG /var | tail -1 | awk '{print $4}' | sed 's/G//')
    if [[ "$var_space" -lt 3 ]]; then
        echo "QC DISK SPACE CHECK FAILED: LESS THAN 3GB AVAILABLE IN /var"
        test_repos_result="FAILED"
        echo "PLEASE REVIEW DISK SPACE"
        df -BG /var
        sleep 2
        return 1
    else
        echo "SUFFICIENT DISK SPACE IN /var. PROCEEDING WITH THE SCRIPT."
        df -BG /var
        sleep 2
    fi

    echo -e "\033[32mQC PASSED FOR DISK SPACE\033[0m"


    echo "--------------------"
    echo "GENERATING QC REPORT"
    echo "--------------------"
    sleep 5

    {
        echo -e "\033[33m===== QC report for $(hostname -s) =====\033[0m"
        echo "(Current date): $(date)"
        echo "(Server running since): $(uptime)"
        echo "(Current running kernel version): $(uname -r)"
        /opt/CrowdStrike/falconctl -g --rfm-state 2>/dev/null | grep -q 'rfm-state=false' && echo "(Is Crowdstrike running): Yes" || echo "(Is Crowdstrike running): No"
        echo "(Current Crowdstrike Version): $(/opt/CrowdStrike/falconctl -g --version 2>/dev/null)"
        echo "(Available Kernel Updates):"
        echo "$(check_kernel_updates)"
        echo "(Test Repositories Result): $test_repos_result"
        echo "(Disk Space Check Result): $disk_space_check_result"
        echo -e "\033[33m========================================\033[0m"
    } | tee "/root/$CHANGE/qc_report.txt"
}

# When you patch an instance, this is where the directional flow happens. The beginning of...the job.
pre_reboot_operations() {
    found_marker=$(find /root/$CHANGE -name "script_reboot_marker" -print -quit)

    if [ -z "$found_marker" ]; then
        echo "PERFORMING PRE-REBOOT OPERATIONS..."
        
        temp_file="/root/$CHANGE/script_reboot_marker"
        
        touch $temp_file
        echo "$CHANGE" > "$temp_file"

        if [ -n "$CHANGE" ]; then
            echo "$CHANGE" > $temp_file
        else
            echo "CHANGE VARIABLE IS NOT SET"
        fi

        [ -d "/root/$CHANGE" ] || mkdir -p "/root/$CHANGE"

        # QC, Commented out as not necessary to run when patching, should be treated separately...but just in case
        /opt/CrowdStrike/falconctl -g --rfm-state 2>/dev/null | grep -q 'rfm-state=false' && echo "Is Crowdstrike running: Yes" || echo "Is Crowdstrike running: No"
        echo "Crowdstrike: $(/opt/CrowdStrike/falconctl -g --version 2>/dev/null)"
        echo "Falcon Kernel Check: $(/opt/CrowdStrike/falcon-kernel-check 2>/dev/null)"
        distro_ball
        before_markers
        modernize

        if [[ "$reboot_flag" -eq 1 ]]; then
            echo
            echo -e "\033[32mREBOOTING NOW...\033[0m"
            echo
            reboot
        else
            echo
            echo -e "\033[31mREBOOT NOT REQUESTED. COMPLETING OPERATIONS WITHOUT A REBOOT.\033[0m"
            echo
        fi
    else
        post_reboot_operations
    fi
}

post_reboot_operations() {
    clear
found_marker=$(find /root/$CHANGE -name "script_reboot_marker" -print -quit)
colors=(31 32 33 34 35 36)

animate_text() {
    local text="POST REBOOT OPERATIONS SEQUENCE INITIATED..."
    local delay=0.2 
    local duration=3
    local end_time=$((SECONDS + duration)) 

    echo -ne "\r\033[K"

    while [ $SECONDS -lt $end_time ]; do
        for color in "${colors[@]}"; do
            if [ $SECONDS -ge $end_time ]; then
                break
            fi
            echo -ne "\033[${color}m${text}\033[0m"
            sleep $delay
            echo -ne "\r\033[K"
        done
    done
}

    animate_text
    distro_ball
    after_markers
    post_security_op
    maintenance_report
    rm -f "$found_marker"
}

auto_mode () {

if [ -z "$CHANGE" ]; then
    echo "Error: CHANGE variable not set. Use the -c flag to set it."
    exit 1
fi

clear
colors=(31 32 33 34 35 36)

animate_text() {
    local text="AUTOMATED PATCH SEQUENCE INITIATED..."
    local delay=0.2 
    local duration=3
    local end_time=$((SECONDS + duration)) 

    echo -ne "\r\033[K"

    while [ $SECONDS -lt $end_time ]; do
        for color in "${colors[@]}"; do
            if [ $SECONDS -ge $end_time ]; then
                break
            fi
            echo -ne "\033[${color}m${text}\033[0m"
            sleep $delay
            echo -ne "\r\033[K"
        done
    done
}

    animate_text
    pre_reboot_operations
}

reboot_flag=0 

# Note! The reboot switch must be before any other flag
while getopts "c:qaphrk:" opt; do
    case $opt in
        r) reboot_flag=1
           ;;
        c) CHANGE="$OPTARG"
           mkdir -p /root/"$CHANGE"
           ;;
        k) Kernel="$OPTARG"
           ;;
        q) QC
           exit 0
           ;;
        a) auto_mode
           exit 0
           ;;
        p) if [ -f "/root/$CHANGE/script_reboot_marker" ]; then
               post_reboot_operations
           else
               echo "No reboot marker found. Exiting."
           fi
           exit 0
           ;;
        h) echo "Usage: $0 [-r Reboot. Must specify before -a and -k switch ] [-c Change Ticket] [-q QC Only] [-a Automatic Mode. To run security patching] [-p Post Reboot Operations] [-h Help] [-v Version] [-k Kernel Version]"
           exit 0
           ;;
        *) echo "Invalid option: -$OPTARG" >&2
           exit 1
           ;;
    esac
done

if [ -z "$CHANGE" ]; then
    echo "Error: CHANGE variable not set. Use the -c flag to set it."
    exit 1
fi

QC
