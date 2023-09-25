#!/bin/bash

if [ "$(id -u)" != '0' ]; 
then
	echo 'Please Run Script As: sudo sh script.sh'
    exit 2 
fi

echo 'pie.secure Will Log Everything Into /var/log/piesecure.log'
echo 'Loading Script...'
sleep 1


# Backup essential configuration files
backup_configs() {
    echo 'Backing up essential configuration files...'
    mkdir -p /backup/piesecure
    cp /etc/passwd /backup/piesecure/passwd.backup
    cp /etc/shadow /backup/piesecure/shadow.backup
    cp /etc/ssh/sshd_config /backup/piesecure/sshd_config.backup
    echo 'Backup completed! Files saved in /backup/piesecure/'
    sleep 3
}

# Log rotation for piesecure.log
rotate_logs() {
    echo 'Rotating piesecure.log...'
    if [ -f "$LOG_FILE" ]; then
        mv "$LOG_FILE" "$LOG_FILE.old"
    fi
    echo 'Log rotation completed! Previous logs saved as piesecure.log.old'
    sleep 3
}

# Log File
LOG_FILE="/var/log/piesecure.log"

log() {
    local message="$1"
    echo "$message"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$LOG_FILE"
}

show_menu() {
    echo "\e[1;37m┌────────────────────────────────────────────────┐\e[0m"
    echo "\e[1;37m│\e[0m\e[1;37m-------------------pie.secure-------------------\e[0m\e[1;37m│\e[0m"
    echo "\e[1;37m│\e[0m\e[1;37m------------------------------------------------\e[0m\e[1;37m│\e[0m"
    echo "\e[1;37m│\e[0m\e[1;37m-------------------Version 1--------------------\e[0m\e[1;37m│\e[0m"
    echo "\e[1;37m└────────────────────────────────────────────────┘\e[0m"
    echo
    echo  "\e[1;33m1. Update\e[0m"
    echo  "\e[1;33m2. Firewall Setup (UFW)\e[0m"
    echo  "\e[1;33m3. Firewall Policies\e[0m"
    echo  "\e[1;33m4. Fix Shadow Permissions\e[0m"
    echo  "\e[1;33m5. User Management Menu\e[0m"
    echo  "\e[1;33m6. SSH Permissions\e[0m"
    echo  "\e[1;33m7. Password Policies\e[0m"
    
    echo  "\e[1;33m9. Backup Essential Configurations\e[0m"
    echo  "\e[1;33m10. Rotate piesecure.log\e[0m"

    echo  "\e[1;33m11. Secure SSH Configuration (Disable Root Login)\e[0m"
    echo  "\e[1;33m12. Set Up Daily Lynis and CHKrootkit Scans\e[0m"
    echo  "\e[1;33m13. Monitor Failed SSH Logins\e[0m"
    echo  "\e[1;33m14. Check System Health\e[0m"
    echo  "\e[1;33m8. Malware & Vulnerabilities Check\e[0m"
    echo
    echo  "\e[1;37mEnter A Number:\e[0m "
}

while true
do
    log
    clear
    show_menu
    sleep 1
    
    read user_number; #user_number is a variable that reads from the keyboard
    
    
    case $user_number in
        1)
            echo 'This Will Update & Upgrade Packages, and Enable Auto Updates'
            echo 'Press Control + C To Cancel Now, Do Not Cancel While Script Is Running'
            sleep 5
            apt update -y
            apt upgrade -y
            apt autoclean
            apt autoremove
            apt-get install unattended-upgrades
            dpkg-reconfigure unattended-upgrades
            echo 'Complete!'
            get_user_feedback
            echo 'Returning To Menu!'
            sleep 3
            ;;
        2)
            echo 'This Will Check If UFW Is Installed (Will Install If Its Not) and Enable It'
            echo 'Press Control + C To Cancel Now, Do Not Cancel While Script Is Running'
            sleep 5
            if is_tool_installed ufw  
            then
                echo 'UFW Is Installed, Enabling If Not Already'
                sleep 3
                ufw enable
                echo 'Complete! Returning To Menu!'
                sleep 3 
            else
                echo 'UFW Is Not Installed, Installing and Enabling UFW'
                sleep 3
                apt-get install ufw -y
                ufw enable
                echo 'Complete! Returning To Menu!'
                sleep 3 
            fi
            ;;
        3)
            echo 'This Will Disable HTTP, SMTP, and Other Unsecure Ports'
            echo 'Press Control + C To Cancel Now, Do Not Cancel While Script Is Running'
            sleep 5
            ufw deny out 25 # Disables Outgoing SMTP Mail
            ufw deny 80 # Disables All HTTP Traffic
            ufw deny 23 # Disables Telnet
            ufw deny 21 # Disables FTP
            ufw deny 161 # Disables SNMP
            ufw deny 123/udp # Disables NTP
            ufw deny 19/udp # Disbales Chargen
            sleep 2
            echo 'Complete!'
            get_user_feedback
            echo 'Returning To Menu!'
            sleep 3
            ;;

        4)
            echo 'This Sets The Permissions Of The Shadow File So Only The Root Can Access It'
            echo 'Press Control + C To Cancel Now, Do Not Cancel While Script Is Running'
            sleep 5
            chmod 000 /etc/shadow
            ls -l /etc/shadow
            sleep 5
            echo 'Check Above And Verify If The Permissions Have Changed'
            sleep 5
            ;;
        
        5)
            show_user_submenu()
                {
                    echo 'All Current Users:'
                    cut -d: -f1 /etc/group
                    echo ''
                    echo ''
                    echo '~~~~~~~~~~~~~~User Management Menu~~~~~~~~~~~~~'
                    echo '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
                    echo 'Scroll Up To See List Of All Curent Local Users'
                    echo '1. Add A User'
                    echo '2. Remove A User'
                    echo '3. Remove A User Admin'
                    echo '4. Grant A User Admin'
                    echo '5. Secure Sudoers File'
                    echo '6. Return To Main Menu'

                    echo 'Enter A Number: '
                }
            
            while true
            do
                clear
                show_user_submenu
                sleep 1
                read user_submenu_number; #user_menu_number is a variable that reads from the keyboard
                case $user_submenu_number in
                    1)
                        read -p 'Enter The Username To Add: ' username
                        read -p 'Do You Want To Give This User Admin Privileges? (y/n): ' admin

                        if [ '$admin' = 'y' ]; then
                            useradd -m -s /bin/bash -G  '$username'
                        else
                            useradd -m -s /bin/bash '$username'
                        fi

                        echo 'User $username created successfully!'
                        sleep 3
                        ;;
                    2)
                        read -p 'Enter The Username To Delete: ' username
                        deluser --remove-home '$username'
                        echo 'User $username removed successfully!'
                        sleep 3
                        ;;
                    3)
                        read -p 'Enter the username: ' username
                        deluser '$username' sudo
                        echo 'Admin privileges removed from user $username successfully!'
                        sleep 3
                        ;;
                    4)
                        read -p 'Enter the username: ' username
                        usermod -aG sudo '$username'
                        echo 'Admin privileges added to user $username successfully!'
                        sleep 3
                        ;;
                    
                    5)
                        if [[ -w '/etc/sudoers' ]]; then
                            echo 'The sudoers file is writable. Fixing the issue...'
                            chmod -w /etc/sudoers
                            echo 'The sudoers file has been fixed.'
                            sleep 3
                        else
                            echo 'The sudoers file is not writable. No action needed.'
                            sleep 3
                        fi

                        ;;
                    6)
                        break
                        ;;
                    *)
                        echo 'Invalid Option. Please Try Again.'
                        sleep 3
                        ;;
                esac
            done
            ;;
        6)
            echo 'This Will Check If OpenSSH Is Installed (Will Install If Its Not) and Secure It'
            echo 'NOTE: THIS ONLY CHECKS FOR CLIENT VERSION OF OPENSSH NOT THE SERVER VERSION'
            echo 'Press Control + C To Cancel Now, Do Not Cancel While Script Is Running'
            sleep 5
            if apt list --installed openssh-client | grep -q 'openssh-client';
            then
                echo 'OpenSSH Is Installed, Securing Now'
                echo 'Removing SSH Root Login'
                # Removes SSH Root Login Permissions
                sleep 3
                sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
                sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
                
                echo 'Changing SSH port to 2222...'
                # Changing SSH Port to 2222 to Reduce Automated Attacks
                sleep 2
                sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
                echo 'Restarting SSH service...'
                sleep 2
                systemctl restart sshd

                echo 'Installing Fail2Ban...'
                # Installing Fail2Ban (Protects Against Brute Force Attacks)
                sleep 2
                apt update
                apt install -y fail2ban
                cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
                sed -i 's/enabled = false/enabled = true/' /etc/fail2ban/jail.local
                systemctl restart fail2ban

                echo 'Configuring UFW firewall...'
                # Enabling UFW Firewall, Allowing New Port 2222
                sleep 2
                apt install -y ufw
                ufw allow 2222/tcp
                ufw enable
                echo 'Generating SSH Key Pairs (If Not Already)'
                # Generating 4096-bit SSH Key Pairs
                if [ ! -f ~/.ssh/id_rsa ]; then
                    echo 'Generating SSH key pair...'
                    ssh-keygen -t rsa -b 4096
                fi

                systemctl restart sshd
                echo 'Complete! Returning To Menu!'
                sleep 3 
            else
                echo 'OpenSSH Is Not Installed, Installing and Securing'
                sleep 3
                apt-get install openssh-client
                echo 'Removing SSH Root Login'
                # Removes SSH Root Login Permissions
                sleep 3
                sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
                sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
                
                echo 'Changing SSH port to 2222...'
                # Changing SSH Port to 2222 to Reduce Automated Attacks
                sleep 2
                sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
                echo 'Restarting SSH service...'
                sleep 2
                systemctl restart sshd

                echo 'Installing Fail2Ban...'
                # Installing Fail2Ban (Protects Against Brute Force Attacks)
                sleep 2
                apt update
                apt install -y fail2ban
                cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
                sed -i 's/enabled = false/enabled = true/' /etc/fail2ban/jail.local
                systemctl restart fail2ban

                echo 'Configuring UFW firewall...'
                # Enabling UFW Firewall, Allowing New Port 2222
                sleep 2
                apt install -y ufw
                ufw allow 2222/tcp
                ufw enable
                echo 'Generating SSH Key Pairs (If Not Already)'
                # Generating 4096-bit SSH Key Pairs
                if [ ! -f ~/.ssh/id_rsa ]; then
                    echo 'Generating SSH key pair...'
                    ssh-keygen -t rsa -b 4096
                fi

                systemctl restart sshd
                echo 'Complete! Returning To Menu!'
                sleep 3 
            fi

        ;;

        7)
            min_length=12

            # Set the minimum number of lowercase, uppercase, digit, and special characters (adjust as needed)
            min_lowercase=2
            min_uppercase=2
            min_digits=2
            min_special=2

            max_days=90
            min_days=7
            warn_days=14

            # Update the common-password PAM configuration
            echo 'Configuring secure password policies...'

            cat <<EOL > /etc/security/pwquality.conf
            minlen = $min_length
            minclass = $min_lowercase
            minclass = $min_uppercase
            minclass = $min_digits
            minclass = $min_special
EOL
            # Update the common-password PAM configuration
            cat <<EOL > /etc/security/pwquality.conf
            password requisite pam_pwquality.so retry=3 minlen=$min_length minclass=$min_lowercase minclass=$min_uppercase minclass=$min_digits minclass=$min_special enforce_for_root
EOL
            cat <<EOL > /etc/security/pwaging.conf
            password requisite pam_pwquality.so retry=3 minlen=$min_length minclass=$min_lowercase minclass=$min_uppercase minclass=$min_digits minclass=$min_special enforce_for_root
            password required pam_unix.so sha512 remember=$min_days minlen=$min_length use_authtok
            password required pam_unix.so sha512 maxdays=$max_days minlen=$min_length use_authtok
            password optional pam_unix.so sha512 remember=$warn_days minlen=$min_length use_authtok
EOL
            echo 'Password policies have been updated. Here Is The New Policy'
            echo '- Minimum password length: $min_length characters'
            echo '- Minimum lowercase letters: $min_lowercase'
            echo '- Minimum uppercase letters: $min_uppercase'
            echo '- Minimum digits: $min_digits'
            echo '- Minimum special characters: $min_special'
            sleep 10
            echo 'Complete! Returning To Menu!'

        ;;


        9)
            backup_configs
            ;;
        10)
            rotate_logs
            ;;

        11)
            secure_ssh_config
            ;;
        12)
            setup_regular_scans
            ;;
        13)
            monitor_failed_logins
            ;;
        14)
            check_system_health
            ;;
        8)
            echo 'This Will Check And See If ClamTK Is Installed (Will Install If Not) and Check For Other Common Vulnerabilities'
            echo 'Press Control + C To Cancel Now, Do Not Cancel While Script Is Running'
            sleep 5

            if apt list --installed clamtk | grep -q 'clamtk';
            then
                echo 'ClamTK Is Installed'
                echo 'Running System Scan'
                clamtk & 
                clear
                echo "ClamTK scan completed. Check the GUI for results. Moving on..."
                sleep 5
            else
                echo 'ClamtTK Is Not Installed, Installing and Scanning'
                sleep 3
                apt-get install clamtk -y
                apt update
                clamtk &
                clear
                echo "ClamTK scan completed. Check the GUI for results. Moving on..."
                sleep 5
            fi

            echo 'This Will Check And See If Lynis Is Installed (Will Install If Not) This Will Perform A System Audit'
            echo 'Press Control + C To Cancel Now, Do Not Cancel While Script Is Running'
            sleep 5

            if is_tool_installed lynis;
            then
                echo 'Lynis Is Installed'
                echo 'Running System Audit'
                lynis audit system
                echo "Lynis audit completed. Check the /var/log/lynis.log file for results."
                echo 'Audit Complete. Moving On...'
                sleep 5
            else
                echo 'Lynis Is Not Installed. Installing & Running Audit'
                apt install lynis -y
                apt update
                apt upgrade -y
                lynis audit system
                echo "Lynis audit completed. Check the /var/log/lynis.log file for results."
                echo 'Audit Complete. Moving On...'
                sleep 5
            fi

            echo 'This Will Check And See If CHKrootkit Is Installed (Will Install If Not) This Will Perform A Rootkit Scan'
            echo 'Press Control + C To Cancel Now, Do Not Cancel While Script Is Running'
            sleep 5

            if is_tool_installed chkrootkit
            then
                echo 'CHKrootkit Is Installed'
                echo 'Running Rootkit Detection'
                chkrootkit
                echo 'Check Complete. Moving On...'
                sleep 5
            else
                echo 'CHKrootkit Is Not Installed. Installing & Running Scan'
                apt install chkrootkit -y
                apt update
                apt upgrade -y
                chkrootkit
                echo 'Check Complete. Moving On...'
                sleep 5
            fi

            echo 'Checking For Unauthorized SUID/SGID Files'
            sleep 3
            
            find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \;

            echo 'Checking /etc/passwd for Unusual Accounts'
            awk -F: '($3 < 1000) {print}' /etc/passwd

            sleep 5
            echo 'Complete! Returning To Menu!'

        ;;
        *)
            echo 'Invalid Option. Please Try Again.'
            sleep 3
            ;;
    esac
    
done


# Disable root login for SSH
secure_ssh_config() {
    echo 'Disabling root login for SSH...'
    sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    systemctl restart sshd
    echo 'SSH root login disabled!'
    sleep 3
}

# Set up regular scans using Lynis and CHKrootkit via cron jobs
setup_regular_scans() {
    echo 'Setting up daily scans with Lynis and CHKrootkit...'
    echo "0 2 * * * root lynis audit system" >> /etc/crontab
    echo "30 2 * * * root chkrootkit" >> /etc/crontab
    systemctl restart cron
    echo 'Daily scans scheduled at 2:00 AM and 2:30 AM respectively!'
    sleep 3
}

# Monitor repeated failed login attempts and suggest the use of fail2ban
monitor_failed_logins() {
    echo 'Checking for repeated failed login attempts...'
    awk '($(NF-1) = /sshd/ && $NF ~ /Failed/) {print $(NF-3)}' /var/log/auth.log | sort | uniq -c | sort -nr
    echo 'If there are many failed login attempts, consider installing and configuring fail2ban.'
    sleep 3
}

# Monitor basic system health metrics
check_system_health() {
    echo 'Checking system health...'
    echo 'Disk Usage:'
    df -h
    echo 'Memory Usage:'
    free -h
    echo 'Top Processes:'
    top -n 1 -b | head -10
    sleep 3
}

# Get user feedback after each operation
get_user_feedback() {
    echo 'Was the operation successful? (yes/no)'
    read feedback
    if [ "$feedback" = "yes" ]; then
        log 'User confirmed the operation was successful.'
        echo 'Thank you for the feedback!'
    else
        log 'User reported an issue with the operation.'
        echo 'Please consider reporting the issue for further assistance.'
    fi
    sleep 3
}

# Check if a tool is installed
is_tool_installed() {
    local tool_name="$1"
    if dpkg -l | grep -qw "$tool_name"; then
        return 0
    else
        return 1
    fi
}
