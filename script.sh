#!/bin/bash

if [ "$(id -u)" != '0' ]; 
then
	echo 'Please Run Script As: sudo sh script.sh'
    exit 2 
fi

# Checks To See If User Ran Command As Sudo, Otherwise Will Displayed: 'Please Run Script As: sudo sh script.sh'

echo 'pie.secure Will Log Everything Into /var/log/piesecure.log'
echo 'Loading Script...'
sleep 1

# Ensure the log directory exists

LOG_DIR="/var/log"
mkdir -p "$LOG_DIR"

# Log File

LOG_FILE="/var/log/piesecure.log"

log() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$LOG_FILE"
}

show_menu() {
    echo "\e[1;37m┌────────────────────────────────────────────────┐\e[0m"
    echo "\e[1;37m│\e[0m\e[1;37m-------------------pie.secure-------------------\e[0m\e[1;37m│\e[0m"
    echo "\e[1;37m│\e[0m\e[1;37m------------------------------------------------\e[0m\e[1;37m│\e[0m"
    echo "\e[1;37m│\e[0m\e[1;37m---------------------V1.5-----------------------\e[0m\e[1;37m│\e[0m"
    echo "\e[1;37m└────────────────────────────────────────────────┘\e[0m"
    echo
    echo  "\e[1;33m1. Update\e[0m"
    echo  "\e[1;33m2. Firewall Setup (UFW)\e[0m"
    echo  "\e[1;33m3. Firewall Policies\e[0m"
    echo  "\e[1;33m4. Fix Shadow Permissions\e[0m"
    echo  "\e[1;33m5. User Management Menu\e[0m"
    echo  "\e[1;33m6. SSH Permissions\e[0m"
    echo  "\e[1;33m7. Password Policies\e[0m"
    echo  "\e[1;33m8. Malware & Vulnerabilities Check\e[0m"
    echo  "\e[1;33m9. Network Security\e[0m"
    echo  "\e[1;33m10. Exit\e[0m"
    echo
    echo  "\e[1;37mEnter A Number:\e[0m "
}

# Main Menu Display, All The Weird Numbers Before and After The Words, Are What Give The Text Colors, and Boldness

while true
do
    log "Menu Displayed."
    clear
    show_menu
    sleep 1

    # Runs a While Loop that constantly checks if user types in a number, one user types in a $user_number, it activate the following numbered case
    
    read user_number; #user_number is a variable that reads from the keyboard=
    
    case $user_number in
        1)
            log "Option 1 selected: Update and upgrade packages."
            echo 'This Will Update & Upgrade Packages, and Enable Auto Updates'
            echo 'Press Control + C To Cancel Now, Do Not Cancel While Script Is Running'
            sleep 5
            apt update -y
            apt upgrade -y
            apt autoclean
            apt autoremove
            clear
            echo 'Please Check If Auto Updates Are On By Typing This In: systemctl status unattended-upgrades, inside a different terminal'
            read -p 'Do You Want To Enable Auto Updates? (y/n): ' admin
            if [ "$admin" = "y" ]; then
                apt-get install unattended-upgrades
                dpkg-reconfigure unattended-upgrades
                echo 'Complete! Returning To Menu!'
                sleep 3
            else
                echo 'Complete! Returning To Menu!'
                sleep 3
            fi

            # Runs Updating Commands, and Autocleans & Autoremoves unnecassries files after updating
            # User Is Prompted With An Option to enable auto updates, if they type in 'y' the auto updating commands will run, if they type in 'n' it will complete the action
            # and return back to the main menu 
            ;;
        2)
            log "Option 2 selected: Firewall setup."
            echo 'This Will Check If UFW Is Installed (Will Install If Its Not) and Enable It'
            echo 'Press Control + C To Cancel Now, Do Not Cancel While Script Is Running'
            sleep 5
            if apt list --installed ufw | grep -q 'ufw';  
            then
                echo 'UFW Is Installed, Enabling If Not Already'
                sleep 3
                ufw enable
                echo 'Complete! Returning To Menu!'
                sleep 3 
                # Checks apt list on computer and sees if UFW is installed, if installed it just makes sure UFW is enabled
            else
                echo 'UFW Is Not Installed, Installing and Enabling UFW'
                sleep 3
                apt-get install ufw -y
                ufw enable
                echo 'Complete! Returning To Menu!'
                sleep 3 
                # Checks apt list on computer and sees if UFW is installed, this above means it wasn't installed, so it installed UFW and enables it
            fi
            ;;
        3)
            log "Option 3 selected: Firewall policies."  
            echo 'This Will Disable HTTP, SMTP, and Other Unsecure Ports'
            echo 'Press Control + C To Cancel Now, Do Not Cancel While Script Is Running'
            sleep 5
            ufw logging on
            ufw deny out 25 # Disables Outgoing SMTP Mail
            ufw deny 80 # Disables All HTTP Traffic
            ufw deny 23 # Disables Telnet
            ufw deny 21 # Disables FTP
            ufw deny 161 # Disables SNMP
            ufw deny 123/udp # Disables NTP
            ufw deny 19/udp # Disbales Chargen
            ufw deny 1337
            ufw deny 2049
            ufw deny 111
            ufw default deny
            sleep 2
            echo 'Complete! Returning To Menu!'
            sleep 3

            # Enables UFW logging, and disable insecure and outdate ports that aren't used in 99 percent of tasks. Changes default firewall policy to block all ports, until specified by user
            ;;

        4)
            log "Option 4 selected: Changing Shadow File Permissions /etc/shadow"
            echo 'This Sets The Permissions Of The Shadow File So Only The Root Can Access It'
            echo 'Press Control + C To Cancel Now, Do Not Cancel While Script Is Running'
            sleep 5
            chmod 000 /etc/shadow
            ls -l /etc/shadow
            sleep 5
            echo 'Check Above And Verify If The Permissions Have Changed'
            sleep 5
            ;;

            # This makes sure the shadow file is unreadable by all users, unless they are logged into a ROOT.
            # Shadow File in Linux contains: users, passwords, and time regulations
        
        5)  
            show_user_submenu()
                {
                    echo 'All Current Users:'
                    cut -d: -f1,4 /etc/group | awk -F: '{ split($2, members, ","); printf "%s: ", $1; for (i in members) { printf "%s (admin), ", members[i] } printf "\n" }'
                    echo ''
                    echo ''
                    echo "\e[1;37m┌────────────────────────────────────────────────┐\e[0m"
                    echo "\e[1;37m│\e[0m\e[1;37m------------------------------------------------\e[0m\e[1;37m│\e[0m"
                    echo "\e[1;37m│\e[0m\e[1;37m-------------User Management Menu---------------\e[0m\e[1;37m│\e[0m"
                    echo "\e[1;37m│\e[0m\e[1;37m------------------------------------------------\e[0m\e[1;37m│\e[0m"
                    echo "\e[1;37m└────────────────────────────────────────────────┘\e[0m"
                    echo ''
                    echo 'Scroll Up To See List Of All Curent Local Users'
                    echo ''
                    echo '1. Add A User'
                    echo '2. Remove A User'
                    echo '3. Remove A User Admin'
                    echo '4. Grant A User Admin'
                    echo '5. Secure Sudoers File'
                    echo '6. Create a User Group'
                    echo '7. Add Users To Group'
                    echo '8. Return To Main Menu'

                    echo 'Enter A Number: '
                }

                # If $user_number = 5, it will open up a User Management Menu, that allows users to Add and Remove Users, Grant and Revoke Admin to Users, and Secures Sudoers File
                # Above the User Menu, it will display all users and groups that are on the system, and display next them if they are a normal user, admin, and/or a group

            while true
            do
                show_user_submenu
                sleep 1
                read user_submenu_number; #user_menu_number is a variable that reads from the keyboard
                case $user_submenu_number in
                # Same as Main Menu, Everything is ran into a while loop until the $user_menu_number equals 1-6.
                    1)
                        log "User Menu Option 1 selected: Adding A User"
                        read -p 'Enter The Username To Add: ' username
                        read -p 'Do You Want To Give This User Admin Privileges? (y/n): ' admin

                        if [ "$admin" = 'y' ]; then
                            useradd -m -s /bin/bash -G sudo "$username"
                        else
                            useradd -m -s /bin/bash "$username"
                        fi
                        echo "User $username created successfully!"
                        sleep 3
                        ;;
                        # Prompts User To Type In A User that will be added, and adds them to the system
                    2)
                        log "User Menu Option 2 selected: Removing A User"
                        read -p 'Enter The Username To Delete: ' username
                        deluser --remove-home "$username"
                        echo "User $username removed successfully!"
                        sleep 3
                        ;;
                        # Prompts User To Type In A User that will be deleted, and removed from the system
                    3)
                        log "User Menu Option 3 selected: Remove User Admin"
                        read -p 'Enter the username: ' username
                        deluser "$username" sudo
                        echo "Admin privileges removed from user $username successfully!"
                        sleep 3
                        ;;
                        # Prompts User To Type In A User that will be given admin privileges
                    4)
                        log "User Menu Option 4 selected: Adding User Admin"
                        read -p 'Enter the username: ' username
                        usermod -aG sudo "$username"
                        echo "Admin privileges added to user $username successfully!"
                        sleep 3
                        ;;
                        # Prompts User To Type In A User that will remove admin privileges from that user
                    
                    5)
                        log "User Menu Option 5 selected: Securing Sudoers File"
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
                        log "User Menu Option 6 selected: Creating a User Group"
                        read -p 'Enter the group name: ' group
                        groupadd "$group"
                        echo "Group $group created successfully!"
                        sleep 3 
                        ;;
                    7)
                        log "User Menu Option 7 selected: Adding Users To Group"
                        read -p 'Enter the username: ' username
                        read -p 'Enter the group name: ' group
                        usermod -aG "$group" "$username"
                        echo "User $username added to group $group successfully!"
                        sleep 3
                        ;;

                    # Checks Permissions of the Sudoers File to make sure it is not writable, so malicoius users cannot give a user unauthorized admins permissions
                    8)
                        log "User Menu Option 8 selected: Returning To Main Menu"
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
            log "Option 6 selected: Installing OpenSSH and Securing It"
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
            log "Option 7 selected: Configuring Password Policies"
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
            echo "Password policies have been updated. Here Is The New Policy"
            echo "Make Sure To Take Note Of These Changes"
            echo "- Minimum password length: $min_length characters"
            echo "- Minimum lowercase letters: $min_lowercase"
            echo "- Minimum uppercase letters: $min_uppercase"
            echo "- Minimum digits: $min_digits"
            echo "- Minimum special characters: $min_special"

            # Displays back to the user all the new password policies
    
            sleep 10
            echo 'Complete! Returning To Menu!'

        ;;

        8)
            log "Option 8 selected: Checking for Malware and Vulnerabilties"
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
                # Checks apt list and sees that ClamTK is installed so it runs a antivirus scan on the system
            else
                echo 'ClamtTK Is Not Installed, Installing and Scanning'
                sleep 3
                apt-get install clamtk -y
                apt update
                clamtk &
                clear
                echo "ClamTK scan completed. Check the GUI for results. Moving on..."
                sleep 5
                # Checks apt list and sees that ClamTK is not installed so it installs it, and then runs a antivirus scan on the system
            fi

            echo 'This Will Check And See If Lynis Is Installed (Will Install If Not) This Will Perform A System Audit'
            echo 'Press Control + C To Cancel Now, Do Not Cancel While Script Is Running'
            sleep 5

            if apt list --installed lynis | grep -q 'lynis';
            then
                echo 'Lynis Is Installed'
                echo 'Running System Audit'
                lynis audit system
                echo "Lynis audit completed. Check the /var/log/lynis.log file for results."
                echo 'Audit Complete. Moving On...'
                sleep 5
                # Checks apt list and sees that Lynis is installed so it runs a audit on the system
            else
                echo 'Lynis Is Not Installed. Installing & Running Audit'
                apt install lynis -y
                apt update
                apt upgrade -y
                lynis audit system
                echo "Lynis audit completed. Check the /var/log/lynis.log file for results."
                echo 'Audit Complete. Moving On...'
                sleep 5
                # Checks apt list and sees that Lynis is not installed, so it installed it, and then runs a audit on the system
            fi

            echo 'This Will Check And See If CHKrootkit Is Installed (Will Install If Not) This Will Perform A Rootkit Scan'
            echo 'Press Control + C To Cancel Now, Do Not Cancel While Script Is Running'
            sleep 5

            if apt list --installed chkrootkit | grep -q 'chkrootkit'
            then
                echo 'CHKrootkit Is Installed'
                echo 'Running Rootkit Detection'
                chkrootkit
                echo 'Check Complete. Moving On...'
                sleep 5
                # Checks apt list and sees that CHKRootkit is installed so it runs a rootkit scan on the system
            else
                echo 'CHKrootkit Is Not Installed. Installing & Running Scan'
                apt install chkrootkit -y
                apt update
                apt upgrade -y
                chkrootkit
                echo 'Check Complete. Moving On...'
                sleep 5
                # Checks apt list and sees that CHKRootkit is not installed, so it installed it, and then runs a rootkit scan on the system
            fi

            echo 'Checking For Unauthorized SUID/SGID Files'
            sleep 3
            
            find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \;
            # This command searches for all files in the root directory ("/") that have the setuid (permission 4000) or setgid (permission 2000) bits set. 
            # These bits allow the files to be executed with the permissions of their owner or group respectively, which can be a security risk if not managed properly. 
            # The 'ls -l' command is then executed on each of these files to display their details in a long listing format.
            echo 'Checking /etc/passwd for Unusual Accounts'
            awk -F: '($3 < 1000) {print}' /etc/passwd
            # This command checks the /etc/passwd file for any accounts with a UID less than 1000. 
            # In many systems, such UIDs are reserved for system accounts, so any non-system accounts with such a UID could be unusual or suspicious.

            sleep 5
            echo 'Complete! Returning To Menu!'

        ;;

        9)
            log "Option 9 selected: Network Harderning"
            echo 'Check IP IPTables, SSH Spammers, and Portscans'
            echo 'Press Control + C To Cancel Now, Do Not Cancel While Script Is Running'
            sleep 5

            if apt list --installed iptables | grep -q 'iptables'
            then
                echo 'IPTables Is Installed'
                echo 'Running IPTables Configurations'
                iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 23 -j DROP
                iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 2049 -j DROP
                iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 2049 -j DROP
                iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 6000:6009 -j DROP
                iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 7100 -j DROP
                iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 515 -j DROP
                iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 515 -j DROP
                iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 111 -j DROP
                iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 111 -j DROP
                iptables -A INPUT -p all -s localhost  -i eth0 -j DROP
                ## These Block Telnet, X-Windows, Printer, and Sun RCP/NFS Protocols
                iptables -I INPUT -p tcp --dport 22 -i eth0 -m state --state NEW -m recent --set
                iptables -I INPUT -p tcp --dport 22 -i eth0 -m state --state NEW -m recent --update --seconds 60 --hitcount 5 -j DROP
                iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
                iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP
                iptables -A INPUT -m recent --name portscan --remove
                iptables -A FORWARD -m recent --name portscan --remove
                iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
                iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP
                iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
                iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP
                ## These Block SSH Spammers and Portscans. Blocks Removed After 1 Day, Scan Attempts Are Logged
                iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
                iptables -A OUTPUT -p icmp -o eth0 -j ACCEPT
                iptables -A INPUT -p icmp --icmp-type echo-reply -s 0/0 -i eth0 -j ACCEPT
                iptables -A INPUT -p icmp --icmp-type destination-unreachable -s 0/0 -i eth0 -j ACCEPT
                iptables -A INPUT -p icmp --icmp-type time-exceeded -s 0/0 -i eth0 -j ACCEPT
                iptables -A INPUT -p icmp -i eth0 -j DROP
                ## NULL Packets and Pings are Dropped
                iptables-save
                /sbin/iptables-save
                ## IPTables Rules Save Location
                clear
                echo 'IPTable Logs Saved At /sbin/iptables-save'
                echo 'Check Complete. Moving On...'
                sleep 5
            else
                echo 'IPTables Is Not Installed. Installing & Running Scan'
                apt-get -y -qq install iptables
                apt update
                apt upgrade -y
                echo 'IPTables Is Installed'
                echo 'Running IPTables Configurations'
                iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 23 -j DROP
                iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 2049 -j DROP
                iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 2049 -j DROP
                iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 6000:6009 -j DROP
                iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 7100 -j DROP
                iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 515 -j DROP
                iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 515 -j DROP
                iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 111 -j DROP
                iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 111 -j DROP
                iptables -A INPUT -p all -s localhost  -i eth0 -j DROP
                ## These Block Telnet, X-Windows, Printer, and Sun RCP/NFS Protocols
                iptables -I INPUT -p tcp --dport 22 -i eth0 -m state --state NEW -m recent --set
                iptables -I INPUT -p tcp --dport 22 -i eth0 -m state --state NEW -m recent --update --seconds 60 --hitcount 5 -j DROP
                iptables -A INPUT -m recent --name portscan --rcheck --seconds 86400 -j DROP
                iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP
                iptables -A INPUT -m recent --name portscan --remove
                iptables -A FORWARD -m recent --name portscan --remove
                iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
                iptables -A INPUT -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP
                iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
                iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP
                ## These Block SSH Spammers and Portscans. Blocks Removed After 1 Day, Scan Attempts Are Logged
                iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
                iptables -A OUTPUT -p icmp -o eth0 -j ACCEPT
                iptables -A INPUT -p icmp --icmp-type echo-reply -s 0/0 -i eth0 -j ACCEPT
                iptables -A INPUT -p icmp --icmp-type destination-unreachable -s 0/0 -i eth0 -j ACCEPT
                iptables -A INPUT -p icmp --icmp-type time-exceeded -s 0/0 -i eth0 -j ACCEPT
                iptables -A INPUT -p icmp -i eth0 -j DROP
                ## NULL Packets and Pings are Dropped
                iptables-save
                /sbin/iptables-save
                ## IPTables Rules Save Location
                clear
                echo 'IPTable Logs Saved At /sbin/iptables-save'
                echo 'Check Complete. Moving On...'
                sleep 5
            fi
        ;;
        
        10)
            exit 0
        ;;

        *)
            echo 'Invalid Option. Please Try Again.'
            sleep 3
            ;;
    esac
    
done
