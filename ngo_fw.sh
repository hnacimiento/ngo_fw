#!/bin/bash
#-----------------------------------------------------------------------------------------------------------------
#title          :ngo_fw.sh
#description    :Uses iptables and ipset to block ip's in known blacklist.
#options        :ngo_fw.sh whitelist | loadatboot | install | installpsad
#
# Some hosting services such as RamNode will ban you for using > 90% of the cpu!!!
# So we recommend installing cpulimit and limiting to 20% of cpu usage when 
# calling this script.
#
# cpulimit -z -l 20 /usr/local/bin/ngo_fw.sh
# cpulimit dosn't like scripts writing to stdout/stderr so them redirect to 
# an output file.
#-----------------------------------------------------------------------------------------------------------------
# Workaround for issues when executing the script from crontab in some Linux systems.
# Some versions of cron do not load the full user's environment variables, including the PATH.
# This can cause the script to fail when trying to run commands not included in the limited PATH set by cron.
# By setting the PATH explicitly to what it would be in a regular root session, we ensure all commands will work.
export PATH="$(sudo -i -u root bash -c 'echo $PATH')"
#-----------------------------------------------------------------------------------------------------------------
SCRIPT_NAME=`basename ${BASH_SOURCE[0]}` # Script File Name.
HOST_NAME=`uname -n` # Hostname.
UBUNTU_VER=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2)
BL_DIR="/var/lib/ngo_fw" # Where we keep some files.
DOWNLOAD_DIR="$BL_DIR/downloads"
WHITELIST_FILE="$BL_DIR/whitelist.txt"
BLACKLIST_FILE="$BL_DIR/blacklist.txt"
ADMINS_FILE="$BL_DIR/dynamic_dns_admins.txt"
TEMP_WHITELIST_FILE="$BL_DIR/temp_whitelist_update.list"
PREVIOUS_IP_FILE="$BL_DIR/previous_ip.list"
LOG_PRI="local0.notice" # Default syslog messages priority and tag.
LOG_TAG="[$SCRIPT_NAME]"
WL_IP=`who | grep pts | awk '{print $5}' | cut -f2 -d"(" | cut -f1 -d")" | uniq` # Your ip if you are connected by ssh
HOME_NET4=`ip addr show | grep inet | awk '{print $2}' | cut -f2 -d: | grep -v 127 | sed '/^$/d' | cut -f1 -d/` # Your internal net
MASK4=/`ip addr show | grep inet | awk '{print $2}' | cut -f2 -d: | grep -v 127 | sed '/^$/d' | cut -f2 -d/`
HOME_NET6=`ip addr show | grep inet6 | awk '{print $2}' | grep -v ::1 | cut -f1 -d/`
MASK6=/`ip addr show | grep inet6 | awk '{print $2}' | grep -v ::1 | cut -f2 -d/`
PSAD_AUTODL=`ip addr show | grep inet | awk '{print $2}' | sed 's/$/ 0;/'`
# Set to empty string if you don't want error emails. Otherwise, set to an admin email.
MAIL_ADMIN="root@localhost"
# Logging is enabled for the following ports this is so we can do later audit checks
# in case we are droping legitimate traffic.
TCP_PORTS="22,80,443,2222"
UDP_PORTS="53"
# If PSAD is installed then block Danger Level = $DL and above attackers
# each time the blacklist are reloaded.
DL=3
# Retrieve new blacklist only when they are older then BL_AGE
BL_AGE="23 hours ago"

#---------------------------------------------------------------------------
# FUNCTIONS
#---------------------------------------------------------------------------

# check_and_create_directory
# This function checks if a directory exists. If it doesn't, it creates it.
# Then it redirects stdout and stderr to a file in that directory.
#
# Globals:
#   BL_DIR - The home directory to check or create.
#   DOWNLOAD_DIR - The directory to store downloaded files.
#
# Arguments:
#   None
#
# Returns:
#   None
check_and_create_directory() {
    # Check if the directory exists.
    if [ ! -d "$BL_DIR" ]; then
        # If not, create the directory.
        mkdir -vp "$BL_DIR"
    fi
    # Create a subdirectory for downloads if it doesn't exist.
    if [ ! -d "$DOWNLOAD_DIR" ]; then
        mkdir -vp "$DOWNLOAD_DIR"
    fi
}

check_and_prepare_file () {
    local file="$1"
    #Create file if it doesn't exist
    if [ ! -f "$file" ]; then
        touch "$file"
        echo -e "touch $file\n"
    else
        # Ensure the file ends with a newline
        sed -i -e '$a\' "$file"
    fi
}

# logmessage <msg_text>
logmessage () {
  MSG="$1"
  logger -s -p $LOG_PRI -t $LOG_TAG "$MSG"
}

# install_packages()
# Installs the given packages using APT.
#
# Arguments:
#   A list of package names to install.
#
# Returns:
#   0 on success, 1 on error.
#
install_packages() {
    # Check if the script is being run as root.
    if [[ $EUID -ne 0 ]]; then
       echo "This script must be run as root."
       exit 1
    fi

    # Check if APT is available on the system.
    if ! command -v apt &> /dev/null; then
        echo "APT is not found on this system."
        exit 1
      else
        echo "apt update"
        apt update
    fi

    # Iterate over the package list and install each package if not already installed.
    for pkg in "$@"; do
        if ! dpkg -l | grep -q "^ii  $pkg "; then
            if ! apt-get install -y "$pkg"; then
                echo "Error installing package $pkg."
                exit 1
            fi
        fi
    done

    return 0
}

# <ips> goodinbadnets
# - returns whitelist <ips> that that are in blacklist.
goodinbadnets () {
  myips=""
  for good in `ipset list whitelist_ips | egrep -E "^[1-9]"`
  do
   myip=`ipset test blacklist_nets_n $good 2>&1 | grep "is in" | awk '{print $1}'`
   if [ -n "$myip" ];then
     myips="$myips $myip"
   fi
  done
  echo $myips
}

# blacklistit <ip/cdr> <listname>
#  - blacklist the given <ip/cdr> to blacklist_nets_n or blacklist_ips_n
#  - also checks if the <ip/cdr> blacklist one of your whitelisted ips, and 
#  if so it will remove it from the blacklist and warn you.
blacklistit () {
 IP=$1
 LISTNAME=$2
 if echo "$IP" | egrep -q "\/[0-9]+"; then
   ipset add blacklist_nets_n $IP -exist
   badip=`goodinbadnets`
   if [ -n "$badip" ]; then
     error_msg="ERROR Your whitelist IP $badip has been blacklisted in $LISTNAME"
     logmessage "$error_msg"
     ERROR_MSGS="$ERROR_MSGS\n$error_msg"
     ipset del blacklist_nets_n $IP
   fi
        
 else
   if ipset test whitelist_ips $IP 2> /dev/null; then
     error_msg="ERROR Your whitelist IP $IP has been blacklisted in $LISTNAME"
     logmessage "$error_msg"
     ERROR_MSGS="$ERROR_MSGS\n$error_msg"
   else 
     ipset add blacklist_ips_n $IP -exist
   fi
 fi
}

# loadblacklist <name> <url>
# - loads standard form blacklist from <url> website, labels cache files with <name>
loadblacklist () {
  BL_NAME=$1
  BL_URL=$2
  BL_FILE="$BL_DIR/$BL_NAME.txt"

  if [ ! -f "$BL_FILE" ] || [ $(date +%s -r "$BL_FILE") -lt $(date +%s --date="$BL_AGE") ]; then
    echo "-- getting fresh $BL_NAME from $BL_URL"
    wget -q -t 2 --output-document=$BL_FILE $BL_URL --no-check-certificate
  fi

  if [ -f "$BL_FILE" ]; then
    echo "-- loading $BL_NAME from $BL_FILE"
    # strip comments - mac address and ipv6 not supported yet so strip :
    grep -Eo '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?' $BL_FILE > ${BL_FILE}.filtered
    echo "-- loading $BL_NAME - `wc -l ${BL_FILE}.filtered` entries"
    
    for ip in `cat ${BL_FILE}.filtered`; do
      blacklistit $ip $BL_NAME
    done
  fi
}

loaddynamicwhitelist () {
  # Use the function for each file
  check_and_prepare_file "$PREVIOUS_IP_FILE"
  check_and_prepare_file "$TEMP_WHITELIST_FILE"
  check_and_prepare_file "$ADMINS_FILE"

  cp -v "$WHITELIST_FILE" "$TEMP_WHITELIST_FILE"

  # Update the dynamic IPs
  IFS=""
  while read -r admin; do
      ip=$(dig +short "$admin" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
      if [[ -f "$PREVIOUS_IP_FILE" ]]; then
          previous_ips=$(grep "$admin" "$PREVIOUS_IP_FILE" | cut -d ' ' -f2)
          # Loop through each previous IP and handle them separately
          for previous_ip in $previous_ips; do
              if [[ "$ip" != "$previous_ip" ]]; then
                  sed -i "/$previous_ip/d" "$TEMP_WHITELIST_FILE"
                  sed -i "/$previous_ip/d" "$PREVIOUS_IP_FILE"
              fi
          done
      fi
      if ! grep -q "$ip" "$TEMP_WHITELIST_FILE"; then
          echo "$ip" >> "$TEMP_WHITELIST_FILE"
          echo "$admin $ip" >> "$PREVIOUS_IP_FILE"
      fi
  done < "$ADMINS_FILE"

  # Remove any lines from the temp file that are not in the admins file
  while read -r line; do
      admin=$(echo "$line" | cut -d ' ' -f1)
      ip=$(echo "$line" | cut -d ' ' -f2)
      if ! grep -q "$admin" "$ADMINS_FILE"; then
          sed -i "/$ip/d" "$TEMP_WHITELIST_FILE"
          sed -i "/$ip/d" "$PREVIOUS_IP_FILE"
      fi
  done < "$PREVIOUS_IP_FILE"

  # Overwrite the whitelist file with the new IPs
  cp -v "$TEMP_WHITELIST_FILE" "$WHITELIST_FILE"
}

# load your good ip's
loadcustomwhitelist () {
# load fresh white list each time as the list should be small.
ipset flush whitelist_ips_n
WL_CUSTOM="$WHITELIST_FILE"
count=0
  if [ -f $WL_CUSTOM ]; then
    while IFS= read -r ip; do
      if [[ -n "$ip" && ! "$ip" =~ ^# ]]; then
        ipset add whitelist_ips_n "$ip" -exist
        count=$((count + 1))
      fi
    done < "$WL_CUSTOM"
  fi
echo "-- loaded `ipset list whitelist_ips_n | egrep "^[1-9]"  | wc -l` entries from whitelist "
echo "-- loaded $count entries from $WL_CUSTOM"
}

loadcustomblacklist() {
# load your personal custom blacklist.
BL_CUSTOM="$BLACKLIST_FILE"
count=0
if [ -f "$BL_CUSTOM" ]; then
  for ip in `grep -Ev "^#|^ *$" $BL_CUSTOM | sed -e "s/#.*$//" -e "s/[^.0-9\/]//g"`; do
    blacklistit $ip $BLACKLIST
    count=$((count+1))
  done
fi
echo "-- loaded `ipset list blacklist_ips_n | egrep "^[1-9]"  | wc -l` entries from blacklist "
echo "-- loaded $count entries from $BL_CUSTOM"
}

loadcustomiptables () {
#
# Setup our firewall ip chains 
#
if ! iptables -L blacklist -n > /dev/null 2>&1; then

  echo "-- creating blacklist iptables rules for first time"
  iptables -N blacklist

  # insert the smaller set first.
  iptables -I INPUT  \
       -m set --match-set blacklist_ips src -j blacklist

  iptables -I OUTPUT  \
       -m set --match-set blacklist_ips dst -j blacklist

  iptables -I INPUT \
       -m set --match-set blacklist_nets src -j blacklist

  iptables -I OUTPUT \
       -m set --match-set blacklist_nets dst -j blacklist

  iptables -I INPUT 15 \
        -m set --match-set whitelist_ips src -p tcp -m tcp --dport 22 -j ACCEPT
  
#  iptables -I INPUT 17 \
#        -m set --match-set whitelist_ips src -p tcp -m tcp --dport 2222 -j ACCEPT

  # keep a record of our business traffic ports.
  # so we can check if we blocked legitimate traffic if need be.
  # DNS and http/https are most typical legit ports
  iptables -A blacklist -p tcp -m multiport --dports $TCP_PORTS \
         -m limit --limit 5/min \
         -j LOG --log-prefix "[NGO_FW BLACKLIST DROP] "
  #  iptables -A blacklist -p udp -m multiport --dport $UDP_PORTS \
  #         -m limit --limit 5/min \
  #         -j LOG --log-prefix "[NGO_FW BLACKLIST DROP] "
  iptables -A blacklist -m state --state NEW -j DROP 
fi
}

#---------------------------------------------------------------------------
# MAIN
#---------------------------------------------------------------------------
if [[ $1 != "" ]]; then OPTS=$1; else OPTS="null"; fi

# Redirect stdout and stderr to a file in the directory.
exec > "$BL_DIR/ngo_fw.out" 2>&1

# Check if the script is running as root, if not, request elevation of privileges
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root. Trying to elevate privileges..."
   sudo "$0" "$@"
   exit $?
fi

check_and_create_directory

if [ $OPTS = "installpsad" ]; then
  clear
    echo "Installing PSAD"
    echo -e "install_packages psad\n"
    debconf-set-selections <<< "postfix postfix/main_mailer_type select No configuration"
    install_packages psad

    # Check the version and execute commands accordingly
    if [[ $UBUNTU_VER == "20.04" ]]; then
        update-rc.d psad enable
    elif [[ $UBUNTU_VER == "22.04" ]]; then
        sudo systemctl enable psad
    else
        echo "You are on an unspecified version of Ubuntu in this script."
        # You can add commands for other versions or a default behavior
        exit -1
    fi

    cat <(crontab -l) <(echo "@daily  root  psad --sig-update && psad -H > $BL_DIR/psad_cron_update.log" ) | crontab -
    cp -v /etc/psad/psad.conf /etc/psad/psad.conf.ori
    sed -i "s/EMAIL_ADDRESSES             root@localhost;/EMAIL_ADDRESSES             $MAIL_ADMIN;/" /etc/psad/psad.conf
    sed -i "s/_CHANGEME_/$HOST_NAME/g" /etc/psad/psad.conf
    #sed -i "s/HOME_NET                    any;/HOME_NET                    $HOME_NET4\\$MASK4;/" /etc/psad/psad.conf
    sed -i "s/HOME_NET                    any;/HOME_NET                    NOT_USED;/" /etc/psad/psad.conf
    sed -i '/ENABLE_AUTO_IDS             N;/ c\ENABLE_AUTO_IDS             Y;' /etc/psad/psad.conf
    sed -i '/AUTO_IDS_DANGER_LEVEL/ c\AUTO_IDS_DANGER_LEVEL 4;' /etc/psad/psad.conf
    sed -i "s/IPT_SYSLOG_FILE             \/var\/log\/messages;/IPT_SYSLOG_FILE             \/var\/log\/ngo_fw_logs;/" /etc/psad/psad.conf
    echo -e "\n$PSAD_AUTODL" >> /etc/psad/auto_dl
    psad --sig-update
    psad -H

    if [ -f /etc/init.d/rsyslog ]; then
      if [ -f /etc/rsyslog.d/30-ngo_fw.conf ]; then
        sed -i "\$a # Log kernel messages generated by iptables to file \n:msg, contains, \"[NGO_FW LOG]\" -/var/log/ngo_fw_logs \n& stop" /etc/rsyslog.d/30-ngo_fw.conf
      else
      echo '# Log kernel messages generated by iptables to file
:msg, contains, "[NGO_FW LOG]" -/var/log/ngo_fw_logs
& stop' > /etc/rsyslog.d/30-ngo_fw.conf
      fi
      service rsyslog restart
    fi
    echo '/var/log/ngo_fw_logs
          {
              rotate 4
              weekly
              missingok
              notifempty
              compress
              delaycompress
              sharedscripts
              postrotate
                  invoke-rc.d rsyslog reload >/dev/null 2>&1 || true
              endscript
          }' >> /etc/logrotate.d/ngo_fw


    echo "PSAD installed successfully"
    exit 0
fi
# Check if the script has been passed the "install" option.
if [ $OPTS = "install" ]; then
  clear
  # Check if the script file already exists.
  if [ -f "/usr/local/bin/$SCRIPT_NAME" ]; then
    echo -e "\nScript file exist on: /usr/local/bin/$SCRIPT_NAME"
    exit 0
  else
    # Install the required packages.
    echo -e "install_packages cpulimit ipset iptables-persistent\n"
    debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v4 boolean true" 
    debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v6 boolean true" 
    install_packages cpulimit ipset iptables-persistent

    # Enable the iptables-persistent service.
    echo "update-rc.d iptables-persistent enable"
    if [[ $UBUNTU_VER == "20.04" ]]; then
        update-rc.d iptables-persistent enable
    elif [[ $UBUNTU_VER == "22.04" ]]; then
        sudo systemctl enable netfilter-persistent
    else
        echo "You are on an unspecified version of Ubuntu in this script."
        # You can add commands for other versions or a default behavior
        exit -1
    fi

    # Copy the iptables rules files.
    cp -v iptables4 /etc/iptables/rules.v4
    cp -v iptables6 /etc/iptables/rules.v6

    # Install the main script.
    echo "cp -fv $SCRIPT_NAME /usr/local/bin/"
    cp -fv $SCRIPT_NAME /usr/local/bin/
    echo "chown root:root /usr/local/bin/ngo_fw.sh"
    chown root:root /usr/local/bin/$SCRIPT_NAME
    echo "chmod +x /usr/local/bin/$SCRIPT_NAME"
    chmod +x /usr/local/bin/$SCRIPT_NAME

    # Create the directory for the blacklist, whitelist and others files.
    check_and_prepare_file "$WHITELIST_FILE"
    check_and_prepare_file "$BLACKLIST_FILE"
    check_and_prepare_file "$PREVIOUS_IP_FILE"
    check_and_prepare_file "$TEMP_WHITELIST_FILE"
    check_and_prepare_file "$ADMINS_FILE"

    # Copy the examples iptables rules files.
    cp -v example-rules.v4 $BL_DIR/
    cp -v example-rules.v6 $BL_DIR/
    
    #read -rep $'Please create and edit the iptables4/6 files according to your needs, \n you can use example-rules.v4/6 files \n Press any key to resume ...'
    
    # Copy the iptables rules files.
    #cp -v $BL_DIR/iptables4 /etc/iptables/rules.v4
    #cp -v $BL_DIR/iptables6 /etc/iptables/rules.v6

    # Update the whitelist file.
      if [[ $WL_IP != "" ]]; then
        echo "$WL_IP" > $WHITELIST_FILE
      else
        echo "Nothing to do on whitelist.txt"
      fi

    # Update the crontab to run the script daily.
    echo 'cat <(crontab -l) <(echo "@daily          root    cpulimit -z -l 20 /usr/local/bin/ngo_fw.sh") | crontab -'
    cat <(crontab -l) <(echo "# SECURITY NGO_FW SCRIPT") | crontab -
    cat <(crontab -l) <(echo "@daily root  sleep 60 && cpulimit -z -l 20 /usr/local/bin/$SCRIPT_NAME &") | crontab -
    
    # Update the rc.local file to run the script at boot.
    if [ -f "/etc/rc.local" ]; then
      sed -i "\$i /bin/bash /usr/local/bin/ngo_fw.sh loadatboot\n" /etc/rc.local
    else
      touch /etc/rc.local && chmod +x /etc/rc.local
      echo '#!/bin/bash' > /etc/rc.local
      echo -e "\nexit" >> /etc/rc.local
      sed -i "\$i /bin/bash /usr/local/bin/ngo_fw.sh loadatboot\n" /etc/rc.local

      # Check the version and execute commands accordingly
      if [[ $UBUNTU_VER == "20.04" ]]; then
          # Check if the rc-local service is already enabled
          service_status=$(systemctl is-enabled rc-local)
          # If the service is not enabled, enable it
          if [ "$service_status" != "enabled" ]; then
              echo "Enabling rc-local service..."
              sudo systemctl enable rc-local
          else
              echo "rc-local service is already enabled."
          fi
      elif [[ $UBUNTU_VER == "22.04" ]]; then
          echo '[Unit]
          Description=Local Startup Script

          [Service]
          Type=simple
          ExecStart=/etc/rc.local

          [Install]
          WantedBy=multi-user.target' >> /etc/systemd/system/rc-local.service

          chmod 644 /etc/systemd/system/rc-local.service
          sudo systemctl enable rc-local.service
          #sudo systemctl start rc-local.service
          sudo systemctl status rc-local.service
      else
          echo "You are on an unspecified version of Ubuntu in this script."
          exit -1
      fi
   fi
   
    # Configure the rsyslog service to log iptables messages.
    if [ -f /etc/rsyslog.conf ]; then
      if [ -f /etc/rsyslog.d/30-ngo_fw.conf ]; then
        sed -i "\$a # Log kernel messages generated by iptables to file \n:msg, contains, \"[NGO_FW BLACKLIST DROP]\" -/var/log/ngo_fw_bl_drops\n & stop" /etc/rsyslog.d/30-ngo_fw.conf
      else
      echo '# Log kernel messages generated by iptables to file
:msg, contains, "[NGO_FW BLACKLIST DROP]" -/var/log/ngo_fw_bl_drops
& stop' > /etc/rsyslog.d/30-ngo_fw.conf
      fi
      service rsyslog restart
    fi

    # Configure log rotation for the iptables logs.
    echo '/var/log/ngo_fw_bl_drops
          {
              rotate 4
              weekly
              missingok
              notifempty
              compress
              delaycompress
              sharedscripts
              postrotate
                  invoke-rc.d rsyslog reload >/dev/null 2>&1 || true
              endscript

          }' >> /etc/logrotate.d/ngo_fw
  fi
  echo -e "\nPre-req is installed!"
  exit 0
fi

# Only reload whitelist
if [ $OPTS = "whitelist" ]; then
  echo -e "\nWhitelist is reloading"
  loaddynamicwhitelist
  if ! ipset list whitelist_ips > /dev/null 2>&1
  then
    echo "-- creating whitelist_ips ipset as does not exist."
    ipset create whitelist_ips hash:ip hashsize 4096 maxelem 262144
    if [ -f "$BL_DIR/whitelist_ips.sav" ]; then
      echo "-- importing from save file $BL_DIR/whitelist_ips.sav"
      grep -v "create" $BL_DIR/whitelist_ips.sav | ipset restore 
    fi
  fi
  ipset create whitelist_ips_n hash:ip hashsize 4096 maxelem 262144 2> /dev/null
  loadcustomwhitelist
  ipset swap whitelist_ips_n whitelist_ips

# Check if IP is in whitelist and delete from blacklist_ips
  while read -r IP; do
    # Check if IP is in whitelist and delete from blacklist_ips
    ip_in_whitelist=$(ipset test whitelist_ips $IP 2> /dev/null)
    if [ -n "$ip_in_whitelist" ]; then
      ipset del blacklist_ips $IP
    fi
  done < "$WHITELIST_FILE"

  ipset destroy whitelist_ips_n
  ipset save whitelist_ips  > $BL_DIR/whitelist_ips.sav
  echo -e "\nWhitelist is reloaded"
  exit 0
fi

# Only load custom iptables
if [ $OPTS = "loadatboot" ]; then
  echo -e "\nWhitelist is reloading"
  if ! ipset list whitelist_ips > /dev/null 2>&1; then
    echo "-- creating whitelist_ips ipset as does not exist."
    ipset create whitelist_ips hash:ip hashsize 4096 maxelem 262144
    if [ -f "$BL_DIR/whitelist_ips.sav" ]; then
      echo "-- importing from save file $BL_DIR/whitelist_ips.sav"
      grep -v "create" $BL_DIR/whitelist_ips.sav | ipset restore 
    fi
  fi
  ipset create whitelist_ips_n hash:ip hashsize 4096 maxelem 262144 2> /dev/null
  loadcustomwhitelist
  ipset swap whitelist_ips_n whitelist_ips
  ipset destroy whitelist_ips_n
  ipset save whitelist_ips  > $BL_DIR/whitelist_ips.sav
  echo -e "\nWhitelist is reloaded"

  if ! ipset list blacklist_ips > /dev/null 2>&1; then
    echo "-- creating blacklist_ips ipset as does not exist."
    ipset create blacklist_ips hash:ip hashsize 4096 maxelem 262144
    if [ -f "$BL_DIR/blacklist_ips.sav" ]; then
      echo "-- importing from save file $BL_DIR/blacklist_ips.sav"
      grep -v "create" $BL_DIR/blacklist_ips.sav | ipset restore 
    fi
  fi
  if ! ipset list blacklist_nets > /dev/null 2>&1; then
    echo "-- creating blacklist_nets ipset as does not exist."
    ipset create blacklist_nets hash:net hashsize 4096 maxelem 262144
    if [ -f "$BL_DIR/blacklist_nets.sav" ]; then
      echo "-- importing from save file $BL_DIR/blacklist_nets.sav"
      grep -v "create" $BL_DIR/blacklist_nets.sav | ipset restore 
    fi
  fi

  touch /var/log/ngo_fw_logs && chown syslog:adm /var/log/ngo_fw_logs
  touch /var/log/ngo_fw_bl_drops && chown syslog:adm /var/log/ngo_fw_bl_drops

  echo -e "\nConfigure IPTABLES"
  loadcustomiptables

  if [ -f /etc/init.d/rsyslog ]; then
    service rsyslog restart
  fi

  echo -e "\nConfigure IPTABLES done"
  exit 0
fi

# concatenated list of all error message
ERROR_MSGS=""

if ! which ipset > /dev/null 2>&1;then
  echo "ERROR: You must install 'ipset'"
  exit 1
fi

logmessage "script started"

# Create temporary swap ipsets
ipset create blacklist_ips_n hash:ip hashsize 4096 maxelem 262144 2> /dev/null
ipset flush blacklist_ips_n

ipset create blacklist_nets_n hash:net hashsize 4096 maxelem 262144 2> /dev/null
ipset flush blacklist_nets_n

ipset create whitelist_ips_n hash:ip hashsize 4096 maxelem 262144 2> /dev/null
ipset flush whitelist_ips_n

#
# Setup the active ipsets if they don't yet exist.
# Load them from last save sets to speed up load times in cases of reboot
# and ensure protection faster.
#
if ! ipset list blacklist_ips > /dev/null 2>&1; then
  echo "-- creating blacklist_ips ipset as does not exist."
  ipset create blacklist_ips hash:ip hashsize 4096 maxelem 262144
  if [ -f "$BL_DIR/blacklist_ips.sav" ]; then
    echo "-- importing from save file $BL_DIR/blacklist_ips.sav"
    grep -v "create" $BL_DIR/blacklist_ips.sav | ipset restore 
  fi
fi
#
if ! ipset list blacklist_nets > /dev/null 2>&1; then
  echo "-- creating blacklist_nets ipset as does not exist."
  ipset create blacklist_nets hash:net hashsize 4096 maxelem 262144
  if [ -f "$BL_DIR/blacklist_nets.sav" ]; then
    echo "-- importing from save file $BL_DIR/blacklist_nets.sav"
    grep -v "create" $BL_DIR/blacklist_nets.sav | ipset restore 
  fi
fi
#
if ! ipset list whitelist_ips > /dev/null 2>&1; then
  echo "-- creating whitelist_ips ipset as does not exist."
  ipset create whitelist_ips hash:ip hashsize 4096 maxelem 262144
  if [ -f "$BL_DIR/whitelist_ips.sav" ]; then
    echo "-- importing from save file $BL_DIR/whitelist_ips.sav"
    grep -v "create" $BL_DIR/whitelist_ips.sav | ipset restore 
  fi
fi

loadcustomwhitelist
loadcustomblacklist
loadcustomiptables

# If PSAD is installed then use some of it's good detection work
# to stop attackers.
count=0
if [ -f "/var/log/psad/top_attackers" ]; then
 for ip in `awk '{print $2, $1}' /var/log/psad/top_attackers | grep "^[$DL-]" | awk '{print $2}'`; do
    blacklistit $ip $BLACKLIST
    count=$((count+1))
  done
fi
echo "-- loaded $count entries from /var/log/psad/top_attackers "

#
# Load Standard format blacklist
# Some of them are over zealous, you may want to comment out.
#
loadblacklist \
  "lists-blocklist-de-all" \
  "http://lists.blocklist.de/lists/all.txt"

loadblacklist \
   "emerging-block-ips" \
   "http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt"

loadblacklist \
   "greensnow" \
   "https://blocklist.greensnow.co/greensnow.txt"

loadblacklist \
  "nubi" \
  "https://www.nubi-network.com/list.txt"

loadblacklist \
      "ci-army-malcious" \
        "http://cinsscore.com/list/ci-badguys.txt"

loadblacklist \
      "bruteforceblocker" \
        "http://danger.rulez.sk/projects/bruteforceblocker/blist.php"

loadblacklist \
      "torexitnodes" \
        "https://check.torproject.org/torbulkexitlist"

loadblacklist \
      "spamhaus-org-lasso" \
        "http://www.spamhaus.org/drop/drop.lasso"


loadblacklist \
      "alienvault-reputation" \
        "https://reputation.alienvault.com/reputation.generic"

loadblacklist \
      "pfBlockerNG-malicious-threats-bbcan177_ms1" \
        "https://gist.githubusercontent.com/BBcan177/bf29d47ea04391cb3eb0/raw"

loadblacklist \
      "pfBlockerNG-malicious-threats-bbcan177_ms3" \
        "https://gist.githubusercontent.com/BBcan177/d7105c242f17f4498f81/raw"

loadblacklist \
      "haley-ssh" \
        "http://charles.the-haleys.org/ssh_dico_attack_hdeny_format.php/hostsdeny.txt"


#
# special cases, custom formats blacklist
# COLUMNS with range subnets
#
# Obtain List of badguys from dshield.org
# https://isc.sans.edu/feeds_doc.html
  BL_NAME="dshield.org-top-20"
  BL_URL="https://feeds.dshield.org/block.txt"

function convert {
 while read line; do
  awk '/[^0-9]/ { printf "%s/%s\n",$1,$3 }'
 done
}

  BL_FILE="$BL_DIR/$BL_NAME.txt"
  if [ ! -f "$BL_FILE" ] || [ $(date +%s -r "$BL_FILE") -lt $(date +%s --date="$BL_AGE") ]; then
    echo "-- getting fresh $BL_NAME from $BL_URL"
    wget -q -t 2 --output-document=$BL_FILE $BL_URL --no-check-certificate
  fi
  
  if [ -f "$BL_FILE" ]; then
    echo "-- loading $BL_NAME from $BL_FILE"
    for net in `grep -E "^[1-9]" $BL_FILE | convert`; do
      blacklistit $net $BL_NAME
    done
  fi
 
# swap in the new sets.
ipset swap blacklist_ips_n blacklist_ips
ipset swap blacklist_nets_n blacklist_nets
ipset swap whitelist_ips_n whitelist_ips

# show before blacklist and after counts.
complete_msg="blacklist_ips: current=`ipset --list blacklist_ips_n | egrep '^[1-9]' | wc -l` \
  previous=`ipset --list blacklist_ips  | egrep '^[1-9]' | wc -l` \
  blacklist_nets: previous=`ipset --list blacklist_nets | egrep '^[1-9]' | wc -l` \
  current=`ipset --list blacklist_nets_n | egrep '^[1-9]' | wc -l`"

logmessage "$complete_msg"

# only send email if problems.
if [ -n "$MAIL_ADMIN" ] && [ -n "$ERROR_MSGS" ]; then
  echo -e "${complete_msg}\n${ERROR_MSGS}" | mail -s "$LOG_TAG $HOST_NAME" $MAIL_ADMIN
fi


# save memory space by destroying the temporary swap ipset
ipset destroy blacklist_ips_n
ipset destroy blacklist_nets_n
ipset destroy whitelist_ips_n

# save our ipsets for quick import on reboot.
ipset save blacklist_ips  > $BL_DIR/blacklist_ips.sav
ipset save blacklist_nets > $BL_DIR/blacklist_nets.sav
ipset save whitelist_ips  > $BL_DIR/whitelist_ips.sav

logmessage "NGO_FW script completed"