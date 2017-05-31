#!/bin/bash

newUserSetup(){
  # Check if user already exists.
  sudo addgroup "$username"

	sudo useradd -p `mkpasswd "$pass"` -d /home/"$username" -m -g "$username" -s /bin/bash "$username"

  sudo sed "s/automatically logged in as 'pi'/automatically logged in as '$username'/g" -i /usr/bin/raspi-config

  sudo sed "s/if id -u pi/if id -u $username/g" -i /usr/bin/raspi-config

  sudo sed "s/autologin-user=pi/autologin-user=$username/g" -i /usr/bin/raspi-config

  sudo sed "s/The pi user has been removed/The $username user has been removed/g" -i /usr/bin/raspi-config

  sudo sed "s/--autologin pi/--autologin $username/g" -i /etc/systemd/system/autologin@.service

  sudo ln -fs /etc/systemd/system/autologin@.service /etc/systemd/system/getty.target.wants/getty@tty1.service

  sudo sed /etc/lightdm/lightdm.conf -i -e "s/^\(#\|\)autologin-user=.*/autologin-user=$username/"

  #sudo sed "s/pi/$username/g" -i /etc/sudoers

  sudo sh -c "echo -n '$username ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers"

	echo "The account is setup"
}

changeSshPort(){
  echo "Going to change default ssh port"

  sudo sed "s/Port 22/Port 3744/g" -i /etc/ssh/sshd_config

  sudo service ssh restart

  echo "SSH port changed"
}

disableSshPasswordAuth(){
  echo "Going to disable ssh password authentication"

  sudo sed "s/#PasswordAuthentication yes/PasswordAuthentication no/g" -i /etc/ssh/sshd_config

  sudo service ssh restart

  echo "SSH password authentication is disabled"
}

protectNetwork(){
  echo "Going to increase network security"

  # prevent some spoofing attacks
  sudo sed "s/#net.ipv4.conf.default.rp_filter=1/net.ipv4.conf.default.rp_filter=1/g" -i /etc/sysctl.conf
  sudo sed "s/#net.ipv4.conf.all.rp_filter=1/net.ipv4.conf.all.rp_filter=1/g" -i /etc/sysctl.conf

  # Do not accept ICMP redirects (prevent MITM attacks)
  sudo sed "s/#net.ipv4.conf.all.accept_redirects = 0/net.ipv4.conf.all.accept_redirects = 0/g" -i /etc/sysctl.conf
  sudo sed "s/#net.ipv6.conf.all.accept_redirects = 0/net.ipv6.conf.all.accept_redirects = 0/g" -i /etc/sysctl.conf

  # Don't send ICMP redirects
  sudo sed "s/#net.ipv4.conf.all.send_redirects = 0/net.ipv4.conf.all.send_redirects = 0/g" -i /etc/sysctl.conf

  # Do not accept IP source route packets (we are not a router)
  sudo sed "s/#net.ipv4.conf.all.accept_source_route = 0/net.ipv4.conf.all.accept_source_route = 0/g" -i /etc/sysctl.conf
  sudo sed "s/#net.ipv6.conf.all.accept_source_route = 0/net.ipv6.conf.all.accept_source_route = 0/g" -i /etc/sysctl.conf

  echo "Network security is done"
}

setupFirewall(){

  echo "Installing Uncomplicated Firewall"

  sudo apt-get install ufw -y

  echo "Firewall installed"

  echo "Configuring Firewall"

  # Deny all incoming connections
  sudo ufw default deny incoming

  # Allow ssh from local network only and from one port only
  sudo ufw allow from 192.168.1.0/24 to any port 3744 proto tcp

  echo "Going to enable ufw"

  sudo ufw --force enable

  echo "Firewall is configured"
}

moveAllData(){
  # Move pi folder
  sudo cp -r /home/pi/* /home/"$username"

}

copySshConnectivityKey(){

  echo "Copying public key for SSH connectivity"

  sudo mkdir -p /home/"$username"/.ssh

  cd /home/"$username"/.ssh && sudo touch authorized_keys

  sudo chmod 600 /home/"$username"/.ssh/authorized_keys

  sudo sh -c "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC0iaGDNGbRZ1P0krH4biyqOlCUycE2bp47/eEmZmSd7AUIbaiCSa8SVq79EyBYmAfMhXDlXlA35EKo+ZAaeNsSfwM0TXhs1zqU/wjh7QDeaB8mkRz2ZivWtFzRR6O43FnWYYYrMfztq6pFPAMthbVBMMljY+E2R1DobHDGfV8dqorZk/ZKm70GboDFNtw6JJoRaV0WHOTHEvQO6OpjEdj3YsqMV7Oud64EmhtacGSk0H+EusoBXofc4hPtppQbealQdpXsmy62x4gurTwyUTbO8cGI55cEieiKikk42GeICWy1hawuGASpKrYKeIgSvk1q8EdJQuKG7a7aB0AxBKKvJGuMM2aSTYvXNB5thM2jJtVDg5cUL9GHqrU/R1zo9pTULRHQcMS8IrL5Tc0mDbwp4yjDEo+pkQ0pOBKKhzG45RMBFTiUwZmIgxtC5u1WF240MY28UZk8ffFFz8/M/NL83UDkyRup2IGTcs+vVTOm077xpJ50+pmAsNUGx+sOL93tE5/+RjyLp8oBlnWF8iLu0/UZnqH3mKu105aSIQAWoPKFJkQZyJg95DLwjMGvn7PW/KliOVvhk/ML+GUvdB5NWkC6XVGdHtj+fBQlmmfm5ZLqpMmpDm1D1grIKh8WwhUvrdfi8Vzx1EaK3KaN+6ce2L0ymo3RxdVvZ3ex4Aq1Vw== bxm player access' >> /home/$username/.ssh/authorized_keys"

  echo "Copying public key for SSH connectivity is done"

  sudo chown -R "$username":"$username" /home/"$username"

}

setupFail2ban(){

  echo "Installing fail2ban"

  # Fail2ban to stop the brute-force attack
  cd /home/"$username" && sudo wget https://github.com/fail2ban/fail2ban/archive/0.9.4.tar.gz

  cd /home/"$username" && sudo tar -xvzf 0.9.4.tar.gz

  cd /home/"$username"/fail2ban-0.9.4 && sudo python setup.py install

  cd /home/"$username" && sudo rm -rf 0.9.4.tar.gz

  echo "Configuring fail2ban"

  sudo touch /etc/fail2ban/jail.local && sudo sh -c "echo '[ssh]\nenabled = true\nport = ssh\nfilter = sshd\nlogpath = /var/log/auth.log\nbantime = 900\nbanaction = iptables-allports\nfindtime = 900\nmaxretry = 3' >> /etc/fail2ban/jail.local"

  sudo cp /home/"$username"/fail2ban-0.9.4/files/debian-initd /etc/init.d/fail2ban

  sudo update-rc.d fail2ban defaults

  sudo service fail2ban start

  echo "Configuration done for fail2ban"

}

removeDefaultUser(){
  sudo deluser -remove-home pi
}

# Run as root, of course. (this might not be necessary, because we have to run the script somehow with root anyway)
#if [ "$UID" -ne 0 ]
#then
  #echo "Must be root to run this script."
  #exit 0
#fi

username=$1
pass=$2

newUserSetup
changeSshPort
disableSshPasswordAuth
protectNetwork
setupFirewall
moveAllData
copySshConnectivityKey
setupFail2ban
#removeDefaultUser

echo "Restarting system.."
sudo reboot

