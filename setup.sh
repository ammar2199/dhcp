#!/bin/bash 

function dev() {
  # Disable firewalld.service using systemctl
  sudo systemctl stop firewalld.service

  # Disable Network Manager
  sudo nmcli device set wlp116s0f4u2 managed no
  sleep 5
  # Turn on wpa_supplicant
  sudo wpa_supplicant -B -i wlp116s0f4u2 -c wpa.conf # wpa.conf created 
                                                     # with wpa_passphrase tool
  sudo ip addr flush wlp116s0f4u2
  sudo ip route add 192.168.0.0/24 dev wlp116s0f4u2 # Add route so broadcast
                                                    # messages can be received.
}

function normal() {
  sudo ip addr flush wlp116s0f4u2
  sudo kill -9 $(pidof wpa_supplicant)
  sudo nmcli device set wlp116s0f4u2 managed yes
  # sudo systemctl start firewalld.service
}

case "$1" in
  "dev")
    echo 'Putting you in development mode...'
    dev
  ;;
  "normal")
    echo 'Putting you in normal mode...'
    normal
    ;;
  *)
    echo "Invocate as: './setup.sh <dev|normal>'"
esac


