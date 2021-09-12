#!/bin/bash

BASE_FOLDER=/usr/share/yukino-message-client
notify() {
	XUSERS=$(who|grep -E "\(:[0-9](\.[0-9])*\)"|awk '{print $1$NF}'|sort -u)
	for XUSER in "${XUSERS[@]}"; do
		IFS='(' read -r -a NAME <<< "$XUSER"
		DISPLAY=${NAME[1]/)/}
		DBUS_ADDRESS=unix:path=/run/user/$(id -u "${NAME[0]}")/bus
		sudo -u "${NAME[0]}" DISPLAY="${DISPLAY}" \
			DBUS_SESSION_BUS_ADDRESS="${DBUS_ADDRESS}" \
			PATH="${PATH}" \
			notify-send -u normal -i ${BASE_FOLDER}/icon.png "$@"
		done
}
critical-notify() {
	XUSERS=$(who|grep -E "\(:[0-9](\.[0-9])*\)"|awk '{print $1$NF}'|sort -u)
	for XUSER in "${XUSERS[@]}"; do
		IFS='(' read -r -a NAME <<< "$XUSER"
		DISPLAY=${NAME[1]/)/}
		DBUS_ADDRESS=unix:path=/run/user/$(id -u "${NAME[0]}")/bus
		sudo -u "${NAME[0]}" DISPLAY="${DISPLAY}" \
			DBUS_SESSION_BUS_ADDRESS="${DBUS_ADDRESS}" \
			PATH="${PATH}" \
			notify-send -u critical -i ${BASE_FOLDER}/icon.png "$@"
		done
}

if [ "$1" = "reboot" ]
then
	critical-notify 'Pending: Reboot' 'System is about to reboot in 60 secs.'
	shutdown -r
fi

if [ "$1" = "shutdown" ]
then
	critical-notify 'Pending: Shutdown' 'System is about to shutdown in 60 secs.'
	shutdown
fi

if [ "$1" = "switch_to_windows" ]
then
	critical-notify 'Pending: Switch To Windows' 'System is about to switch to Windows OS in 3 secs.'
	sleep 3
	systemctl reboot --boot-loader-entry=auto-windows
fi

if [ "$1" = "notify" ]
then
	notify "${@:2}"
fi
