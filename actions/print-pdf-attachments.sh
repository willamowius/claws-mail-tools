#!/bin/bash
SUPPORTED_FILETYPES=.pdf
LP_OPTIONS="-o media=A4,tray1 -o fit-to-page -o position=top -o scaling=100"

FILENAME=$1
LP_EXTRA_OPTIONS=$2

if [ "$?" = "0" ]; then
	/usr/bin/uudeview +e $SUPPORTED_FILETYPES -p ~/print_tmp/ -i -q $FILENAME
	for f in ~/print_tmp/*
	do
		test -f "$f" || continue
		lp $LP_OPTIONS $LP_EXTRA_OPTIONS "$f" > /dev/null
		rm "$f"
	done
fi

