function end_test {
	EXITCODES=$1
	for exitcode in "${EXITCODES[@]}"
	do
		:
		if [[ $exitcode != 0 ]]; then
			echo "*** Test suite failed"
			exit $exitcode
		fi
	done
	echo "Success"
	exit 0
}