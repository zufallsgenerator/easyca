#!/bin/bash

set +e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CMD="python ${DIR}/../easyca/cli.py"

TEMPDIR=$(mktemp -d -t easyca_test.XXXXX)
CA_PATH=$TEMPDIR

echo "### Init CA without --common-name should fail"
$CMD ca init 2&> /dev/null
# Negate the exit code
if [[ $? == 0 ]]; then
	echo "*** Expected exitcode != 0"
	EXITCODES+=(1)
else
	EXITCODES+=(0)
fi


echo "### Should Init CA"
$CMD ca init --common-name="example.com" > /dev/null
EXITCODES+=($?)


rm -rf $TEMPDIR
echo "All tests done, results: ${EXITCODES[*]}"

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
