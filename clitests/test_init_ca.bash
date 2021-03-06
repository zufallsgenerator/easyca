#!/bin/bash

set +e


DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $DIR/base.bash
CMD="python ${DIR}/../cli/cmd_ca.py"

TEMPDIR=$(mktemp -d -t easyca_test.XXXXX)
#CA_PATH=$TEMPDIR

echo "### Init CA without --common-name should fail"
$CMD --ca-path=$TEMPDIR init 2&> /dev/null
# Negate the exit code
if [[ $? == 0 ]]; then
	echo "*** Expected exitcode != 0"
	EXITCODES+=(1)
else
	EXITCODES+=(0)
fi


echo "### Should Init CA"
$CMD --ca-path=$TEMPDIR init --common-name="example.com" > /dev/null
EXITCODES+=($?)
ret=$($CMD --ca-path=$TEMPDIR info | grep "example.com")
if [[ "${ret}" == "" ]]; then
	echo "*** Could not find common-name provided"
	EXITCODE+=(0)
else
	EXITCODE+=(0)
fi




rm -rf $TEMPDIR

end_test $EXITCODES
