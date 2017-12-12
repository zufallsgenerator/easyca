#!/bin/bash

set +e


DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $DIR/base.bash
CMD="python3 ${DIR}/../easyca/cli.py"

TEMPDIR=$(mktemp -d -t easyca_test.XXXXX)

echo "### Should Init CA with utf-8 CN"
$CMD --ca-path=$TEMPDIR init --common-name="Linköping" > /dev/null
EXITCODES+=($?)
ret=$($CMD --ca-path=$TEMPDIR info | grep "Linköping")
if [[ "${ret}" == "" ]]; then
	echo "*** Could not find common-name provided"
	EXITCODE+=(0)
else
	EXITCODE+=(0)
fi




rm -rf $TEMPDIR

end_test $EXITCODES
