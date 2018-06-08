#! /bin/bash

fpath=`dirname $0`
if [ "$fpath" != "" ]; then
    cd $fpath
fi

date
./vanity $*
date
