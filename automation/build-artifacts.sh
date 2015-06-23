#!/bin/bash -xe

shopt -s nullglob

rm -rf ../exported-artifacts/*
rm -rf $HOME/rpmbuild
# generate automake/autoconf files
./autogen.sh

# create rpm
make rpms
mkdir -p ../exported-artifacts/

for file in $(find $HOME/rpmbuild/ -iregex ".*\.\(tar\.gz\|rpm\)$"); do
    echo "Archiving $file"
    mv "$file" ../exported-artifacts/
done

