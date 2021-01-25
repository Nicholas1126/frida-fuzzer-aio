#!/bin/sh

if [[ $# -ne 1 ]]; then
  echo "Usage: ./test <pcapng_folder>"
  exit 1
fi

PCAPNG_FOLDER=$1

echo "-- Fuzzing pcapng files in $PCAPNG_FOLDER"

echo "-- Compiling"

make
if [[ $? != 0 ]]; then
  exit 1
fi

echo "-- Fuzzing"

failed=0
succeded=0
processed=0

meta=/tmp/meta
output=/tmp/tmp.pcapng

for input in $PCAPNG_FOLDER/*.pcapng; do
  rm -f $meta $output

  ./bin/radamsa --generators pcapng --patterns od --mutations nop $input --output $output --meta $meta

  if cmp -s "$input" "$output"; then
    echo "[OK] $input (input_size=$(stat -f%z $input), output_size=$(stat -f%z $output))"
    let succeded=succeded+1
  else
    echo "[FAILED] $input (input_size=$(stat -f%z $input), output_size=$(stat -f%z $output))"
    cat $meta
    let failed=failed+1
  fi

  let processed=processed+1
done

echo "Processed $processed pcapng files, of which $succeded succeded and $failed failed."
