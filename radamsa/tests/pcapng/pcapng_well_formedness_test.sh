#!/bin/sh

if [[ $# -ne 2 ]]; then
  echo "Usage: ./test <pcapng_folder> <pcapng_samples>"
  exit 1
fi

PCAPNG_FOLDER=$1
SAMPLES=$2

echo "-- Fuzzing pcapng files in $PCAPNG_FOLDER"
echo "-- Trying to generate $SAMPLES (unique) fuzzed pcapngs for each pcapng file"

echo "-- Compiling"

make
if [[ $? != 0 ]]; then
  exit 1
fi

echo "-- Fuzzing"

generated=0
analyzed=0
failed=0
succeded=0
skipped=0
total_unique_pcaps=0

meta=/tmp/meta
output=/tmp/tmp_%03n.pcapng
output_pattern=/tmp/tmp_*.pcapng
output_hashes=/tmp/tmp_hashes

for input in $PCAPNG_FOLDER/*.pcapng; do
  rm -f $meta $output_pattern $output_hashes

  # first level check - NOP mutation
  #./bin/radamsa --generators pcapng $input --mutations nop --output $output --meta $meta

  # second level check - in-place modification
  #./bin/radamsa --generators pcapng $input --mutations bei --output $output --meta $meta

  # third level check - add bytes
  #./bin/radamsa --generators pcapng $input --mutations bi --output $output --meta $meta

  # third level check - remove bytes
  #./bin/radamsa --generators pcapng $input --mutations bd --output $output --meta $meta

  # fourth level check - everything is allowed
  #./bin/radamsa --generators pcapng $input --output $output --meta $meta

  # fifth level check - generate multiple pcaps, discard checksums
  # ./bin/radamsa --generators pcapng $input --output $output --checksums 0 --count $SAMPLES --meta $meta

  # sixth level check - generate multiple pcaps, keep checksums
  ./bin/radamsa --generators pcapng $input --output $output --count $SAMPLES --meta $meta

  # debug with
  #./bin/ol -r rad/main.scm --generators pcapng $input --output $output --meta $meta

  exit_value=$?

  if [[ $exit_value != 0 ]]; then
    cat $meta
    echo "radamsa exited with non-zero value: $exit_value"
    echo "[WARN] $input"
    let skipped=skipped+1
  else
    let failures=0
    let analyzed=analyzed+1
    for current_output in $output_pattern; do
      let generated=generated+1
      tcpdump_output="$(tcpdump -t -qnr $current_output 2>&1)"
      if [[ $? -eq 0 ]]; then
        hash="$(shasum -b -a 256 $current_output | cut -d" " -f 1)"
        echo $hash >> $output_hashes
        let succeded=succeded+1
      else
        cat $meta
        echo $tcpdump_output
        echo "[FAILED] $input ~> $current_output (input_size=$(stat -f%z $input), output_size=$(stat -f%z $current_output))"
        let failures=failures+1
      fi
    done

    let failed=failed+failures

    if [[ $failures -eq 0 ]]; then
      unique_hashes=$(cat $output_hashes | sort | uniq | wc -l | xargs)
      echo "[OK] $input (input_size=$(stat -f%z $input), unique_hashes=$unique_hashes)"
    fi

    total_unique_pcaps=$((total_unique_pcaps+unique_hashes))
  fi
done

echo "-- INPUT: $analyzed analyzed, $skipped skipped"
echo "-- OUTUT: $generated generated, $total_unique_pcaps unique ($(bc -l <<< "scale=2; $total_unique_pcaps/$generated*100")%)"
echo "-- STATS: $succeded successes, $failed failures"
