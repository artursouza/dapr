#!/bin/bash

set -ue





make ./dist/${GOOS}_${GOARCH}/release/daprd

./dist/darwin_arm64/release/daprd --app-id target &
pid=$!
sleep $SECONDS_FOR_PROCESS_TO_RUN
RESIDENT_MEM=`ps -o rss= $pid`
VIRT_MEM=`ps -o vsz= $pid`
kill -TERM $pid
lsof -p $pid +r 1 &>/dev/null

~/.dapr/bin/daprd --app-id baseline &
baseline_pid=$!
sleep $SECONDS_FOR_PROCESS_TO_RUN
BASELINE_RESIDENT_MEM=`ps -o rss= $baseline_pid`
BASELINE_VIRT_MEM=`ps -o vsz= $baseline_pid`
kill -TERM $baseline_pid
lsof -p $baseline_pid +r 1 &>/dev/null

DELTA_RESIDENT_MEM=$(( $RESIDENT_MEM - $BASELINE_RESIDENT_MEM ))
DELTA_VIRT_MEM=$(( $VIRT_MEM - $BASELINE_VIRT_MEM ))

echo "Resident memory: $RESIDENT_MEM KB compared to baseline of $BASELINE_RESIDENT_MEM KB ($DELTA_RESIDENT_MEM KB)"
echo "Virtual memory: $VIRT_MEM KB compared to baseline of $BASELINE_VIRT_MEM KB ($DELTA_VIRT_MEM KB)"
echo $DELTA_VIRT_MEM

if [[ $DELTA_VIRT_MEM -gt $LIMIT_DELTA_VIRT_MEM ]]; then
   echo "New version is consuming too much virtual memory: $DELTA_VIRT_MEM KB"
   exit 1
fi
