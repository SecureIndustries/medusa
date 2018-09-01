#!/bin/bash

first=100;
increment=100;
last=3000;

rm -rf ./test/benchmark-04.out
rm -rf ./test/benchmark-04-event.out

for i in `seq $first $increment $last`; do
	line=`./test/benchmark-04 -b 0 -l 10 -s 10 -n $i -a 100 -w 100 2>&1 | tail -n 2 | head -n 1`;
	printf "%8d $line\n" $i;
	printf "%8d $line\n" $i >> ./test/benchmark-04.out;
done

for i in `seq $first $increment $last`; do
	line=`./test/benchmark-04-event -b 0 -l 10 -s 10 -n $i -a 100 -w 100 2>&1 | tail -n 2 | head -n 1`;
	printf "%8d $line\n" $i;
	printf "%8d $line\n" $i >> ./test/benchmark-04-event.out;
done
