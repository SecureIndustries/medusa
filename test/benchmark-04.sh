#!/bin/bash

rm -rf ./test/benchmark-04-*.out

current=100;
while [ $current -le 100000 ]; do
	line=`./test/benchmark-04 -b 0 -l 2 -s 10 -n $current -a 100 -w 100 -t 0 2>&1 | tail -n 2 | head -n 1`;
	printf "%8d $line\n" $current;
	printf "%8d $line\n" $current >> ./test/benchmark-04-100.out;
	if [ $current -lt 1000 ]; then
		current=$(($current + 100));
	elif [ $current -lt 10000 ]; then
		current=$(($current + 1000));
	elif [ $current -lt 100000 ]; then
		current=$(($current + 10000));
	else
		break;
	fi
done

current=100;
while [ $current -le 100000 ]; do
	line=`./test/benchmark-04-event -b 0 -l 2 -s 10 -n $current -a 100 -w 100 -t 0 2>&1 | tail -n 2 | head -n 1`;
	printf "%8d $line\n" $current;
	printf "%8d $line\n" $current >> ./test/benchmark-04-100-event.out;
	if [ $current -lt 1000 ]; then
		current=$(($current + 100));
	elif [ $current -lt 10000 ]; then
		current=$(($current + 1000));
	elif [ $current -lt 100000 ]; then
		current=$(($current + 10000));
	else
		break;
	fi
done

current=1000;
while [ $current -le 100000 ]; do
	line=`./test/benchmark-04 -b 0 -l 2 -s 10 -n $current -a 1000 -w 1000 -t 0 2>&1 | tail -n 2 | head -n 1`;
	printf "%8d $line\n" $current;
	printf "%8d $line\n" $current >> ./test/benchmark-04-1000.out;
	if [ $current -lt 1000 ]; then
		current=$(($current + 100));
	elif [ $current -lt 10000 ]; then
		current=$(($current + 1000));
	elif [ $current -lt 100000 ]; then
		current=$(($current + 10000));
	else
		break;
	fi
done

current=1000;
while [ $current -le 100000 ]; do
	line=`./test/benchmark-04-event -b 0 -l 2 -s 10 -n $current -a 1000 -w 1000 -t 0 2>&1 | tail -n 2 | head -n 1`;
	printf "%8d $line\n" $current;
	printf "%8d $line\n" $current >> ./test/benchmark-04-1000-event.out;
	if [ $current -lt 1000 ]; then
		current=$(($current + 100));
	elif [ $current -lt 10000 ]; then
		current=$(($current + 1000));
	elif [ $current -lt 100000 ]; then
		current=$(($current + 10000));
	else
		break;
	fi
done

current=100;
while [ $current -le 100000 ]; do
	line=`./test/benchmark-04 -b 0 -l 2 -s 10 -n $current -a 100 -w 100 -t 1 2>&1 | tail -n 2 | head -n 1`;
	printf "%8d $line\n" $current;
	printf "%8d $line\n" $current >> ./test/benchmark-04-100-timer.out;
	if [ $current -lt 1000 ]; then
		current=$(($current + 100));
	elif [ $current -lt 10000 ]; then
		current=$(($current + 1000));
	elif [ $current -lt 100000 ]; then
		current=$(($current + 10000));
	else
		break;
	fi
done

current=100;
while [ $current -le 100000 ]; do
	line=`./test/benchmark-04-event -b 0 -l 2 -s 10 -n $current -a 100 -w 100 -t 1 2>&1 | tail -n 2 | head -n 1`;
	printf "%8d $line\n" $current;
	printf "%8d $line\n" $current >> ./test/benchmark-04-100-timer-event.out;
	if [ $current -lt 1000 ]; then
		current=$(($current + 100));
	elif [ $current -lt 10000 ]; then
		current=$(($current + 1000));
	elif [ $current -lt 100000 ]; then
		current=$(($current + 10000));
	else
		break;
	fi
done

current=1000;
while [ $current -le 100000 ]; do
	line=`./test/benchmark-04 -b 0 -l 2 -s 10 -n $current -a 1000 -w 1000 -t 1 2>&1 | tail -n 2 | head -n 1`;
	printf "%8d $line\n" $current;
	printf "%8d $line\n" $current >> ./test/benchmark-04-1000-timer.out;
	if [ $current -lt 1000 ]; then
		current=$(($current + 100));
	elif [ $current -lt 10000 ]; then
		current=$(($current + 1000));
	elif [ $current -lt 100000 ]; then
		current=$(($current + 10000));
	else
		break;
	fi
done

current=1000;
while [ $current -le 100000 ]; do
	line=`./test/benchmark-04-event -b 0 -l 2 -s 10 -n $current -a 1000 -w 1000 -t 1 2>&1 | tail -n 2 | head -n 1`;
	printf "%8d $line\n" $current;
	printf "%8d $line\n" $current >> ./test/benchmark-04-1000-timer-event.out;
	if [ $current -lt 1000 ]; then
		current=$(($current + 100));
	elif [ $current -lt 10000 ]; then
		current=$(($current + 1000));
	elif [ $current -lt 100000 ]; then
		current=$(($current + 10000));
	else
		break;
	fi
done
