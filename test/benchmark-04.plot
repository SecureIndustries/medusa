#!/usr/bin/gnuplot

reset
set terminal pngcairo enhanced font "arial,10" fontscale 1.0 size 500,300;
set zeroaxis;

set ylabel "time (usecs)\nlower is better"

set xlabel "number of file descriptors"

set style data lines
set style line 1 linecolor rgb '#ff0000' linewidth 1
set style line 2 linecolor rgb '#00ff00' linewidth 1

plot './test/benchmark-04.out'       using 1:4 with lines ls 1 title 'medusa',      \
     './test/benchmark-04-event.out' using 1:4 with lines ls 2 title 'libevent
