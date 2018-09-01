#!/usr/bin/gnuplot

reset
set terminal pngcairo enhanced font "tahoma,10" fontscale 1.0 size 1600,1200;

set ylabel "time (usecs)\nlower is better";

set xlabel "number of file descriptors";

set style data lines;
set style line 1 linecolor rgb '#4B87EF' linewidth 1.5;
set style line 2 linecolor rgb '#D94838' linewidth 1.5;
set style line 3 linecolor rgb '#76BD51' linewidth 1.5;

set key left top;

set yrange [];
set xrange [100:];
set logscale x 10;

set output './test/benchmark-04-100.png';

set multiplot layout 3,2 rowsfirst title '100 active clients';

set title "create";
plot './test/benchmark-04-100.out'       using 1:2 with lines ls 1 title 'medusa',  \
     './test/benchmark-04-100-event.out' using 1:2 with lines ls 2 title 'libevent';

set title "apply";
plot './test/benchmark-04-100.out'       using 1:3 with lines ls 1 title 'medusa',  \
     './test/benchmark-04-100-event.out' using 1:3 with lines ls 2 title 'libevent';

set title "run";
plot './test/benchmark-04-100.out'       using 1:4 with lines ls 1 title 'medusa',  \
     './test/benchmark-04-100-event.out' using 1:4 with lines ls 2 title 'libevent';

set title "destroy";
plot './test/benchmark-04-100.out'       using 1:5 with lines ls 1 title 'medusa',  \
     './test/benchmark-04-100-event.out' using 1:5 with lines ls 2 title 'libevent';

set title "total";
plot './test/benchmark-04-100.out'       using 1:6 with lines ls 1 title 'medusa',  \
     './test/benchmark-04-100-event.out' using 1:6 with lines ls 2 title 'libevent';

unset multiplot;

set yrange [];
set xrange [1000:];
set logscale x 10;

set output './test/benchmark-04-1000.png';

set multiplot layout 3,2 rowsfirst title '1000 active clients';

set title "create";
plot './test/benchmark-04-1000.out'       using 1:2 with lines ls 1 title 'medusa',  \
     './test/benchmark-04-1000-event.out' using 1:2 with lines ls 2 title 'libevent';

set title "apply";
plot './test/benchmark-04-1000.out'       using 1:3 with lines ls 1 title 'medusa',  \
     './test/benchmark-04-1000-event.out' using 1:3 with lines ls 2 title 'libevent';

set title "run";
plot './test/benchmark-04-1000.out'       using 1:4 with lines ls 1 title 'medusa',  \
     './test/benchmark-04-1000-event.out' using 1:4 with lines ls 2 title 'libevent';

set title "destroy";
plot './test/benchmark-04-1000.out'       using 1:5 with lines ls 1 title 'medusa',  \
     './test/benchmark-04-1000-event.out' using 1:5 with lines ls 2 title 'libevent';

set title "total";
plot './test/benchmark-04-1000.out'       using 1:6 with lines ls 1 title 'medusa',  \
     './test/benchmark-04-1000-event.out' using 1:6 with lines ls 2 title 'libevent';

unset multiplot;

set yrange [];
set xrange [100:];
set logscale x 10;

set output './test/benchmark-04-100-timer.png';

set multiplot layout 3,2 rowsfirst title '100 active clients with timeout timer';

set title "create";
plot './test/benchmark-04-100-timer.out'       using 1:2 with lines ls 1 title 'medusa',  \
     './test/benchmark-04-100-timer-event.out' using 1:2 with lines ls 2 title 'libevent';

set title "apply";
plot './test/benchmark-04-100-timer.out'       using 1:3 with lines ls 1 title 'medusa',  \
     './test/benchmark-04-100-timer-event.out' using 1:3 with lines ls 2 title 'libevent';

set title "run";
plot './test/benchmark-04-100-timer.out'       using 1:4 with lines ls 1 title 'medusa',  \
     './test/benchmark-04-100-timer-event.out' using 1:4 with lines ls 2 title 'libevent';

set title "destroy";
plot './test/benchmark-04-100-timer.out'       using 1:5 with lines ls 1 title 'medusa',  \
     './test/benchmark-04-100-timer-event.out' using 1:5 with lines ls 2 title 'libevent';

set title "total";
plot './test/benchmark-04-100-timer.out'       using 1:6 with lines ls 1 title 'medusa',  \
     './test/benchmark-04-100-timer-event.out' using 1:6 with lines ls 2 title 'libevent';

unset multiplot;

set yrange [];
set xrange [1000:];
set logscale x 10;

set output './test/benchmark-04-1000-timer.png';

set multiplot layout 3,2 rowsfirst title '1000 active clients with timeout timer';

set title "create";
plot './test/benchmark-04-1000-timer.out'       using 1:2 with lines ls 1 title 'medusa',  \
     './test/benchmark-04-1000-timer-event.out' using 1:2 with lines ls 2 title 'libevent';

set title "apply";
plot './test/benchmark-04-1000-timer.out'       using 1:3 with lines ls 1 title 'medusa',  \
     './test/benchmark-04-1000-timer-event.out' using 1:3 with lines ls 2 title 'libevent';

set title "run";
plot './test/benchmark-04-1000-timer.out'       using 1:4 with lines ls 1 title 'medusa',  \
     './test/benchmark-04-1000-timer-event.out' using 1:4 with lines ls 2 title 'libevent';

set title "destroy";
plot './test/benchmark-04-1000-timer.out'       using 1:5 with lines ls 1 title 'medusa',  \
     './test/benchmark-04-1000-timer-event.out' using 1:5 with lines ls 2 title 'libevent';

set title "total";
plot './test/benchmark-04-1000-timer.out'       using 1:6 with lines ls 1 title 'medusa',  \
     './test/benchmark-04-1000-timer-event.out' using 1:6 with lines ls 2 title 'libevent';

unset multiplot;
