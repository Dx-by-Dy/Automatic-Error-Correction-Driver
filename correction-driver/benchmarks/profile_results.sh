#!/bin/bash

cat /sys/kernel/debug/tracing/trace_stat/function* | awk '
                                   /Function/ || /---/ {next} 
                                   {
                                     gsub(/us/, "", $3); gsub(/us/, "", $4); 
                                     
                                     hits[$1] += $2; 
                                     total_time[$1] += $3
                                   } 
                                   END {
                                     print "Function\t\t\tHits\tTotal Time\tAvg Time";
                                     for (f in hits) {
                                       avg = total_time[f] / hits[f];
                                       printf "%-35s\t%d\t%.3f us\t\t%.3f us\n", f, hits[f], total_time[f], avg
                                     }
                                   }' | sort -k5 -n -r