#!/bin/bash

echo 0 > /sys/kernel/debug/tracing/function_profile_enabled
echo nop > /sys/kernel/debug/tracing/current_tracer
echo '*:mod:dm_dcorr' > /sys/kernel/debug/tracing/set_ftrace_filter
echo 1 > /sys/kernel/debug/tracing/function_profile_enabled
