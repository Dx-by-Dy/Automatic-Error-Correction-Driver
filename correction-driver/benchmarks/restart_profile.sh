#!/bin/bash

echo 0 > /sys/kernel/debug/tracing/function_profile_enabled
echo nop > /sys/kernel/debug/tracing/current_tracer
echo '*:mod:correction_driver' > /sys/kernel/debug/tracing/set_ftrace_filter
echo 1 > /sys/kernel/debug/tracing/function_profile_enabled
