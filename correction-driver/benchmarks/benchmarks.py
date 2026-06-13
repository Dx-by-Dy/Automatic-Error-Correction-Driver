#!/usr/bin/env python3

import json
import subprocess
import re
import os
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt


SSD_LABEL = "SSD"

DEVICES = {
    "corrdm": "/dev/mapper/corrdm",
    "vdb": "/dev/vdb",
}

TESTS = [
    {
        "name": "seq_write_16k",
        "rw": "write",
        "bs": "16k",
        "iodepth": 32,
        "numjobs": 8,
        "runtime": 60,
    },
    {
        "name": "seq_read_16k",
        "rw": "read",
        "bs": "16k",
        "iodepth": 32,
        "numjobs": 8,
        "runtime": 60,
    },
    {
        "name": "rand_write_4k",
        "rw": "randwrite",
        "bs": "4k",
        "iodepth": 32,
        "numjobs": 8,
        "runtime": 60,
    },
    {
        "name": "rand_read_4k",
        "rw": "randread",
        "bs": "4k",
        "iodepth": 32,
        "numjobs": 8,
        "runtime": 60,
    },
]

def run_fio(device_name, device_path, test):
    print(f"{device_name}: {test['name']}")

    out = f"results/{device_name}_{test['name']}.json"

    cmd = [
        "fio",
        f"--name={test['name']}",
        "--output-format=json",
        f"--output={out}",
        f"--filename={device_path}",
        f"--rw={test['rw']}",
        f"--bs={test['bs']}",
        "--direct=1",
        "--ioengine=libaio",
        f"--iodepth={test['iodepth']}",
        f"--numjobs={test['numjobs']}",
        "--time_based",
        f"--runtime={test['runtime']}",
    ]

    subprocess.run(cmd, check=True)

    return out

def parse_result(path):
    with open(path) as f:
        data = json.load(f)

    job = data["jobs"][0]

    if "read" in job and job["read"]["io_bytes"] > 0:
        stat = job["read"]
    else:
        stat = job["write"]

    return {
        "bw_mib": stat["bw_bytes"] / 1024 / 1024,
        "iops": stat["iops"],
        "lat_avg_us": stat["clat_ns"]["mean"] / 1000,
        "lat_p99_us": stat["clat_ns"]["percentile"]["99.000000"] / 1000,
    }

def collect():
    rows = []

    Path("results").mkdir(exist_ok=True)

    for dev_name, dev_path in DEVICES.items():
        for test in TESTS:

            result_file = run_fio(
                dev_name,
                dev_path,
                test
            )

            metrics = parse_result(result_file)

            rows.append({
                "device": dev_name,
                "test": test["name"],
                **metrics
            })

    return pd.DataFrame(rows)

def plot_bw(df):
    plt.figure(figsize=(12, 6))

    pivot = df.pivot(
        index="test",
        columns="device",
        values="bw_mib"
    )

    pivot.plot(kind="bar")

    plt.ylabel("MiB/s")
    plt.title(f"Bandwidth Comparison ({SSD_LABEL})")
    plt.tight_layout()

    Path("figures").mkdir(exist_ok=True)
    plt.savefig("figures/bandwidth_ssd.png")

def plot_iops(df):
    plt.figure(figsize=(12, 6))

    pivot = df.pivot(
        index="test",
        columns="device",
        values="iops"
    )

    pivot.plot(kind="bar")

    plt.ylabel("IOPS")
    plt.title(f"IOPS Comparison ({SSD_LABEL})")
    plt.tight_layout()

    Path("figures").mkdir(exist_ok=True)
    plt.savefig("figures/iops_ssd.png")

def plot_latency(df):
    plt.figure(figsize=(12, 6))

    pivot = df.pivot(
        index="test",
        columns="device",
        values="lat_avg_us"
    )

    pivot.plot(kind="bar")

    plt.ylabel("Latency (us)")
    plt.title(f"Average Latency ({SSD_LABEL})")
    plt.tight_layout()

    Path("figures").mkdir(exist_ok=True)
    plt.savefig("figures/latency_avg.png")

def plot_p99(df):
    plt.figure(figsize=(12, 6))

    pivot = df.pivot(
        index="test",
        columns="device",
        values="lat_p99_us"
    )

    pivot.plot(kind="bar")

    plt.ylabel("Latency (us)")
    plt.title(f"P99 Latency ({SSD_LABEL})")
    plt.tight_layout()

    Path("figures").mkdir(exist_ok=True)
    plt.savefig("figures/latency_p99_ssd.png")

def main():
    df = collect()

    print(df)

    plot_bw(df)
    plot_iops(df)
    plot_latency(df)
    plot_p99(df)

    print("\nDone.")


if __name__ == "__main__":
    main()