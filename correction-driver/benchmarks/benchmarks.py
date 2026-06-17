#!/usr/bin/env python3

import json
import subprocess
import re
import os
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

REPEATS = 10
SSD_LABEL = "SSD"

DEVICES = {
    "corrdm": "/dev/mapper/corrdm",
    "vdb": "/dev/vdb",
}

TESTS = [
    {
        "name": "seq_write_512",
        "rw": "write",
        "bs": "512",
        "iodepth": 32,
        "numjobs": 8,
        "runtime": 30,
    },
    {
        "name": "seq_write_16k",
        "rw": "write",
        "bs": "16k",
        "iodepth": 32,
        "numjobs": 8,
        "runtime": 30,
    },
    {
        "name": "seq_read_512",
        "rw": "read",
        "bs": "512",
        "iodepth": 32,
        "numjobs": 8,
        "runtime": 30,
    },
    {
        "name": "seq_read_16k",
        "rw": "read",
        "bs": "16k",
        "iodepth": 32,
        "numjobs": 8,
        "runtime": 30,
    },
    # {
    #     "name": "rand_write_4k",
    #     "rw": "randwrite",
    #     "bs": "4k",
    #     "iodepth": 32,
    #     "numjobs": 8,
    #     "runtime": 60,
    # },
    # {
    #     "name": "rand_read_4k",
    #     "rw": "randread",
    #     "bs": "4k",
    #     "iodepth": 32,
    #     "numjobs": 8,
    #     "runtime": 60,
    # },
]

def run_fio(device_name, device_path, test, run_id):
    print(f"{device_name}: {test['name']} [{run_id + 1}/{REPEATS}]")

    out = f"results/{device_name}_{test['name']}_{run_id}.json"
    
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
            for run_id in range(REPEATS):

                result_file = run_fio(
                    dev_name,
                    dev_path,
                    test,
                    run_id
                )

                metrics = parse_result(result_file)

                rows.append({
                    "device": dev_name,
                    "test": test["name"],
                    "run": run_id,
                    **metrics
                })

    return pd.DataFrame(rows)

def summarize(df):
    agg = (
        df.groupby(["device", "test"])
          .agg({
              "bw_mib": ["mean", "std"],
              "iops": ["mean", "std"],
              "lat_avg_us": ["mean", "std"],
              "lat_p99_us": ["mean", "std"],
          })
    )

    agg.columns = [
        "_".join(col)
        for col in agg.columns
    ]

    agg = agg.reset_index()

    for metric in [
        "bw_mib",
        "iops",
        "lat_avg_us",
        "lat_p99_us"
    ]:
        agg[f"{metric}_se"] = (
            agg[f"{metric}_std"] / np.sqrt(REPEATS)
        )

    return agg

def add_labels(ax, pivot_mean, pivot_se):
    n_tests = len(pivot_mean.index)
    n_devices = len(pivot_mean.columns)

    bars = ax.patches

    bar_idx = 0

    for device_idx, device in enumerate(pivot_mean.columns):
        for test_idx in range(n_tests):

            bar = bars[bar_idx]
            bar_idx += 1

            value = bar.get_height()
            se = pivot_se.iloc[test_idx][device]

            ax.text(
                bar.get_x() + bar.get_width() / 2,
                value + se,
                f"{value:.2f}±{se:.2f}",
                ha="center",
                va="bottom",
                fontsize=8,
            )

def plot_metric(
    summary,
    metric,
    se_metric,
    ylabel,
    title,
    filename
):
    pivot_mean = summary.pivot(
        index="test",
        columns="device",
        values=metric
    )

    pivot_se = summary.pivot(
        index="test",
        columns="device",
        values=se_metric
    )

    fig, ax = plt.subplots(figsize=(12, 6))

    pivot_mean.plot(
        kind="bar",
        yerr=pivot_se,
        capsize=5,
        ax=ax
    )

    add_labels(ax, pivot_mean, pivot_se)

    ax.set_ylabel(ylabel)
    ax.set_title(title)

    plt.tight_layout()

    Path("figures").mkdir(exist_ok=True)

    plt.savefig(
        f"figures/{filename}",
        dpi=300
    )

def main():
    raw_df = collect()

    summary = summarize(raw_df)

    summary.to_csv(
        "results/summary.csv",
        index=False
    )

    plot_metric(
        summary,
        "bw_mib_mean",
        "bw_mib_se",
        "MiB/s",
        f"Bandwidth Comparison ({SSD_LABEL})",
        "bandwidth_ssd.png"
    )

    plot_metric(
        summary,
        "iops_mean",
        "iops_se",
        "IOPS",
        f"IOPS Comparison ({SSD_LABEL})",
        "iops_ssd.png"
    )

    plot_metric(
        summary,
        "lat_avg_us_mean",
        "lat_avg_us_se",
        "Latency (us)",
        f"Average Latency ({SSD_LABEL})",
        "latency_avg_ssd.png"
    )

    plot_metric(
        summary,
        "lat_p99_us_mean",
        "lat_p99_us_se",
        "Latency (us)",
        f"P99 Latency ({SSD_LABEL})",
        "latency_p99_ssd.png"
    )

    print(summary)


if __name__ == "__main__":
    main()