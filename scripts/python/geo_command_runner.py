import subprocess
import time
import sys
import numpy as np
from scipy.stats import geom

def run_command(command):
    start_time = time.time()
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    end_time = time.time()
    return end_time - start_time

def main():
    if len(sys.argv) < 2:
        print("Usage: python", sys.argv[0], "<command>")
        sys.exit(1)

    command = " ".join(sys.argv[1:])
    response_times = []
    iteration = 0

    while True:
        iteration += 1
        response_time = run_command(command)
        response_times.append(response_time)

        mean = np.mean(response_times)
        std_dev = np.std(response_times)

        print(f"Iteration {iteration}:")
        print(f"  Response time: {response_time:.4f} seconds")
        print(f"  Running mean: {mean:.4f} seconds")
        print(f"  Running standard deviation: {std_dev:.4f} seconds")

        # Generate geometrically distributed wait time with mean of 60 seconds (1 minute)
        wait_time = geom.rvs(p=1/60) # p = 1/mean
        time.sleep(wait_time)

if __name__ == "__main__":
    main()

