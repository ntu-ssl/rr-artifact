from matplotlib.ticker import FuncFormatter
import datetime;
import numpy as np
import math
import sys
import matplotlib.pyplot as plt
import matplotlib as mpl
import json
import os
from scipy.stats import norm
import subprocess

CONFIG_DIR = os.environ.get('CONFIG')
ROOT_DIR = ''

with open(CONFIG_DIR + '/config.json', 'r') as file:
    data = json.load(file)
    ROOT_DIR = data['root-directory']

CUR_DIR = ROOT_DIR + '/aes-profile/analysis-utils'

TEWHAT = int(sys.argv[1])
SAMPLE_N = int(sys.argv[2]) 
d_range = int(sys.argv[3]) 

reversed_threshold_candidates = range(2000 - 1, 0 - 1, -1)
threshold_candidates = range(0, 2000, 1)

def get_data(mode):
    data = []
    with open(CUR_DIR + '/../result/d_range_loads_number_Te{}_{}'.format(TEWHAT, mode), "r") as f:
        while(1):
            lines = f.readlines()

            if not lines:
                break
            j = 0
            for line in lines:
                numbers = line.split(' ')
                data.append(int(numbers[d_range]))
                j += 1
            break
    return data

def get_gaussian(sample_counts):
    mean = np.mean(sample_counts)
    std = np.std(sample_counts)
    gaussian_hist = [float(0)] * SAMPLE_N 
    for x in range(SAMPLE_N):
        pdf = norm.pdf(x, mean, std)
        gaussian_hist[x] = pdf
    return gaussian_hist
    
if __name__ == "__main__":
    with open(CUR_DIR + '/../templates/d-range-lowerbounds.json', 'r') as file:
        data = json.load(file)
    data['d_range_lowerbound_Te{}'.format(TEWHAT)] = d_range
    with open(CUR_DIR + '/../templates/d-range-lowerbounds.json', 'w') as file:
        data = json.dump(data, file)
    
    d_range_loads_number_hist_access_m = get_data("access_m")
    d_range_loads_number_hist_not_access_m = get_data("not_access_m")

    samples_counts_access_m = d_range_loads_number_hist_access_m
    samples_counts_not_access_m = d_range_loads_number_hist_not_access_m
    gaussian_hist_access_m = get_gaussian(samples_counts_access_m)
    with open(CUR_DIR + "/../templates/gaussian_hist_Te{}_access_m".format(TEWHAT), "w") as f:
        for hist in gaussian_hist_access_m:
            f.write("{}\n".format(hist))
    gaussian_hist_not_access_m = get_gaussian(samples_counts_not_access_m)
    with open(CUR_DIR + "/../templates/gaussian_hist_Te{}_not_access_m".format(TEWHAT), "w") as f:
        for hist in gaussian_hist_not_access_m:
            f.write("{}\n".format(hist))

