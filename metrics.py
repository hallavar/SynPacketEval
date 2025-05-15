#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Wed Apr 30 17:12:26 2025

@author: hallavar
"""

import pandas as pd
import numpy as np
from prdc import compute_prdc
from scipy import stats
from scipy.spatial import distance
from sklearn.preprocessing import MinMaxScaler

pd.set_option('future.no_silent_downcasting', True)

def compute_WD(real, generated):#EMD in paper
    score = 0
    for i in real.columns:
        #compute the empirical cdfs
        cdf1,bins1 = np.histogram(real[i].to_numpy(), bins='fd')
        ecdf1 = np.cumsum(cdf1)/len(real)
        ecdf2 = np.cumsum(np.histogram(generated[i].to_numpy(), bins=bins1)[0])/len(generated)
        score += stats.wasserstein_distance(ecdf1, ecdf2)
    return score/len(real.columns)

def compute_JSD(df1, df2):
    #get set of all variables
    variables = set(df1.columns).union(set(df2.columns))

    #initialize empty list to store jsd values for each variable
    jsd_values = []

    #loop through variables
    for var in variables:
        #get the set of values for the variable from both dataframes
        values1 = set(df1[var].unique())
        values2 = set(df2[var].unique())

        #create a union of the sets of values for the variable
        all_values = values1.union(values2)

        #fill missing values with 0
        data1 = df1[var].value_counts().reindex(all_values, fill_value=0)
        data2 = df2[var].value_counts().reindex(all_values, fill_value=0)
        #compute jsd for the variable and append to list
        jsd = distance.jensenshannon(data1, data2)
        jsd_values.append(jsd)

    return np.mean(jsd_values)

def compute_PCD(real, generated):

    temp = real.to_numpy()
    g = generated.to_numpy()
    scaler = MinMaxScaler().fit(np.concatenate((temp, g)))#min-max normalization

    temp = scaler.transform(temp)
    g = scaler.transform(g)
    pcd_r = np.corrcoef(temp.T)
    pcd_g = np.corrcoef(g.T)
    pcd_r[np.isnan(pcd_r)] = 0#replace nan by 0
    pcd_g[np.isnan(pcd_g)] = 0
    return np.linalg.norm(pcd_r - pcd_g)

def compute_CMD(real, generated):
    #get all pairs of columns possible
    all_pairs = [(real.columns[i], real.columns[j]) for i in range(real.shape[1]) for j in range(i + 1, real.shape[1])]
    s=0
    for i in all_pairs:
        contingency_table_r = pd.crosstab(real[i[0]], real[i[1]], dropna=False, normalize=True)
        contingency_table_g = pd.crosstab(generated[i[0]], generated[i[1]], dropna=False, normalize=True)

        #list of all unique values in both variables
        all_categories_0 = sorted(set(real[i[0]].unique()).union(generated[i[0]].unique()))
        all_categories_1 = sorted(set(real[i[1]].unique()).union(generated[i[1]].unique()))

        #extend the contingencie tables with all the possible values
        contingency_table_r_extended = pd.DataFrame(index=all_categories_0, columns=all_categories_1)
        contingency_table_r_extended.update(contingency_table_r)
        contingency_table_g_extended = pd.DataFrame(index=all_categories_0, columns=all_categories_1)
        contingency_table_g_extended.update(contingency_table_g)
        #fill missing values with 0
        contingency_table_g_extended = contingency_table_g_extended.astype(float).fillna(0)
        contingency_table_r_extended = contingency_table_r_extended.astype(float).fillna(0)
        
        s+= np.linalg.norm(contingency_table_r_extended - contingency_table_g_extended)
    return s/len(all_pairs)

def transform_discretize(df, i=30):
    #this function discretize feature that does not have sufficent distinct value to be considere continuosu
    for c in df.columns:
        if df[c].nunique()>i and 'ADDR' not in c and 'PORT' not in c:
            df[c] = pd.qcut(df[c],i,duplicates='drop')
    return df

def transform_OHE(df, i=30):
    #this function get the one hot encoding of all the columns
    for col in df.columns:
        if df[col].nunique()<i or 'ADDR' in col or 'PORT' in col:
            df = pd.concat([df,pd.get_dummies(df[col],prefix=col+'_is', prefix_sep='_')],axis=1)
            df=df.drop(col,axis=1)
    return df

def compute_authenticity(train, test, generated, i= 50, n = 500):#MD in the paper
    temp = transform_discretize(pd.concat([train, test, generated]), i)#Turn every feature discrete

    u= []

    for c in temp.columns:
        u.extend(list(temp[c].unique()))#get the list and index of al unique value
    u = list(set(u))
    
    tr = train.replace(dict(zip(u, list(range(len(u)))))).infer_objects(copy=False)
    ts = test.replace(dict(zip(u, list(range(len(u)))))).infer_objects(copy=False)
    g  = generated.replace(dict(zip(u, list(range(len(u)))))).infer_objects(copy=False)
 
    n = min(n, len(ts), len(tr), len(g))
    
    #g is a dataset of integer
    ts = ts.sample(n).to_numpy() ##test set
    tr = tr.sample(n).to_numpy() ##train set
    g = g.sample(n).to_numpy() ##generated set

    M = np.ones((len(ts)+len(tr), len(g)))
    for i, row in enumerate(np.concatenate([ts, tr])):
        for j, col in enumerate(g):
            M[i, j] = distance.hamming(row, col)#calculate hamming distance beetwen all the generated samples an all the real (train+test) samples.
    score = 0
    for r in np.linspace(0,1,15):#for every r
        u = M <= r#True the hamming distance between a real sample and a generated sample is lower than R
        result = (np.count_nonzero(u, axis=1) > 0)#See the real sample that has a hamming distance to a generated sample inferior to r
        label = np.concatenate([np.zeros(len(ts)), np.ones(len(tr))]).astype(bool)#We know wich label are training and wich is not
        if result.sum() == 0:
            continue

        pr = np.logical_and(result, label).sum()/label.sum()
        rr = np.logical_and(result, label).sum()/result.sum()
        f1 = 0 if (pr + rr) == 0 else 2 * pr * rr / (pr + rr)
        
        score += f1#Score is the summation of the f1 for all the r
    return score

def compute_density_coverage(real, g, i=30, n=5):
    temp = transform_OHE(pd.concat([real, g]), i)

    temp = temp.astype(float)

    r = temp.head(len(real)).to_numpy()
    generated = temp.tail(len(g)).to_numpy()

    scaler = MinMaxScaler().fit(np.concatenate((r, generated)))

    r = scaler.transform(r)
    generated = scaler.transform(generated)
    scores = list(compute_prdc(r, generated, n).values())
    return tuple(scores[-2:])

def compute_DKC(u):
    score = 0
    generated = u.astype(str)
    score+=len(generated[((generated["L4_DST_PORT"].isin(['53', '137', '138', '5353', '1900', '67', '0', '3544', '8612', '3702', '123'])) & (generated["PROTOCOL"].str.contains("6")))])/len(generated)
    score+=len(generated[((generated["L4_DST_PORT"].isin(['80', '8000', '25', '993', '587', '445', '0', '84', '8088', '8080'])) & (generated["PROTOCOL"].str.contains("17")))])/len(generated)
    score+=len(generated[((generated["L4_DST_PORT"].isin(["137.0", "138.0", "1900.0"])) & (generated["IN_BYTES"]!="0"))])/len(generated)
    score+=len(generated[((generated["L4_DST_PORT"].isin(["137.0", "138.0", "1900.0"])) & (generated["IN_PKTS"]!="0"))])/len(generated)
    score+=len(generated[(generated["TCP_FLAGS"]!="0") & (generated["PROTOCOL"]!="6")])/len(generated)
    score+=len(generated[generated["IN_PKTS"].astype(float)*42 > generated["IN_BYTES"].astype(float)])/len(generated)
    score+=len(generated[generated["OUT_PKTS"].astype(float)*42 > generated["OUT_BYTES"].astype(float)])/len(generated)
    score+=len(generated[generated["IN_BYTES"].astype(float) > 65535*generated["IN_PKTS"].astype(float)])/len(generated)
    score+=len(generated[generated["OUT_BYTES"].astype(float) > 65535*generated["OUT_PKTS"].astype(float)])/len(generated)
    score+=len(generated[generated["FLOW_DURATION_MILLISECONDS"].str.contains("-")])/len(generated)
    score+=len(generated[((generated["FLOW_DURATION_MILLISECONDS"].astype(float)>00) & (generated["IN_PKTS"].astype(float)+generated["OUT_PKTS"].astype(float)==1))])/len(generated)
    return score/20


if __name__ == '__main__':
    import sys

    if len(sys.argv) != 4:
        print("Usage: python3 metrics.py syn.csv num_runs sample_size")
        sys.exit(1)

    syn_filename = sys.argv[1]
    num_runs = int(sys.argv[2])
    sample_size = int(sys.argv[3])
    base_path = "output_csvs/"

    print("Loading dataframes")
    train_full = pd.read_csv(base_path + "train.csv")
    test_full = pd.read_csv(base_path + "test.csv")
    syn_full = pd.read_csv(base_path + syn_filename)
    
    sample_size = min(sample_size, len(train_full), len(test_full), len(syn_full))

    continuous = ['FLOW_START_TIMESTAMP', 'IN_BYTES', 'OUT_BYTES', 'IN_PKTS', 'OUT_PKTS',
                  'FLOW_DURATION_MILLISECONDS', 'DURATION_IN', 'DURATION_OUT', 'MIN_TTL','MAX_TTL',
                  'LONGEST_FLOW_PKT', 'SHORTEST_FLOW_PKT','MIN_IP_PKT_LEN','MAX_IP_PKT_LEN',
                  'SRC_TO_DST_SECOND_BYTES', 'DST_TO_SRC_SECOND_BYTES', 'RETRANSMITTED_IN_BYTES',
                  'RETRANSMITTED_IN_PKTS', 'RETRANSMITTED_OUT_BYTES', 'RETRANSMITTED_OUT_PKTS',
                  'SRC_TO_DST_AVG_THROUGHPUT', 'DST_TO_SRC_AVG_THROUGHPUT','TCP_FLAGS',
                  'CLIENT_TCP_FLAGS', 'SERVER_TCP_FLAGS', 'DNS_QUERY_ID', 'DNS_TTL_ANSWER',
                  'NUM_PKTS_UP_TO_128_BYTES', 'NUM_PKTS_128_TO_256_BYTES',
                  'NUM_PKTS_256_TO_512_BYTES', 'NUM_PKTS_512_TO_1024_BYTES',
                  'NUM_PKTS_1024_TO_1514_BYTES', 'TCP_WIN_MAX_IN', 'TCP_WIN_MAX_OUT']
    
    discrete = ['IPV4_SRC_ADDR', 'IPV4_DST_ADDR', 'L4_SRC_PORT', 'L4_DST_PORT', 'PROTOCOL',
                'L7_PROTO', 'ICMP_TYPE', 'ICMP_IPV4_TYPE', 'DNS_QUERY_TYPE', 'FTP_COMMAND_RET_CODE']

    remove = []
    for df in [train_full, test_full, syn_full]:
        df[discrete] = df[discrete].fillna(0).astype(str)
        remove.extend(df.columns[df.isnull().any()])

    remove = np.unique(remove)
    continuous = [f for f in continuous if f not in remove]
    discrete = [f for f in discrete if f not in remove]

    for df in [train_full, test_full, syn_full]:
        df.drop(columns=remove, inplace=True)

    import random
    from statistics import mean, stdev

    def evaluate_metric(metric_func, *args):
        results = []
        for seed in range(num_runs):
            np.random.seed(seed)
            random.seed(seed)
            sampled = [df.sample(sample_size, random_state=seed) for df in args]
            results.append(metric_func(*sampled))
        return round(mean(results), 6), round(stdev(results), 6)

    def eval_density_coverage(real, syn):
        precs, covs = [], []
        for seed in range(num_runs):
            np.random.seed(seed)
            sampled_real = real.sample(sample_size, random_state=seed)
            sampled_syn = syn.sample(sample_size, random_state=seed)
            prec, cov = compute_density_coverage(sampled_real, sampled_syn)
            precs.append(prec)
            covs.append(cov)
        return (round(mean(precs), 6), round(stdev(precs), 6)), (round(mean(covs), 6), round(stdev(covs), 6))

    def eval_dkc(syn):
        results = []
        for seed in range(num_runs):
            np.random.seed(seed)
            sampled_syn = syn.sample(sample_size, random_state=seed)
            results.append(compute_DKC(sampled_syn))
        return round(mean(results), 6), round(stdev(results), 6)

    def eval_auth(train, test, syn):
        results = []
        for seed in range(num_runs):
            np.random.seed(seed)
            random.seed(seed)
            sampled_train = train.sample(sample_size, random_state=seed)
            sampled_test = test.sample(sample_size, random_state=seed)
            sampled_syn = syn.sample(sample_size, random_state=seed)
    
            try:
                score = compute_authenticity(sampled_train, sampled_test, sampled_syn)
                score = float(score)  # cast to native Python float
                if not np.isnan(score):
                    results.append(score)
            except Exception as e:
                print(f"[eval_auth] Warning: skipping run with seed={seed} due to error: {e}")
    
        if len(results) < 2:
            print("[eval_auth] Warning: insufficient data to compute stdev.")
            return float('nan'), float('nan')
    
        return round(mean(results), 6), round(stdev(results), 6)

    print("\n=== Metric Evaluations over", num_runs, "runs with", sample_size, "samples each ===\n")

    metrics = [
        ("WD (syn vs train)", compute_WD, train_full[continuous], syn_full[continuous]),
        ("WD (syn vs test)", compute_WD, test_full[continuous], syn_full[continuous]),
        ("WD (train vs test)", compute_WD, train_full[continuous], test_full[continuous]),

        ("JSD (syn vs train)", compute_JSD, train_full[discrete], syn_full[discrete]),
        ("JSD (syn vs test)", compute_JSD, test_full[discrete], syn_full[discrete]),
        ("JSD (train vs test)", compute_JSD, train_full[discrete], test_full[discrete]),

        ("PCD (syn vs train)", compute_PCD, train_full[continuous], syn_full[continuous]),
        ("PCD (syn vs test)", compute_PCD, test_full[continuous], syn_full[continuous]),
        ("PCD (train vs test)", compute_PCD, train_full[continuous], test_full[continuous]),

        ("CMD (syn vs train)", compute_CMD, train_full[discrete], syn_full[discrete]),
        ("CMD (syn vs test)", compute_CMD, test_full[discrete], syn_full[discrete]),
        ("CMD (train vs test)", compute_CMD, train_full[discrete], test_full[discrete]),
    ]

    for name, func, *args in metrics:
        avg, std = evaluate_metric(func, *args)
        print(f"{name}: avg = {avg}, std = {std}")

    print("\nDKC (synthetic only):")
    avg, std = eval_dkc(syn_full)
    print(f"DKC: avg = {avg}, std = {std}")

    print("\nPRDC (Precision & Coverage):")
    (p_avg, p_std), (c_avg, c_std) = eval_density_coverage(train_full, syn_full)
    print(f"Precision: avg = {p_avg}, std = {p_std}")
    print(f"Coverage : avg = {c_avg}, std = {c_std}")

    print("\nAuthenticity (F1 Curve Agreement):")
    avg, std = eval_auth(train_full, test_full, syn_full)
    print(f"Authenticity: avg = {avg}, std = {std}")
    