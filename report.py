import os
import pandas as pd

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt

# Создаем директорию, если ее нет.
def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)
    
# График числа запросов в минуту.
def plot_requests_over_time(df: pd.DataFrame, out_path: str):
    s = df.set_index("ts").resample("1min").size()
    plt.figure()
    s.plot()
    plt.title("Requests per minute")
    plt.xlabel("Time")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()
    
# Горизонтальный bar chart с топ-IP.
def plot_top_ips(df: pd.DataFrame, out_path: str, n=10):
    s = df["ip"].value_counts().head(n)
    plt.figure()
    s.sort_values().plot(kind="barh")
    plt.title(f"Top {n} IPs by request count")
    plt.xlabel("Count")
    plt.ylabel("IP")
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()

# Экспорт инцидентов в CSV.
def incidents_to_csv(incidents: list[dict], out_path: str):
    pd.DataFrame(incidents).to_csv(out_path, index=False, encoding="utf-8")
