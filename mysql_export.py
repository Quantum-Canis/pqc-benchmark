import mysql.connector
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv()

config = {
    'host': os.getenv("DB_HOST"),
    'port': int(os.getenv("DB_PORT")),
    'user': os.getenv("DB_USER"),
    'password': os.getenv("DB_PASS"),
    'database': os.getenv("DB_NAME")
}

def submit_raw_data(results, raw_timings, system_label="default"):
    algorithm = results["algorithm"]
    category = results["category"]
    timestamp = datetime.strptime(results["timestamp"], "%Y-%m-%d %H:%M:%S")
    correctness = results["correctness_rate"] == 1.0

    data_rows = []

    for operation, timings in raw_timings.items():
        for idx, duration in enumerate(timings, 1):
            data_rows.append((
                algorithm,
                category,
                operation,
                idx,
                duration,
                correctness,
                timestamp,
                system_label
            ))

    query = """
    INSERT INTO benchmark_results_raw (
        algorithm, category, operation,
        iteration, duration_ms, correctness,
        timestamp, system_label
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    with mysql.connector.connect(**config) as conn:
        with conn.cursor() as cursor:
            cursor.executemany(query, data_rows)
            conn.commit()

def submit_summary(results, system_label="default"):
    algorithm = results["algorithm"]
    category = results["category"]
    iterations = results["iterations"]
    timestamp = datetime.strptime(results["timestamp"], "%Y-%m-%d %H:%M:%S")
    key_size = results.get("key_size")
    signature_size = results.get("signature_size")

    operations = [key for key in results.keys() if key.endswith("_ms")]

    rows = []

    for op_key in operations:
        operation = op_key.replace("_ms", "")
        stats = results[op_key]

        rows.append((
            algorithm,
            category,
            operation,
            stats["mean"],
            stats["median"],
            stats["max"],
            stats["min"],
            stats["stddev"],
            stats["cv"],
            signature_size,
            key_size,
            iterations,
            timestamp,
            system_label
        )) 

    query = """
    INSERT INTO benchmark_summary (
        algorithm, category, operation,
        mean_ms, median_ms, max_ms, min_ms, stddev_ms, cv,
        signature_size, key_size, iterations, timestamp, system_label
    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    with mysql.connector.connect(**config) as conn:
        with conn.cursor() as cursor:
            cursor.executemany(query, rows)
            conn.commit()