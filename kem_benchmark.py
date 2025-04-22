import oqs
import time
import statistics as stats


def compute_stats(data):
    mean = stats.mean(data)
    stddev = stats.stdev(data)
    return {
        "mean": round(mean, 6),
        "median": round(stats.median(data), 6),
        "max": round(max(data), 6),
        "min": round(min(data), 6),
        "stddev": round(stddev, 6),
        "cv": round(stddev / mean, 6)
    }

def warmup(kem):
    for _ in range(5):
        public_key = kem.generate_keypair()
        ciphertext, shared_secret_enc = kem.encap_secret(public_key)
        shared_secret_dec = kem.decap_secret(ciphertext)
        assert shared_secret_enc == shared_secret_dec


def benchmark(category, algorithm, iterations=100):
    generation_times = []
    encapsulate_times = []
    decapsulate_times = []
    failures = 0

    with oqs.KeyEncapsulation(algorithm) as kem:
        warmup(kem)

        for _ in range(iterations):
            start_time = time.perf_counter_ns()
            public_key = kem.generate_keypair()
            elapsed_ns = time.perf_counter_ns() - start_time
            elapsed_ms = elapsed_ns / 1_000_000  # Convert to milliseconds
            generation_times.append(elapsed_ms)

            start_time = time.perf_counter_ns()
            ciphertext, shared_secret_enc = kem.encap_secret(public_key)
            elapsed_ns = time.perf_counter_ns() - start_time
            elapsed_ms = elapsed_ns / 1_000_000  # Convert to milliseconds
            encapsulate_times.append(elapsed_ms)

            start_time = time.perf_counter_ns()
            shared_secret_dec = kem.decap_secret(ciphertext)
            elapsed_ns = time.perf_counter_ns() - start_time
            elapsed_ms = elapsed_ns / 1_000_000  # Convert to milliseconds
            decapsulate_times.append(elapsed_ms)

            if shared_secret_enc != shared_secret_dec:
                failures += 1
    
    benchmark_results = {
        "algorithm": algorithm,
        "category": category,
        "iterations": iterations,
        "key_size": len(public_key),
        "keygen_ms": compute_stats(generation_times),
        "encap_ms": compute_stats(encapsulate_times),
        "decap_ms": compute_stats(decapsulate_times),
        "correctness_rate": round((iterations - failures) / iterations, 6),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    }
    
    raw_timings = {
        "keygen": generation_times,
        "encap": encapsulate_times,
        "decap": decapsulate_times
    }

    return benchmark_results, raw_timings
