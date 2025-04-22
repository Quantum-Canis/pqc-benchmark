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

def warmup(message, sig):
    for _ in range(5):
        public_key = sig.generate_keypair()
        signature = sig.sign(message)
        verification = sig.verify(message, signature, public_key)
        assert verification


def benchmark(category, algorithm, iterations=100, message_length=1024):
    generation_times = []
    sign_times = []
    verify_times = []
    failures = 0
    message = b'\xFF' * message_length

    with oqs.Signature(algorithm) as sig:
        warmup(message, sig)

        for _ in range(iterations):
            start_time = time.perf_counter_ns()
            public_key = sig.generate_keypair()
            elapsed_ns = time.perf_counter_ns() - start_time
            elapsed_ms = elapsed_ns / 1_000_000  # Convert to milliseconds
            generation_times.append(elapsed_ms)

            start_time = time.perf_counter_ns()
            signature = sig.sign(message)
            elapsed_ns = time.perf_counter_ns() - start_time
            elapsed_ms = elapsed_ns / 1_000_000  # Convert to milliseconds
            sign_times.append(elapsed_ms)

            start_time = time.perf_counter_ns()
            verification = sig.verify(message, signature, public_key)
            elapsed_ns = time.perf_counter_ns() - start_time
            elapsed_ms = elapsed_ns / 1_000_000  # Convert to milliseconds
            verify_times.append(elapsed_ms)

            if not verification:
                failures += 1
    
    benchmark_results = {
        "algorithm": algorithm,
        "category": category,
        "iterations": iterations,
        "key_size": len(public_key),
        "signature_size": len(signature),
        "keygen_ms": compute_stats(generation_times),
        "sign_ms": compute_stats(sign_times),
        "verify_ms": compute_stats(verify_times),
        "correctness_rate": round((iterations - failures) / iterations, 6),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    }

    raw_timings = {
        "keygen": generation_times,
        "sign": sign_times,
        "verify": verify_times
    }

    return benchmark_results, raw_timings
