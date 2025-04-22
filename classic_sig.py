import time
import statistics as stats
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, ed25519

def compute_stats(data):
    mean = stats.mean(data)
    stddev = stats.stdev(data)
    return {
        "mean": round(mean, 6),
        "median": round(stats.median(data), 6),
        "max": round(max(data), 6),
        "min": round(min(data), 6),
        "stddev": round(stddev, 6),
        "cv": round(stddev / mean, 6) if mean != 0 else 0.0
    }

def warmup(message, keygen, sign, verify):
    for _ in range(5):
        private_key = keygen()
        public_key = private_key.public_key()
        signature = sign(private_key, message)
        assert verify(public_key, message, signature)

def benchmark(category, algorithm, keygen, sign, verify, iterations=100, message_length=1024):
    generation_times = []
    sign_times = []
    verify_times = []
    failures = 0
    message = b'\xFF' * message_length

    warmup(message, keygen, sign, verify)

    for _ in range(iterations):
        start = time.perf_counter_ns()
        private_key = keygen()
        public_key = private_key.public_key()
        generation_times.append((time.perf_counter_ns() - start) / 1_000_000)

        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_size = len(public_key_bytes)

        start = time.perf_counter_ns()
        signature = sign(private_key, message)
        sign_times.append((time.perf_counter_ns() - start) / 1_000_000)

        start = time.perf_counter_ns()
        try:
            valid = verify(public_key, message, signature)
        except Exception:
            valid = False
        verify_times.append((time.perf_counter_ns() - start) / 1_000_000)

        if not valid:
            failures += 1

    benchmark_results = {
        "algorithm": algorithm,
        "category": category,
        "iterations": iterations,
        "key_size": key_size,
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
