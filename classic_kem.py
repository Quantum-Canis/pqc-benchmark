import time
import os
import statistics as stats
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


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

def warmup():
    for _ in range(5):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        secret = os.urandom(32)
        ciphertext = public_key.encrypt(
            secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        recovered = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        assert recovered == secret

def benchmark_rsa_oaep(iterations=100):
    generation_times = []
    encapsulate_times = []
    decapsulate_times = []
    failures = 0

    warmup()

    for _ in range(iterations):
        # Generate new keypair
        start_time = time.perf_counter_ns()
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        generation_times.append((time.perf_counter_ns() - start_time) / 1_000_000)

        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_size = len(public_key_bytes)

        secret = os.urandom(32)

        # Encapsulation (encrypt)
        start_time = time.perf_counter_ns()
        ciphertext = public_key.encrypt(
            secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encapsulate_times.append((time.perf_counter_ns() - start_time) / 1_000_000)

        # Decapsulation (decrypt)
        start_time = time.perf_counter_ns()
        secret_dec = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decapsulate_times.append((time.perf_counter_ns() - start_time) / 1_000_000)
        if secret_dec != secret:
            failures += 1

    algorithm = "RSA-OAEP_2048-bit"
    category = "legacy_kem"

    benchmark_results = {
        "algorithm": algorithm,
        "category": category,
        "iterations": iterations,
        "key_size": key_size,
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