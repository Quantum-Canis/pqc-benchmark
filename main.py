import warnings
warnings.filterwarnings("ignore", category=UserWarning)
import oqs
import os
import json
import validate
import kem_benchmark
import sig_benchmark
import mysql_export
import classic_kem
import classic_sig
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, ed25519
from cryptography.hazmat.primitives import hashes
import csv
from pathlib import Path


def export_csv(results, raw_timings, label="default"):
    timestamp = results["timestamp"].replace(":", "-").replace(" ", "_")
    base_dir = Path("exports") / label
    base_dir.mkdir(parents=True, exist_ok=True)

    # Summary CSV
    summary_file = base_dir / f"{results['algorithm']}_{timestamp}_summary.csv"
    with open(summary_file, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["operation", "mean", "median", "max", "min", "stddev", "cv"])
        for k, v in results.items():
            if k.endswith("_ms"):
                op = k.replace("_ms", "")
                writer.writerow([
                    op,
                    v["mean"], v["median"], v["max"],
                    v["min"], v["stddev"], v["cv"]
                ])

    # Raw timings CSV
    raw_file = base_dir / f"{results['algorithm']}_{timestamp}_raw.csv"
    with open(raw_file, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["operation", "iteration", "duration_ms"])
        for operation, timings in raw_timings.items():
            for idx, duration in enumerate(timings, 1):
                writer.writerow([operation, idx, duration])

def _safe_verify(verify_func, *args, **kwargs):
    try:
        verify_func(*args, **kwargs)
        return True
    except Exception:
        return False

def main():
    system_label = os.getenv("SYSTEM_LABEL", "default")
    # Import algorithms from json file
    with open("algorithms.json", "r") as file:
        standards = json.load(file)

    # Validate the algorithms against the OQS library
    kems_mlkem, kems_hqc, sigs_mldsa, sigs_slhdsa = validate.algorithms(oqs, standards)

    
    print(f"\nBenchmarking Classic KEM: RSA-OAEP (2048-bit)")
    results, raw_timings = classic_kem.benchmark_rsa_oaep()
    print(json.dumps(results, indent=4))
    mysql_export.submit_summary(results, system_label)
    mysql_export.submit_raw_data(results, raw_timings, system_label)
    export_csv(results, raw_timings, system_label)

    print(f"\nBenchmarking Classic Signature: RSA-2048")
    results, raw_timings = classic_sig.benchmark(
        category="legacy_sig",
        algorithm="RSA-2048",
        keygen=lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
        sign=lambda priv, msg: priv.sign(
            msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        ),
        verify=lambda pub, msg, sig: _safe_verify(pub.verify, sig, msg,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    )
    print(json.dumps(results, indent=4))
    mysql_export.submit_summary(results, system_label)
    mysql_export.submit_raw_data(results, raw_timings, system_label)
    export_csv(results, raw_timings, system_label)

    print(f"\nBenchmarking Classic Signature: ECDSA-P256")
    results, raw_timings = classic_sig.benchmark(
        category="legacy_sig",
        algorithm="ECDSA-P256",
        keygen=lambda: ec.generate_private_key(ec.SECP256R1()),
        sign=lambda priv, msg: priv.sign(msg, ec.ECDSA(hashes.SHA256())),
        verify=lambda pub, msg, sig: _safe_verify(pub.verify, sig, msg, ec.ECDSA(hashes.SHA256()))
    )
    print(json.dumps(results, indent=4))
    mysql_export.submit_summary(results, system_label)
    mysql_export.submit_raw_data(results, raw_timings, system_label)
    export_csv(results, raw_timings, system_label)

    print(f"\nBenchmarking Classic Signature: Ed25519")
    results, raw_timings = classic_sig.benchmark(
        category="legacy_sig",
        algorithm="Ed25519",
        keygen=lambda: ed25519.Ed25519PrivateKey.generate(),
        sign=lambda priv, msg: priv.sign(msg),
        verify=lambda pub, msg, sig: _safe_verify(pub.verify, sig, msg)
    )
    print(json.dumps(results, indent=4))
    mysql_export.submit_summary(results, system_label)
    mysql_export.submit_raw_data(results, raw_timings, system_label)
    export_csv(results, raw_timings, system_label)


    for kem in kems_mlkem:
        print(f"\nBenchmarking KEM: {kem}")
        results, raw_timings = kem_benchmark.benchmark("ML-KEM", kem)
        print(json.dumps(results, indent=4))
        mysql_export.submit_summary(results, system_label)
        mysql_export.submit_raw_data(results, raw_timings, system_label)
        export_csv(results, raw_timings, system_label)

    for kem in kems_hqc:
        print(f"\nBenchmarking KEM: {kem}")
        results, raw_timings = kem_benchmark.benchmark("HQC", kem)
        print(json.dumps(results, indent=4))
        mysql_export.submit_summary(results, system_label)
        mysql_export.submit_raw_data(results, raw_timings, system_label)
        export_csv(results, raw_timings, system_label)

    for sig in sigs_mldsa:
        print(f"\nBenchmarking Signature Algorithm: {sig}")
        results, raw_timings = sig_benchmark.benchmark("ML-DSA", sig)
        print(json.dumps(results, indent=4))
        mysql_export.submit_summary(results, system_label)
        mysql_export.submit_raw_data(results, raw_timings, system_label)
        export_csv(results, raw_timings, system_label)

    for sig in sigs_slhdsa:
        print(f"\nBenchmarking Signature Algorithm: {sig}")
        results, raw_timings = sig_benchmark.benchmark("SLH-DSA", sig)
        print(json.dumps(results, indent=4))
        mysql_export.submit_summary(results, system_label)
        mysql_export.submit_raw_data(results, raw_timings, system_label)
        export_csv(results, raw_timings, system_label)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"An error occurred: {e}")