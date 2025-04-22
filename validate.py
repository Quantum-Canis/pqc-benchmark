def algorithms(oqs, algorithms):
    enabled_kems = oqs.get_enabled_kem_mechanisms()
    enabled_sigs = oqs.get_enabled_sig_mechanisms()

    kems_mlkem = []
    kems_hqc = []
    sigs_mldsa = []
    sigs_slhdss = []

    print(f"{'Key Encapsulation Mechanisms (KEMs)':-^80}")
    for category, kems in algorithms["kems"].items():
        for kem in kems:
            status = "enabled" if kem in enabled_kems else "disabled"
            print(f"{kem:>30}: {status}")
            if status == "enabled":
                if category == "ml-kem":
                    kems_mlkem.append(kem)
                elif category == "hqc":
                    kems_hqc.append(kem)

    print()
    print(f"{'Signature Algorithms':-^80}")
    for category, sigs in algorithms["signatures"].items():
        for sig in sigs:
            status = "enabled" if sig in enabled_sigs else "disabled"
            print(f"{sig:>30}: {status}")
            if status == "enabled":
                if category == "ml-dsa":
                    sigs_mldsa.append(sig)
                elif category == "slh-dsa":
                    sigs_slhdss.append(sig)

    return kems_mlkem, kems_hqc, sigs_mldsa, sigs_slhdss
    