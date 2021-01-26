// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "bench.h"
#include <benchmark/benchmark.h>
#include <seal/seal.h>
using namespace benchmark;
using namespace seal;
using namespace std;

/**
This file defines benchmarks for common HE primitives shared by BFV and CKKS.
*/

namespace seal
{
    struct KeyGenerator::KeyGeneratorPrivateHelper
    {
        static void generate_sk(KeyGenerator *keygen)
        {
            return keygen->generate_sk();
        }
    };
} // namespace seal

namespace sealbench
{
    void bm_keygen_secret(State &state, const EncryptionParameters &parms)
    {
        global_bench_set->initialize(parms);
        KeyGenerator keygen(global_bench_set->context());
        for (auto _ : state)
        {
            seal::KeyGenerator::KeyGeneratorPrivateHelper::generate_sk(&keygen);
        }
    }

    void bm_keygen_public(State &state, const EncryptionParameters &parms)
    {
        global_bench_set->initialize(parms);
        PublicKey pk;
        for (auto _ : state)
        {
            global_bench_set->keygen()->create_public_key(pk);
        }
    }

    void bm_keygen_relin(State &state, const EncryptionParameters &parms)
    {
        global_bench_set->initialize(parms);
        if (!global_bench_set->context().using_keyswitching())
        {
            state.SkipWithError("Relinearization is disabled for this parameter set.");
        }
        RelinKeys rlk;
        for (auto _ : state)
        {
            global_bench_set->keygen()->create_relin_keys(rlk);
        }
    }

    void bm_keygen_galois(State &state, const EncryptionParameters &parms)
    {
        global_bench_set->initialize(parms);
        if (!global_bench_set->context().using_keyswitching())
        {
            state.SkipWithError("Galois automorphism is disabled for this parameter set.");
        }
        GaloisKeys glk;
        for (auto _ : state)
        {
            global_bench_set->keygen()->create_galois_keys(glk);
        }
    }

} // namespace sealbench