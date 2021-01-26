// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "bench.h"
#include <benchmark/benchmark.h>
#include <seal/seal.h>
#include <seal/util/rlwe.h>
using namespace benchmark;
using namespace sealbench;
using namespace seal;
using namespace std;

/**
This file defines benchmarks for BFV-specific HE primitives.
*/

namespace sealbench
{
    void bm_bfv_mul_ct(State &state, shared_ptr<BenchEnv> bench_env)
    {
        auto &parms = bench_env->parms();
        auto prng = bench_env->prng();
        vector<Ciphertext> &ct = bench_env->ct();
        for (auto _ : state)
        {
            state.PauseTiming();
            util::sample_poly_uniform(prng, parms, ct[0].data(0));
            util::sample_poly_uniform(prng, parms, ct[0].data(1));
            util::sample_poly_uniform(prng, parms, ct[1].data(0));
            util::sample_poly_uniform(prng, parms, ct[1].data(1));
            state.ResumeTiming();
            Ciphertext res;
            bench_env->evaluator()->multiply(ct[0], ct[1], res);
        }
    }
} // namespace sealbench