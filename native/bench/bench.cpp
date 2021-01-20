// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "bench.h"
#include <benchmark/benchmark.h>
#include <seal/seal.h>
#include <sstream>
using namespace benchmark;
using namespace seal;
using namespace std;

namespace sealbench
{
    shared_ptr<BenchSet> global_bench_set{ nullptr };

    const vector<size_t> degrees = { 1024, 2048, 4096, 8192, 16384 };

    void register_common()
    {
        for (auto &i : degrees)
        {
            EncryptionParameters parms(scheme_type::ckks);
            parms.set_poly_modulus_degree(i);
            parms.set_coeff_modulus(CoeffModulus::BFVDefault(i));
            benchmark::RegisterBenchmark(
                string("COMMON_KEYGEN_SECRET_").append(to_string(i)).c_str(), bm_keygen_secret, parms);
            if (i >= 4096)
            {
                benchmark::RegisterBenchmark(
                    string("COMMON_KEYGEN_RELIN_").append(to_string(i)).c_str(), bm_keygen_relin, parms);
            }
        }
    }

} // namespace sealbench

int main(int argc, char **argv)
{
    sealbench::global_bench_set = make_shared<sealbench::BenchSet>(seal::EncryptionParameters());
    sealbench::register_common();
    //    for (auto& test_input : { /* ... */ })
    //        benchmark::RegisterBenchmark(test_input.name(), BM_test, test_input);

    Initialize(&argc, argv);
    RunSpecifiedBenchmarks();
}
