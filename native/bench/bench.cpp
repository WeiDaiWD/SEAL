// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "bench.h"
#include <benchmark/benchmark.h>
#include <seal/seal.h>
//#include <utility>
using namespace benchmark;
using namespace seal;
using namespace std;

namespace sealbench
{
    static vector<pair<size_t, vector<Modulus>>> global_parms;

    unordered_map<EncryptionParameters, shared_ptr<BenchEnv>> global_bench_env;

    /**
    Wraps benchmark::RegisterBenchmark to use microsecond and accepts std::string name.
    */
    template <class Lambda, class... Args>
    internal::Benchmark *register_bm(string name, Lambda &&fn, Args &&... args)
    {
        return RegisterBenchmark(name.c_str(), [=](State &st) { fn(st, args...); })->Unit(benchmark::kMicrosecond);
    }

#define SEAL_BENCHMARK_REGISTER(category, n, log_q, name, func, ...)                                                \
    register_bm(                                                                                                    \
        string("n=") + to_string(n) + string(" / log_q=") + to_string(log_q) + string(#category " / " #name), func, \
        __VA_ARGS__)

    void register_bm_family(const pair<size_t, vector<Modulus>> &parms)
    {
        // For BFV benchmark cases (default to 20-bit plain_modulus)
        EncryptionParameters parms_bfv(scheme_type::bfv);
        parms_bfv.set_poly_modulus_degree(parms.first);
        parms_bfv.set_coeff_modulus(parms.second);
        parms_bfv.set_plain_modulus(PlainModulus::Batching(parms.first, 20));
        shared_ptr<BenchEnv> bench_env_bfv = global_bench_env.find(parms_bfv)->second;

        // For CKKS / KeyGen / Util benchmark cases
        EncryptionParameters parms_ckks(scheme_type::ckks);
        parms_ckks.set_poly_modulus_degree(parms.first);
        parms_ckks.set_coeff_modulus(parms.second);
        shared_ptr<BenchEnv> bench_env_ckks = global_bench_env.find(parms_ckks)->second;

        // Registration / display order:
        // 1. KeyGen
        // 2. BFV
        // 3. CKKS
        // 4. Util
        int n = static_cast<int>(parms.first);
        int log_q = static_cast<int>(
            global_bench_env.find(parms_ckks)->second->context().key_context_data()->total_coeff_modulus_bit_count());
//        SEAL_BENCHMARK_REGISTER(KeyGen, n, log_q, Secret,             bm_keygen_secret,       bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(KeyGen, n, log_q, Public,             bm_keygen_public,       bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(KeyGen, n, log_q, Relin,              bm_keygen_relin,        bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(KeyGen, n, log_q, Galois,             bm_keygen_galois,       bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(BFV,    n, log_q, EncryptSecret,      bm_bfv_encrypt_secret,  bench_env_bfv );
//        SEAL_BENCHMARK_REGISTER(BFV,    n, log_q, EncryptPublic,      bm_bfv_encrypt_public,  bench_env_bfv );
//        SEAL_BENCHMARK_REGISTER(BFV,    n, log_q, Decrypt,            bm_bfv_decrypt,         bench_env_bfv );
//        SEAL_BENCHMARK_REGISTER(BFV,    n, log_q, EncodeBatch,        bm_bfv_encode_batch,    bench_env_bfv );
//        SEAL_BENCHMARK_REGISTER(BFV,    n, log_q, DecodeBatch,        bm_bfv_decode_batch,    bench_env_bfv );
//        SEAL_BENCHMARK_REGISTER(BFV,    n, log_q, EvaluateAddCt,      bm_bfv_add_ct,          bench_env_bfv );
//        SEAL_BENCHMARK_REGISTER(BFV,    n, log_q, EvaluateAddPt,      bm_bfv_add_pt,          bench_env_bfv );
        SEAL_BENCHMARK_REGISTER(BFV,    n, log_q, EvaluateMulCt,      bm_bfv_mul_ct,          bench_env_bfv );
//        SEAL_BENCHMARK_REGISTER(BFV,    n, log_q, EvaluateMulPt,      bm_bfv_mul_pt,          bench_env_bfv );
//        SEAL_BENCHMARK_REGISTER(BFV,    n, log_q, EvaluateSquare,     bm_bfv_square,          bench_env_bfv );
//        SEAL_BENCHMARK_REGISTER(BFV,    n, log_q, EvaluateRelin,      bm_bfv_relin,           bench_env_bfv );
//        SEAL_BENCHMARK_REGISTER(BFV,    n, log_q, EvaluateModSwitch,  bm_bfv_mod_switch,      bench_env_bfv );
//        SEAL_BENCHMARK_REGISTER(BFV,    n, log_q, EvaluateRotateRows, bm_bfv_rotate_rows,     bench_env_bfv );
//        SEAL_BENCHMARK_REGISTER(BFV,    n, log_q, EvaluateRotateCols, bm_bfv_rotate_cols,     bench_env_bfv );
//        SEAL_BENCHMARK_REGISTER(CKKS,   n, log_q, EncryptSecret,      bm_ckks_encrypt_secret, bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(CKKS,   n, log_q, EncryptPublic,      bm_ckks_encrypt_public, bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(CKKS,   n, log_q, Decrypt,            bm_ckks_decrypt,        bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(CKKS,   n, log_q, EncodeDouble,       bm_ckks_encode_double,  bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(CKKS,   n, log_q, DecodeDouble,       bm_ckks_decode_double,  bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(CKKS,   n, log_q, EvaluateAddCt,      bm_ckks_add_ct,         bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(CKKS,   n, log_q, EvaluateAddPt,      bm_ckks_add_pt,         bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(CKKS,   n, log_q, EvaluateMulCt,      bm_ckks_mul_ct,         bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(CKKS,   n, log_q, EvaluateMulPt,      bm_ckks_mul_ct,         bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(CKKS,   n, log_q, EvaluateSquare,     bm_ckks_square,         bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(CKKS,   n, log_q, EvaluateRelin,      bm_ckks_relin,          bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(CKKS,   n, log_q, EvaluateRescale,    bm_ckks_rescale,        bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(CKKS,   n, log_q, EvaluateRotate,     bm_ckks_rotate,         bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(Util,   n, log_q, NTTForward,         bm_ntt_forward,         bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(Util,   n, log_q, NTTBackward,        bm_ntt_backward,        bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(Util,   n, log_q, NTTLazyForward,     bm_ntt_lazy_forward,    bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(Util,   n, log_q, NTTLazyBackward,    bm_ntt_lazy_backward,   bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(Util,   n, log_q, FFTForward,         bm_fft_forward,         bench_env_ckks);
//        SEAL_BENCHMARK_REGISTER(Util,   n, log_q, FFTBackward,        bm_fft_backward,        bench_env_ckks);
    }

} // namespace sealbench

int main(int argc, char **argv)
{
    // Initialize global_parms with BFV default paramaters with 128-bit security.
    // Advanced users may replace this section with custom parameters.
    // SEAL benchmark allow insecure parameters for experimental purpose.
    // DO NOT USE SEAL BENCHMARK AS EXAMPLE.
    auto default_parms = seal::util::global_variables::GetDefaultCoeffModulus128();
    for (auto i : default_parms)
    {
        sealbench::global_parms.emplace_back(i);
    }

    // Initialize global_bench_env with global_parms each of which creates two EncryptionParameters for BFV and CKKS.
    for (auto &i : default_parms)
    {
        EncryptionParameters parms_ckks(scheme_type::ckks);
        parms_ckks.set_poly_modulus_degree(i.first);
        parms_ckks.set_coeff_modulus(i.second);
        EncryptionParameters parms_bfv(scheme_type::bfv);
        parms_bfv.set_poly_modulus_degree(i.first);
        parms_bfv.set_coeff_modulus(i.second);
        parms_bfv.set_plain_modulus(PlainModulus::Batching(i.first, 20));

        if (sealbench::global_bench_env.emplace(make_pair(parms_ckks, make_shared<sealbench::BenchEnv>(parms_ckks))).second == false)
        {
            throw invalid_argument("duplicate parameter sets");
        }
        if (sealbench::global_bench_env.emplace(make_pair(parms_bfv, make_shared<sealbench::BenchEnv>(parms_bfv))).second == false)
        {
            throw invalid_argument("duplicate parameter sets");
        }
    }

    // For each parameter set in global_parms, register a family of benchmark cases.
    for (auto &i : default_parms)
    {
        sealbench::register_bm_family(i);
    }

    Initialize(&argc, argv);
    RunSpecifiedBenchmarks();
}

/*
Program received signal SIGSEGV, Segmentation fault.
__memmove_avx_unaligned_erms () at ../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:416
416	../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S: No such file or directory.
(gdb) bt
#0  __memmove_avx_unaligned_erms () at ../sysdeps/x86_64/multiarch/memmove-vec-unaligned-erms.S:416
#1  0x0000000000454f3d in seal::UniformRandomGenerator::generate(unsigned long, std::byte*) ()
#2  0x0000000000469633 in seal::util::sample_poly_uniform(std::shared_ptr<seal::UniformRandomGenerator>, seal::EncryptionParameters const&, unsigned long*) ()
#3  0x000000000041d50b in sealbench::bm_bfv_mul_ct (state=..., bench_env=warning: RTTI symbol not found for class 'std::_Sp_counted_ptr_inplace<sealbench::BenchEnv, std::allocator<sealbench::BenchEnv>, (__gnu_cxx::_Lock_policy)2>'
warning: RTTI symbol not found for class 'std::_Sp_counted_ptr_inplace<sealbench::BenchEnv, std::allocator<sealbench::BenchEnv>, (__gnu_cxx::_Lock_policy)2>'

std::shared_ptr<sealbench::BenchEnv> (use count 3, weak count 0) = {...})
    at /home/weidai/Repositories/SEAL-Wei/native/bench/bfv.cpp:27
#4  0x0000000000411228 in sealbench::register_bm<void (&)(benchmark::State&, std::shared_ptr<sealbench::BenchEnv>), std::shared_ptr<sealbench::BenchEnv>&>(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, void (&)(benchmark::State&, std::shared_ptr<sealbench::BenchEnv>), std::shared_ptr<sealbench::BenchEnv>&)::{lambda(benchmark::State&)#1}::operator()(benchmark::State&) const (this=0x3a8a1d0, st=...) at /home/weidai/Repositories/SEAL-Wei/native/bench/bench.cpp:24
#5  0x00000000004111d6 in benchmark::internal::LambdaBenchmark<sealbench::register_bm<void (&)(benchmark::State&, std::shared_ptr<sealbench::BenchEnv>), std::shared_ptr<sealbench::BenchEnv>&>(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, void (&)(benchmark::State&, std::shared_ptr<sealbench::BenchEnv>), std::shared_ptr<sealbench::BenchEnv>&)::{lambda(benchmark::State&)#1}>::Run(benchmark::State&) (this=0x3a8a110, st=...)
    at /usr/local/include/benchmark/benchmark.h:1021
#6  0x0000000000560112 in benchmark::internal::BenchmarkInstance::Run(unsigned long, int, benchmark::internal::ThreadTimer*, benchmark::internal::ThreadManager*) const ()
#7  0x000000000054d2b1 in benchmark::internal::(anonymous namespace)::RunInThread(benchmark::internal::BenchmarkInstance const*, unsigned long, int, benchmark::internal::ThreadManager*) ()
#8  0x000000000054bce2 in benchmark::internal::RunBenchmark(benchmark::internal::BenchmarkInstance const&, std::vector<benchmark::BenchmarkReporter::Run, std::allocator<benchmark::BenchmarkReporter::Run> >*) ()
#9  0x000000000052c793 in benchmark::RunSpecifiedBenchmarks(benchmark::BenchmarkReporter*, benchmark::BenchmarkReporter*) ()
#10 0x0000000000408c1b in main (argc=1, argv=0x7fffffffde38) at /home/weidai/Repositories/SEAL-Wei/native/bench/bench.cpp:136
(gdb) 

*/