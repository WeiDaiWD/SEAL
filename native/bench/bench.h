// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <benchmark/benchmark.h>
#include <seal/seal.h>

namespace sealbench
{
    /**
    Class BenchSet contains a set of required precomputed/preconstructed objects to setup a benchmark case.
    A global BenchSet object is only initialized when a benchmark case for a EncryptionParameters is requested.
    Since benchmark cases for the same parameters are registered together, this avoids heavy precomputation.
    */
    class BenchSet
    {
    public:
        BenchSet() = delete;

        BenchSet(const seal::EncryptionParameters &parms) : parms_(parms), context_(seal::SEALContext(parms_))
        {}

        /**
        Skipped if parms is the same with current parms_.
        */
        void initialize(const seal::EncryptionParameters &parms)
        {
            if (parms == parms_)
            {
                return;
            }
            parms_ = parms;
            context_ = seal::SEALContext(parms_, false);
            keygen_ = std::make_shared<seal::KeyGenerator>(context_);
            sk_ = keygen_->secret_key();
            keygen_->create_public_key(pk_);
            if (context_.using_keyswitching())
            {
                keygen_->create_relin_keys(rlk_);
                galois_elts_all_ = context_.key_context_data()->galois_tool()->get_elts_all();
                keygen_->create_galois_keys(galois_elts_all_, glk_);
            }

            encryptor_ = std::make_shared<seal::Encryptor>(context_, pk_, sk_);
            decryptor_ = std::make_shared<seal::Decryptor>(context_, sk_);
            if (parms_.scheme() == seal::scheme_type::bfv)
            {
                batch_encoder_ = std::make_shared<seal::BatchEncoder>(context_);
            }
            else if (parms_.scheme() == seal::scheme_type::ckks)
            {
                ckks_encoder_ = std::make_shared<seal::CKKSEncoder>(context_);
            }
            evaluator_ = std::make_shared<seal::Evaluator>(context_);
        }

        SEAL_NODISCARD const seal::EncryptionParameters &parms() const
        {
            return parms_;
        }

        SEAL_NODISCARD const seal::SEALContext &context() const
        {
            return context_;
        }

        SEAL_NODISCARD std::shared_ptr<seal::KeyGenerator> keygen()
        {
            return keygen_;
        }

        SEAL_NODISCARD std::shared_ptr<seal::Encryptor> encryptor()
        {
            return encryptor_;
        }

        SEAL_NODISCARD std::shared_ptr<seal::Decryptor> decryptor()
        {
            return decryptor_;
        }

        SEAL_NODISCARD std::shared_ptr<seal::BatchEncoder> batch_encoder()
        {
            return batch_encoder_;
        }

        SEAL_NODISCARD std::shared_ptr<seal::CKKSEncoder> ckks_encoder()
        {
            return ckks_encoder_;
        }

        SEAL_NODISCARD std::shared_ptr<seal::Evaluator> evaluator()
        {
            return evaluator_;
        }

        SEAL_NODISCARD seal::SecretKey &sk()
        {
            return sk_;
        }

        SEAL_NODISCARD const seal::SecretKey &sk() const
        {
            return sk_;
        }

        SEAL_NODISCARD seal::PublicKey &pk()
        {
            return pk_;
        }

        SEAL_NODISCARD const seal::PublicKey &pk() const
        {
            return pk_;
        }

        SEAL_NODISCARD seal::RelinKeys &rlk()
        {
            return rlk_;
        }

        SEAL_NODISCARD const seal::RelinKeys &rlk() const
        {
            return rlk_;
        }

        SEAL_NODISCARD seal::GaloisKeys &glk()
        {
            return glk_;
        }

        SEAL_NODISCARD const seal::GaloisKeys &glk() const
        {
            return glk_;
        }

        SEAL_NODISCARD const std::vector<std::uint32_t> &galois_elts_all() const
        {
            return galois_elts_all_;
        }

    private:
        seal::EncryptionParameters parms_;
        seal::SEALContext context_;
        std::shared_ptr<seal::KeyGenerator> keygen_{ nullptr };
        std::shared_ptr<seal::Encryptor> encryptor_{ nullptr };
        std::shared_ptr<seal::Decryptor> decryptor_{ nullptr };
        std::shared_ptr<seal::BatchEncoder> batch_encoder_{ nullptr };
        std::shared_ptr<seal::CKKSEncoder> ckks_encoder_{ nullptr };
        std::shared_ptr<seal::Evaluator> evaluator_{ nullptr };
        seal::SecretKey sk_;
        seal::PublicKey pk_;
        seal::RelinKeys rlk_;
        seal::GaloisKeys glk_;
        std::vector<std::uint32_t> galois_elts_all_;
    }; // namespace BenchSet

    extern std::shared_ptr<BenchSet> global_bench_set;

    /**
    This is a template to create a benchmark case.

    void bm_category_opname(State &state, const EncryptionParameters &parms)
    {
        global_bench_set.initialize(parms);

        // Fast initilization ...

        for (auto _: state)
        {
            // operation to measure
            //bench_set->...;
        }
    }
    */

    void bm_keygen_secret(benchmark::State &state, const seal::EncryptionParameters &parms);

    void bm_keygen_public(benchmark::State &state, const seal::EncryptionParameters &parms);

    void bm_keygen_relin(benchmark::State &state, const seal::EncryptionParameters &parms);

    void bm_keygen_galois(benchmark::State &state, const seal::EncryptionParameters &parms);

} // namespace sealbench