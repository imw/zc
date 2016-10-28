#include <sodium.h>
#include <boost/log/trivial.hpp>
#include <boost/static_assert.hpp>
#include <vector>


typedef crypto_generichash_blake2b_state eh_HashState;
typedef uint32_t eh_index;
typedef uint8_t eh_trunc;


inline constexpr const size_t max(const size_t A, const size_t B) { return A > B ? A : B; }

inline constexpr size_t equihash_solution_size(unsigned int N, unsigned int K) {
    return (1 << K)*(N/(K+1)+1)/8;
}

template<unsigned int N, unsigned int K>
class Equihash {
private:
    BOOST_STATIC_ASSERT(K < N);
    BOOST_STATIC_ASSERT(N % 8 == 0);
    BOOST_STATIC_ASSERT((N / (K + 1)) + 1 < 8 * sizeof(eh_index));

public:
    enum : size_t {
        IndicesPerHashOutput = 512 / N
    };
    enum : size_t {
        HashOutput = IndicesPerHashOutput * N / 8
    };
    enum : size_t {
        CollisionBitLength = N / (K + 1)
    };
    enum : size_t {
        CollisionByteLength = (CollisionBitLength + 7) / 8
    };
    enum : size_t {
        HashLength = (K + 1) * CollisionByteLength
    };
    enum : size_t {
        FullWidth = 2 * CollisionByteLength + sizeof(eh_index) * (1 << (K - 1))
    };
    enum : size_t {
        FinalFullWidth = 2 * CollisionByteLength + sizeof(eh_index) * (1 << (K))
    };
    enum : size_t {
        TruncatedWidth = max(HashLength + sizeof(eh_trunc), 2 * CollisionByteLength + sizeof(eh_trunc) * (1 << (K - 1)))
    };
    enum : size_t {
        FinalTruncatedWidth = max(HashLength + sizeof(eh_trunc),
                                  2 * CollisionByteLength + sizeof(eh_trunc) * (1 << (K)))
    };
    enum : size_t {
        SolutionWidth = (1 << K) * (CollisionBitLength + 1) / 8
    };

    Equihash() {}

    int InitialiseState(eh_HashState &base_state);


};

    static Equihash<96, 3> Eh96_3;
    static Equihash<200, 9> Eh200_9;
    static Equihash<96, 5> Eh96_5;
    static Equihash<48, 5> Eh48_5;

template int Equihash<200,9>::InitialiseState(eh_HashState& base_state);

#define EhInitialiseState(n, k, base_state)  \
    if (n == 96 && k == 3) {                 \
        Eh96_3.InitialiseState(base_state);  \
    } else if (n == 200 && k == 9) {         \
        Eh200_9.InitialiseState(base_state); \
    } else if (n == 96 && k == 5) {          \
        Eh96_5.InitialiseState(base_state);  \
    } else if (n == 48 && k == 5) {          \
        Eh48_5.InitialiseState(base_state);  \
    } else {                                 \
        throw std::invalid_argument("Unsupported Equihash parameters"); \
    }


template<unsigned int N, unsigned int K>
int Equihash<N,K>::InitialiseState(eh_HashState& base_state)
{
    uint32_t le_N = htole32(N);
    uint32_t le_K = htole32(K);
    unsigned char personalization[crypto_generichash_blake2b_PERSONALBYTES] = {};
    memcpy(personalization, "ZcashPoW", 8);
    memcpy(personalization+8,  &le_N, 4);
    memcpy(personalization+12, &le_K, 4);
    return crypto_generichash_blake2b_init_salt_personal(&base_state,
                                                         NULL, 0, // No key.
                                                         (512/N)*N/8,
                                                         NULL,    // No salt.
                                                         personalization);
}



void GenerateHash(const eh_HashState& base_state, eh_index g,
                  unsigned char* hash, size_t hLen)
{
    eh_HashState state;
    state = base_state;
    eh_index lei = htole32(g);
    crypto_generichash_blake2b_update(&state, (const unsigned char*) &lei,
                                      sizeof(eh_index));
    crypto_generichash_blake2b_final(&state, hash, hLen);
}

int main(){
    const unsigned int n = 200;
    const unsigned int N = 200;
    const unsigned int k = 9;
    const unsigned int K = 9;

    enum : size_t {
        IndicesPerHashOutput = 512 / N
    };
    enum : size_t {
        HashOutput = IndicesPerHashOutput * N / 8
    };

    if (sodium_init() == -1) {
        return -1;
    }
    else {
        BOOST_LOG_TRIVIAL(debug) << "sodium init";
    }


    size_t cBitLen (n/(k+1));
    const std::string &I = "block header";

    crypto_generichash_blake2b_state state;
    EhInitialiseState(n,k,state);
    crypto_generichash_blake2b_update(&state, (unsigned char*)&I[0], I.size());
	unsigned char tmpHash[HashOutput];
    unsigned char * temp;
    for(eh_index i = 0; i < 100; i++) {
        GenerateHash(state, i, tmpHash, HashOutput);
        for(unsigned int p = 0; p < HashOutput; p++) {
            temp = &tmpHash[p];
            int bit_index;
            for (bit_index = 7; bit_index >= 0; --bit_index)
            {
                int bit = *temp >> bit_index & 1;
                printf("%d", bit);
            }
        }

        printf("\n");
        printf("\n");
        printf("\n");
        }



    return 0;
}


// Explicit instantiations for Equihash<200,9>
