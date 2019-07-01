#pragma once

#include <cstdint>
#include <cstring>

#ifndef Sha256GRG_H
#define Sha256GRG_H

struct SHA256Hash
{
	unsigned char Hash[32];
	bool operator==(const SHA256Hash& other)
	{
		for (uint8_t i = 0; i < 32; i++)
		{
			if (Hash[i] == other.Hash[i])
			{
				continue;
			}
			else
			{
				return false;
			}
		}
		return true;
	}

	SHA256Hash(unsigned char H[32])
	{
		for (uint8_t i = 0; i < 32; i++)
		{
			Hash[i] = H[i];
		}
	}

};



namespace SHA256Util
{
	void byte_swap_64(uint64_t* thing)
	{
		uint64_t tmp = 0;
		for (uint8_t i = 0; i < 8; i++)
		{
			*(((uint8_t*)&tmp) + (7 - i)) = *(((uint8_t*)thing) + i);
		}
		*thing = tmp;
	}

	void byte_swap_32(uint32_t* thing)
	{
		uint32_t tmp = 0;
		for (uint8_t i = 0; i < 4; i++)
		{
			*(((uint8_t*)&tmp) + (3 - i)) = *(((uint8_t*)thing) + i);
		}
		*thing = tmp;
	}

	inline uint32_t SHA256_Sn32(uint32_t x, uint8_t n)
	{
		return (x >> n) | (x << (32 - n));
	}

	inline uint32_t SHA256_Rn32(uint32_t x, uint8_t n)
	{
		return x >> n;
	}

	inline uint32_t SHA256_Ch32(uint32_t x, uint32_t y, uint32_t z)
	{
		return (x & y) ^ (~x & z);
	}

	inline uint32_t SHA256_Maj32(uint32_t x, uint32_t y, uint32_t z)
	{
		return (x & y) ^ (x & z) ^ (y & z);
	}

	inline uint32_t SHA256_Sum0_32(uint32_t x)
	{
		return SHA256_Sn32(x, 2) ^ SHA256_Sn32(x, 13) ^ SHA256_Sn32(x, 22);
	}

	inline uint32_t SHA256_Sum1_32(uint32_t x)
	{
		return SHA256_Sn32(x, 6) ^ SHA256_Sn32(x, 11) ^ SHA256_Sn32(x, 25);
	}

	inline uint32_t SHA256_Sig0_32(uint32_t x)
	{
		return SHA256_Sn32(x, 7) ^ SHA256_Sn32(x, 18) ^ SHA256_Rn32(x, 3);
	}

	inline uint32_t SHA256_Sig1_32(uint32_t x)
	{
		return SHA256_Sn32(x, 17) ^ SHA256_Sn32(x, 19) ^ SHA256_Rn32(x, 10);
	}
}

template<typename T>
SHA256Hash SHA256(T* data)
{
	return SHA256(data, sizeof(T));
}

SHA256Hash SHA256(const void * data, const unsigned int size)
{
	// hash padding
	unsigned int padding_size = 512 - (((size * 8) + 8 + 64) % 512);
	unsigned int tmp_size = size + 1 + ((padding_size + 64) / 8);
	unsigned int no_blocks = tmp_size / 64;
	unsigned char* tM = new unsigned char[tmp_size];

	// padding (currently poorly optimized -> can be made in the parsing itself)
	memcpy(tM, data, size);
	memset(tM + size, 128, 1);
	memset(tM + size + 1, 0, (padding_size / 8));
	uint64_t len = (size * 8); // endianness ... -.-
	SHA256Util::byte_swap_64(&len); // swap endianess :D
	memcpy(tM + size + 1 + (padding_size / 8), &len, 8);

	// unpleasant necessary conversions
	uint32_t* M = (uint32_t*)tM;

	// actual hash calculation
	// initial hash
	uint32_t H[8] = {
		 0x6a09e667,
		 0xbb67ae85,
		 0x3c6ef372,
		 0xa54ff53a,
		 0x510e527f,
		 0x9b05688c,
		 0x1f83d9ab,
		 0x5be0cd19,
	};
	const uint32_t K[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	};
	uint32_t W[64];
	uint32_t H_i[8];
	// careful - heavy indexing
	for (unsigned int k = 0; k < no_blocks; k++)
	{
		// calculate w (see description : http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf page 8)
		for (uint8_t j = 0; j < 16; j++)
		{
			// fuckin endianess
			SHA256Util::byte_swap_32(&M[j + (k * 16)]);
			W[j] = M[j + (k * 16)];
		}

		for (uint8_t j = 16; j < 64; j++)
		{
			W[j] = SHA256Util::SHA256_Sig1_32(W[j - 2]) + W[j - 7] + SHA256Util::SHA256_Sig0_32(W[j - 15]) + W[j - 16];
		}
		// tmphash update (load the current hash into the working "registers" -> even though i doubt theese end up in registers)
		// what cpu even has 8 32 bit registers and enough registers left for looping 
		for (uint8_t j = 0; j < 8; j++)
		{
			H_i[j] = H[j];
		}
		// the actual calculation
		for (unsigned int i = 0; i < 64; i++)
		{
			uint32_t t1 = H_i[7] + SHA256Util::SHA256_Sum1_32(H_i[4]) + SHA256Util::SHA256_Ch32(H_i[4], H_i[5], H_i[6]) + K[i] + W[i];
			uint32_t t2 = SHA256Util::SHA256_Sum0_32(H_i[0]) + SHA256Util::SHA256_Maj32(H_i[0], H_i[1], H_i[2]);
			H_i[7] = H_i[6];
			H_i[6] = H_i[5];
			H_i[5] = H_i[4];
			H_i[4] = H_i[3] + t1;
			H_i[3] = H_i[2];
			H_i[2] = H_i[1];
			H_i[1] = H_i[0];
			H_i[0] = t1 + t2;
		}
		// update hash
		// add intermediate value to the current hash
		for (uint8_t j = 0; j < 8; j++)
		{
			H[j] += H_i[j];
		}
	}
	for (uint8_t j = 0; j < 8; j++)
	{
		// endianness the third ...
		SHA256Util::byte_swap_32(&H[j]);
	}
	delete[] tM;
	return SHA256Hash((uint8_t*)H);
}

#endif
