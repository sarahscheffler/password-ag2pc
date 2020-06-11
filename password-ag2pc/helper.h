#ifndef __HELPER
#define __HELPER
#include <emp-tool/emp-tool.h>
#include "c2pc_config.h"
#include <immintrin.h>
#include <boost/align/align.hpp>

using std::future;
using std::cout;
using std::endl;
using std::flush;
#undef align

namespace emp {

void send_bool_aligned(NetIO* io, const bool * data, int length) {
	unsigned long long * data64 = (unsigned long long * )data;
	int i = 0;
#if !defined(__BMI2__)
	unsigned long long mask;
#endif
	for(; i < length/8; ++i) {
		unsigned long long tmp;
#if defined(__BMI2__)
		tmp = _pext_u64(data64[i], 0x0101010101010101ULL);
#else
		// https://github.com/Forceflow/libmorton/issues/6
		tmp = 0;
		mask = 0x0101010101010101ULL;
		for (unsigned long long bb = 1; mask != 0; bb += bb) {
			if (data64[i] & mask & -mask) { tmp |= bb; }
			mask &= (mask - 1);
		}
#endif
		io->send_data(&tmp, 1);
	}
	if (8*i != length)
		io->send_data(data + 8*i, length - 8*i);
}
void recv_bool_aligned(NetIO* io, bool * data, int length) {
	unsigned long long * data64 = (unsigned long long *) data;
	int i = 0;
#if !defined(__BMI2__)
	unsigned long long mask;
#endif
	for(; i < length/8; ++i) {
		unsigned long long tmp = 0;
		io->recv_data(&tmp, 1);
#if defined(__BMI2__)
		data64[i] = _pdep_u64(tmp, (unsigned long long) 0x0101010101010101ULL);
#else
		data64[i] = 0;
		mask = 0x0101010101010101ULL;
                for (unsigned long long bb = 1; mask != 0; bb += bb) {
                        if (tmp & bb) {data64[i] |= mask & (-mask); }
                        mask &= (mask - 1);
                }
#endif
	}
	if (8*i != length)
		io->recv_data(data + 8*i, length - 8*i);
}
void send_bool(NetIO * io, bool * data, int length) {
	void * ptr = (void *)data;
	size_t space = length;
	void * aligned = boost::alignment::align(alignof(uint64_t), sizeof(uint64_t), ptr, space);
    if(aligned == nullptr)
        io->send_data(data, length);
    else{
        int diff = length - space;
        io->send_data(data, diff);
        send_bool_aligned(io, (const bool*)aligned, length - diff);
    }
}

void recv_bool(NetIO * io, bool * data, int length) {
	void * ptr = (void *)data;
	size_t space = length;
	void * aligned = boost::alignment::align(alignof(uint64_t), sizeof(uint64_t), ptr, space);
    if(aligned == nullptr)
        io->recv_data(data, length);
    else{
        int diff = length - space;
        io->recv_data(data, diff);
        recv_bool_aligned(io, (bool*)aligned, length - diff);
    }
}

template<int B>
void send_partial_block(NetIO * io, const block * data, int length) {
	for(int i = 0; i < length; ++i) {
		io->send_data(&(data[i]), B);
	}
}

template<int B>
void recv_partial_block(NetIO * io, block * data, int length) {
	for(int i = 0; i < length; ++i) {
		io->recv_data(&(data[i]), B);
	}
}

//ADDED:
void print_block(const block& bl) {
	uint8_t val[16];
	memcpy(val, &bl, sizeof(val));
	printf("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", 
			val[0], val[1], val[2], val[3], val[4], val[5], val[6],
			val[7], val[8], val[9], val[10], val[11], val[12],
			val[13], val[14], val[15]);
}
}
#endif// __HELPER
