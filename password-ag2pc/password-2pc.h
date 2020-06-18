#ifndef C2PC_H__
#define C2PC_H__
#include "fpre.h"
#include <emp-tool/emp-tool.h>
#include "argon2.h"
using std::flush;
using std::cout;
using std::cin;
using std::endl;
//#define __debug
namespace emp {
class C2PC { public:
	const static int SSP = 5;//5*8 in fact...
	const block MASK = makeBlock(0x0ULL, 0xFFFFFULL);
	Fpre* fpre = nullptr;
	block * mac = nullptr;
	block * key = nullptr;
	bool * value = nullptr;

	block * preprocess_mac = nullptr;
	block * preprocess_key = nullptr;
	bool* preprocess_value = nullptr;

	block * sigma_mac = nullptr;
	block * sigma_key = nullptr;
	bool * sigma_value = nullptr;

	block * labels = nullptr;

	bool * mask = nullptr;
	CircuitFile * cf;
	NetIO * io;
	int num_ands = 0;
	int party, total_pre;

	//added for FC-resilient implementation:
	const static int SALTLEN = 16; // 16 bytes = 128 bits
	const static int MAXPWLEN = 32; // max password length (bytes)
	block _salt;
	block (*selfGTinputBlocks)[2] = nullptr;
	bool (*selfGTinputBits)[2] = nullptr;
	bool (*selfGToutput)[4] = nullptr;
	uint8_t* mask_input_input = nullptr;
	//end added

	C2PC(NetIO * io, int party, CircuitFile * cf) {
		this->party = party;
		this->io = io;
		this->cf = cf;
		for(int i = 0; i < cf->num_gate; ++i) {
			if (cf->gates[4*i+3] == AND_GATE)
				++num_ands;
		}
		cout << cf->n1<<" "<<cf->n2<<" "<<cf->n3<<" "<<num_ands<<endl<<flush;
		total_pre = cf->n1 + cf->n2 + num_ands;
		fpre = new Fpre(io, party, num_ands);

		key = new block[cf->num_wire];
		mac = new block[cf->num_wire];
		value = new bool[cf->num_wire];

		preprocess_mac = new block[total_pre];
		preprocess_key = new block[total_pre];
		preprocess_value = new bool[total_pre];

		//sigma values in the paper
		sigma_mac = new block[num_ands];
		sigma_key = new block[num_ands];
		sigma_value = new bool[num_ands];

		labels = new block[cf->num_wire];

		mask = new bool[cf->n1 + cf->n2];

		mask_input_input = new uint8_t[cf->n1 + cf->n2];

		if (party == ALICE) {
			selfGTinputBlocks = new block[cf->n2][2];
			selfGTinputBits = new bool[cf->n2][2];
			selfGToutput = new bool[cf->n3][4];
		}
	}
	~C2PC(){
		delete[] key;
		delete[] mac;
		delete[] value;
		delete[] mask;
		delete[] GT;
		delete[] GTK;
		delete[] GTM;
		delete[] GTv;

		delete[] preprocess_mac;
		delete[] preprocess_key;
		delete[] preprocess_value;

		delete[] sigma_mac;
		delete[] sigma_key;
		delete[] sigma_value;

		delete[] labels;
		delete fpre;

		if (party==ALICE) {
			delete[] selfGTinputBlocks;
			delete[] selfGTinputBits;
			delete[] selfGToutput;
		}
	}
	PRG prg;
	PRP prp;
	block (* GT)[4][2] = nullptr;
	block (* GTK)[4] = nullptr;
	block (* GTM)[4] = nullptr;
	bool (* GTv)[4] = nullptr;

	//not allocation
	block * ANDS_mac = nullptr;
	block * ANDS_key = nullptr;
	bool * ANDS_value = nullptr;
	void function_independent() {
		if(party == ALICE) {
			prg.random_block(labels, cf->num_wire);
			prg.random_block(&_salt, 1);
		}

		fpre->refill();
		ANDS_mac = fpre->MAC;
		ANDS_key = fpre->KEY;
		ANDS_value = fpre->r;

		prg.random_bool(preprocess_value, total_pre);
		if(fpre->party == ALICE) {
			fpre->abit1[0]->send(preprocess_key, total_pre);
			fpre->io[0]->flush();
			fpre->abit2[0]->recv(preprocess_mac, preprocess_value, total_pre);
			fpre->io2[0]->flush();
		} else {
			fpre->abit1[0]->recv(preprocess_mac, preprocess_value, total_pre);
			fpre->io[0]->flush();
			fpre->abit2[0]->send(preprocess_key, total_pre);
			fpre->io2[0]->flush();
		}
		memcpy(key, preprocess_key, (cf->n1+cf->n2)*sizeof(block));
		memcpy(mac, preprocess_mac, (cf->n1+cf->n2)*sizeof(block));
		memcpy(value, preprocess_value, (cf->n1+cf->n2)*sizeof(bool));
	}

	void function_dependent() {
		int ands = cf->n1+cf->n2;
		bool * x1 = new bool[num_ands];
		bool * y1 = new bool[num_ands];
		bool * x2 = new bool[num_ands];
		bool * y2 = new bool[num_ands];

		for(int i = 0; i < cf->num_gate; ++i) {
			if (cf->gates[4*i+3] == AND_GATE) {
				key[cf->gates[4*i+2]] = preprocess_key[ands];
				mac[cf->gates[4*i+2]] = preprocess_mac[ands];
				value[cf->gates[4*i+2]] = preprocess_value[ands];
				++ands;
			}
		}

		for(int i = 0; i < cf->num_gate; ++i) {
			if (cf->gates[4*i+3] == XOR_GATE) {
				key[cf->gates[4*i+2]] = xorBlocks(key[cf->gates[4*i]], key[cf->gates[4*i+1]]);
				mac[cf->gates[4*i+2]] = xorBlocks(mac[cf->gates[4*i]], mac[cf->gates[4*i+1]]);
				value[cf->gates[4*i+2]] = logic_xor(value[cf->gates[4*i]], value[cf->gates[4*i+1]]);
				if(party == ALICE)
					labels[cf->gates[4*i+2]] = xorBlocks(labels[cf->gates[4*i]], labels[cf->gates[4*i+1]]);
			} else if (cf->gates[4*i+3] == NOT_GATE) {
				if(party == ALICE)
					labels[cf->gates[4*i+2]] = xorBlocks(labels[cf->gates[4*i]], fpre->Delta);
				value[cf->gates[4*i+2]] = value[cf->gates[4*i]];
				key[cf->gates[4*i+2]] = key[cf->gates[4*i]];
				mac[cf->gates[4*i+2]] = mac[cf->gates[4*i]];
			}
		}
		ands = 0;
		for(int i = 0; i < cf->num_gate; ++i) {
			if (cf->gates[4*i+3] == AND_GATE) {
				x1[ands] = logic_xor(value[cf->gates[4*i]], ANDS_value[3*ands]);
				y1[ands] = logic_xor(value[cf->gates[4*i+1]], ANDS_value[3*ands+1]);	
				ands++;
			}
		}
		if(party == ALICE) {
			send_bool(io, x1, num_ands);
			send_bool(io, y1, num_ands);
			recv_bool(io, x2, num_ands);
			recv_bool(io, y2, num_ands);
		} else {
			recv_bool(io, x2, num_ands);
			recv_bool(io, y2, num_ands);
			send_bool(io, x1, num_ands);
			send_bool(io, y1, num_ands);
		}
		for(int i = 0; i < num_ands; ++i) {
			x1[i] = logic_xor(x1[i], x2[i]); 
			y1[i] = logic_xor(y1[i], y2[i]); 
		}
		ands = 0;
		for(int i = 0; i < cf->num_gate; ++i) {
			if (cf->gates[4*i+3] == AND_GATE) {
				sigma_mac[ands] = ANDS_mac[3*ands+2];
				sigma_key[ands] = ANDS_key[3*ands+2];
				sigma_value[ands] = ANDS_value[3*ands+2];

				if(x1[ands]) {
					sigma_mac[ands] = xorBlocks(sigma_mac[ands], ANDS_mac[3*ands+1]);
					sigma_key[ands] = xorBlocks(sigma_key[ands], ANDS_key[3*ands+1]);
					sigma_value[ands] = logic_xor(sigma_value[ands], ANDS_value[3*ands+1]);
				}
				if(y1[ands]) {
					sigma_mac[ands] = xorBlocks(sigma_mac[ands], ANDS_mac[3*ands]);
					sigma_key[ands] = xorBlocks(sigma_key[ands], ANDS_key[3*ands]);
					sigma_value[ands] = logic_xor(sigma_value[ands], ANDS_value[3*ands]);
				}
				if(x1[ands] and y1[ands]) {
					if(party == ALICE)
						sigma_key[ands] = xorBlocks(sigma_key[ands], fpre->Delta);
					else
						sigma_value[ands] = not sigma_value[ands];
				}

#ifdef __debug
				block MM[] = {mac[cf->gates[4*i]], mac[cf->gates[4*i+1]], sigma_mac[ands]};
				block KK[] = {key[cf->gates[4*i]], key[cf->gates[4*i+1]], sigma_key[ands]};
				bool VV[] = {value[cf->gates[4*i]], value[cf->gates[4*i+1]], sigma_value[ands]};
				check(MM, KK, VV);
#endif
				ands++;
			}
		}//sigma_[] stores the and of input wires to each AND gates

		delete[] fpre->MAC;
		delete[] fpre->KEY;
		delete[] fpre->r;
		fpre->MAC = nullptr;
		fpre->KEY = nullptr;
		fpre->r = nullptr;
		GT = new block[num_ands][4][2];
		GTK = new block[num_ands][4];
		GTM = new block[num_ands][4];
		GTv = new bool[num_ands][4];
	
		ands = 0;
		block H[4][2];
		block K[4], M[4];
		bool r[4];
		for(int i = 0; i < cf->num_gate; ++i) {
			if(cf->gates[4*i+3] == AND_GATE) {
				r[0] = logic_xor(sigma_value[ands] , value[cf->gates[4*i+2]]);
				r[1] = logic_xor(r[0] , value[cf->gates[4*i]]);
				r[2] = logic_xor(r[0] , value[cf->gates[4*i+1]]);
				r[3] = logic_xor(r[1] , value[cf->gates[4*i+1]]);
				if(party == BOB) r[3] = not r[3];

				M[0] = xorBlocks(sigma_mac[ands], mac[cf->gates[4*i+2]]);
				M[1] = xorBlocks(M[0], mac[cf->gates[4*i]]);
				M[2] = xorBlocks(M[0], mac[cf->gates[4*i+1]]);
				M[3] = xorBlocks(M[1], mac[cf->gates[4*i+1]]);

				K[0] = xorBlocks(sigma_key[ands], key[cf->gates[4*i+2]]);
				K[1] = xorBlocks(K[0], key[cf->gates[4*i]]);
				K[2] = xorBlocks(K[0], key[cf->gates[4*i+1]]);
				K[3] = xorBlocks(K[1], key[cf->gates[4*i+1]]);
				if(party == ALICE) K[3] = xorBlocks(K[3], fpre->Delta);

				if(party == ALICE) {
					Hash(H, labels[cf->gates[4*i]], labels[cf->gates[4*i+1]], i);
					for(int j = 0; j < 4; ++j) {
						H[j][0] = xorBlocks(H[j][0], M[j]);
						H[j][1] = xorBlocks(H[j][1], xorBlocks(K[j], labels[cf->gates[4*i+2]]));
						if(r[j]) 
							H[j][1] = xorBlocks(H[j][1], fpre->Delta);
#ifdef __debug
						check2(M[j], K[j], r[j]);
#endif
					}
					for(int j = 0; j < 4; ++j ) {
						send_partial_block<SSP>(io, &H[j][0], 1);
						io->send_block(&H[j][1], 1);
					}
				} else {
					memcpy(GTK[ands], K, sizeof(block)*4);
					memcpy(GTM[ands], M, sizeof(block)*4);
					memcpy(GTv[ands], r, sizeof(bool)*4);
#ifdef __debug
					for(int j = 0; j < 4; ++j)
						check2(M[j], K[j], r[j]);
#endif
					for(int j = 0; j < 4; ++j ) {
						recv_partial_block<SSP>(io, &GT[ands][j][0], 1);
						io->recv_block(&GT[ands][j][1], 1);
					}
				}
				++ands;
			}
		}
		delete[] x1;
		delete[] x2;
		delete[] y1;
		delete[] y2;


		block tmp;
		if(party == ALICE) {
			send_partial_block<SSP>(io, mac, cf->n1);
			for(int i = cf->n1; i < cf->n1+cf->n2; ++i) {
				recv_partial_block<SSP>(io, &tmp, 1);
				block ttt = xorBlocks(key[i], fpre->Delta);
				ttt =  _mm_and_si128(ttt, MASK);
				block mask_key = _mm_and_si128(key[i], MASK);
				tmp =  _mm_and_si128(tmp, MASK);
				if(block_cmp(&tmp, &mask_key, 1))
					mask[i] = false;
				else if(block_cmp(&tmp, &ttt, 1))
					mask[i] = true;
				else cout <<"no match! ALICE\t"<<i<<endl;
			}
		} else {
			for(int i = 0; i < cf->n1; ++i) {
				recv_partial_block<SSP>(io, &tmp, 1);
				block ttt = xorBlocks(key[i], fpre->Delta);
				ttt =  _mm_and_si128(ttt, MASK);
				tmp =  _mm_and_si128(tmp, MASK);
				block mask_key = _mm_and_si128(key[i], MASK);
				if(block_cmp(&tmp, &mask_key, 1)) {
					mask[i] = false;
				} else if(block_cmp(&tmp, &ttt, 1)) {
					mask[i] = true;
				}
				else cout <<"no match! BOB\t"<<i<<endl;
			}
			send_partial_block<SSP>(io, mac+cf->n1, cf->n2);
		}
	}

	void selfgarble_io() {
		if(party == ALICE) {
			block perm_bits;
			int pc = 0; // perm_counter
			uint8_t perm_tmp[sizeof(block)];
			for(int i = cf->n1; i < cf->n1+cf->n2; ++i) {
				//ALICE: self-garbled input tables
				if (pc % (sizeof(block)*8) == 0) {
					prg.random_block(&perm_bits, 1);
					memcpy(perm_tmp, &perm_bits, sizeof(block));
					pc = 0;
				}
				pc += 1;
				int perm_bit = (int) ((perm_tmp[pc/8] >> (pc%8))%2 == 1);
				int j = i - cf->n1;
				//printf("Computing self-garbled input tables from PBKDF\n");
				bool pwmask0 = pbkdf_input(selfGTinputBlocks[j][perm_bit], i, 0);
				bool pwmask1 = pbkdf_input(selfGTinputBlocks[j][1 - perm_bit], i, 1);
				selfGTinputBits[j][perm_bit] = logic_xor(mask[i], 
						logic_xor(value[i], pwmask0));
				selfGTinputBits[j][1 - perm_bit] = logic_xor(value[i],
						logic_xor(pwmask1,
						logic_xor(mask[i], 1)));
			}

			// ALICE: self-garbled output tables
			for (int i=0; i < cf->n3; ++i) {
				bool r = value[cf->num_wire - cf->n3 + i];
				//printf("Computing self-garbled output tables from PBKDF\n");
				// zmsk = 0, s=0 => z = r
				selfGToutput[i][0] = logic_xor(r,
						pbkdf_output(cf->num_wire-cf->n3+i, 0, 0));
				// zmsk = 0, s=1 => z = r+1
				selfGToutput[i][1] = logic_xor(r, true);
				selfGToutput[i][1] = logic_xor(selfGToutput[i][1],
						pbkdf_output(cf->num_wire-cf->n3+i, 0, 1));
				// zmsk = 1, s=0 => z = r+1
				selfGToutput[i][2] = logic_xor(r, true);
				selfGToutput[i][2] = logic_xor(selfGToutput[i][2],
						pbkdf_output(cf->num_wire-cf->n3+i, 1, 0));
				// zmsk = 1, s=1 => z = r
				selfGToutput[i][3] = logic_xor(r,
						pbkdf_output(cf->num_wire-cf->n3+i, 1, 1));
			}

			// Alice "securely deletes" all r values except for the ones for her input
			std::fill(value, value+(cf->n1), false);
			std::fill(value+(cf->n1+cf->n2), 
					value+(cf->num_wire-(cf->n1+cf->n2)), false);
		}

	}

	void handle_input (bool * input) {
		memset(mask_input_input, 0, cf->n1 + cf->n2);
		block tmp;

		if(party == ALICE) {
			for(int i = cf->n1; i < cf->n1+cf->n2; ++i) {

				// re-get masked input from self-garbled input tables
				int j = i - cf->n1;
				block tmp;
				//printf("Reconstructing input from PBKDF\n");
				bool maskbit = pbkdf_input(tmp, i, input[j]);
				if (block_cmp(&tmp, &(selfGTinputBlocks[j][0]), 1))
					mask_input_input[i] = (uint8_t) logic_xor(maskbit, selfGTinputBits[j][0]);
				else if (block_cmp(&tmp, &(selfGTinputBlocks[j][1]), 1))
					mask_input_input[i] = (uint8_t) logic_xor(maskbit, selfGTinputBits[j][1]);
				else
					cout << "Re-entered PBKDF did not find masked input" << endl;
			}
			io->recv_data(mask_input_input, cf->n1);
			io->send_data(mask_input_input+cf->n1, cf->n2);
			for(int i = 0; i < cf->n1 + cf->n2; ++i) {
				tmp = labels[i];
				if(mask_input_input[i]) tmp = xorBlocks(tmp, fpre->Delta);
				io->send_block(&tmp, 1);
			}
		} else {
			for(int i = 0; i < cf->n1; ++i) {
				mask_input_input[i] = logic_xor(input[i], value[i]);
				mask_input_input[i] = logic_xor(mask_input_input[i], mask[i]);
			}
			io->send_data(mask_input_input, cf->n1);
			io->recv_data(mask_input_input+cf->n1, cf->n2);
			io->recv_block(labels, cf->n1 + cf->n2);

			//send output mask data (Bob does this for FC-resil version)
			send_partial_block<SSP>(io, mac+cf->num_wire - cf->n3, cf->n3);
		}
	}

	void online () {
		// separated for benchmarking purposes
		uint8_t * mask_input = new uint8_t[cf->num_wire];
		memset(mask_input, 0, cf->num_wire);
		memcpy(mask_input, mask_input_input, cf->n1+cf->n2);
		memset(mask_input_input, 0, cf->n1 + cf->n2);
		int ands = 0;
		if(party == BOB) {
			for(int i = 0; i < cf->num_gate; ++i) {
				if (cf->gates[4*i+3] == XOR_GATE) {
					labels[cf->gates[4*i+2]] = xorBlocks(labels[cf->gates[4*i]], labels[cf->gates[4*i+1]]);
					mask_input[cf->gates[4*i+2]] = logic_xor(mask_input[cf->gates[4*i]], mask_input[cf->gates[4*i+1]]);
				} else if (cf->gates[4*i+3] == AND_GATE) {
					int index = 2*mask_input[cf->gates[4*i]] + mask_input[cf->gates[4*i+1]];
					block H[2];
					Hash(H, labels[cf->gates[4*i]], labels[cf->gates[4*i+1]], i, index);
					GT[ands][index][0] = xorBlocks(GT[ands][index][0], H[0]);
					GT[ands][index][1] = xorBlocks(GT[ands][index][1], H[1]);

					block ttt = xorBlocks(GTK[ands][index], fpre->Delta);
					ttt =  _mm_and_si128(ttt, MASK);
					GTK[ands][index] =  _mm_and_si128(GTK[ands][index], MASK);
					GT[ands][index][0] =  _mm_and_si128(GT[ands][index][0], MASK);

					if(block_cmp(&GT[ands][index][0], &GTK[ands][index], 1))
						mask_input[cf->gates[4*i+2]] = false;
					else if(block_cmp(&GT[ands][index][0], &ttt, 1))
						mask_input[cf->gates[4*i+2]] = true;
					else 	cout <<ands <<"no match GT!"<<endl;
					mask_input[cf->gates[4*i+2]] = logic_xor(mask_input[cf->gates[4*i+2]], GTv[ands][index]);

					labels[cf->gates[4*i+2]] = xorBlocks(GT[ands][index][1], GTM[ands][index]);
					ands++;
				} else {
					mask_input[cf->gates[4*i+2]] = not mask_input[cf->gates[4*i]];	
					labels[cf->gates[4*i+2]] = labels[cf->gates[4*i]];
				}
			}

			// send output wire labels
			io->send_data(labels+(cf->num_wire - cf->n3), (cf->n3)*sizeof(block));
		}
		delete[] mask_input;

	}

	void process_outputs(bool* output) {

		if (party == ALICE) {
			bool * o = new bool[cf->n3];
			uint8_t* mask_input = new uint8_t[cf->n3];
			// receive and verify s (shares of lambda)
			for(int i = 0; i < cf->n3; ++i) {
				block tmp;
				recv_partial_block<SSP>(io, &tmp, 1);
				tmp =  _mm_and_si128(tmp, MASK);

				block ttt = xorBlocks(key[cf->num_wire - cf-> n3 + i], fpre->Delta);
				ttt =  _mm_and_si128(ttt, MASK);
				key[cf->num_wire - cf-> n3 + i] =  _mm_and_si128(key[cf->num_wire - cf-> n3 + i], MASK);

				if(block_cmp(&tmp, &key[cf->num_wire - cf-> n3 + i], 1)) 
					o[i] = false;
				else if(block_cmp(&tmp, &ttt, 1)) 
					o[i] = true;
				else cout <<"output MAC did not verify!"<<endl;
			}

			// receive and verify wire labels
			block* received_labels = new block[cf->n3];
			io->recv_data(received_labels, (cf->n3)*sizeof(block));

			for (int i=0; i < cf->n3; ++i) {
				block tmp0 = labels[cf->num_wire-cf->n3 + i];
				block tmp1 = xorBlocks(tmp0, fpre->Delta);
				if (block_cmp(&tmp0, received_labels+i, 1))
					//mask_input[cf->num_wire - cf->n3 + i] = 0;
					mask_input[i] = 0;
				else if (block_cmp(&tmp1, received_labels+i, 1))
					//mask_input[cf->num_wire - cf->n3 + i] = 1;
					mask_input[i] = 1;
				else
					cout<<"received wire label " <<i<< " did not match!"<<endl;
			}
			delete[] received_labels;

			// output by reconstructing from self-garbled table
			for(int i = 0; i < cf->n3; ++i) {
				//uint8_t zmsk = mask_input[cf->num_wire - cf->n3 + i];
				uint8_t zmsk = mask_input[i];
				uint8_t s = o[i];
				uint8_t out_index = s + 2*zmsk;
				bool output_from_table = selfGToutput[i][out_index];
				//printf("Reconstructing output from PBKDF\n");
				output[i] = logic_xor(output_from_table,
						pbkdf_output(cf->num_wire-cf->n3+i, zmsk, s));
			}

			delete[] o;
			delete[] mask_input;
		}
	}

	void check(block * MAC, block * KEY, bool * r, int length = 1) {
		if (party == ALICE) {
			io->send_data(r, length*3);
			io->send_block(&fpre->Delta, 1);
			io->send_block(KEY, length*3);
			block DD;io->recv_block(&DD, 1);

			for(int i = 0; i < length*3; ++i) {
				block tmp;io->recv_block(&tmp, 1);
				if(r[i]) tmp = xorBlocks(tmp, DD);
				if (!block_cmp(&tmp, &MAC[i], 1))
					cout <<i<<"\tWRONG ABIT!"<<endl<<flush;
			}

		} else {
			bool tmp[3];
			for(int i = 0; i < length; ++i) {
				io->recv_data(tmp, 3);
				bool res = (logic_xor(tmp[0], r[3*i] )) and (logic_xor(tmp[1], r[3*i+1]));
				if(res != logic_xor(tmp[2], r[3*i+2]) ) {
					cout <<i<<"\tWRONG!"<<endl<<flush;
				}
			}
			block DD;io->recv_block(&DD, 1);

			for(int i = 0; i < length*3; ++i) {
				block tmp;io->recv_block(&tmp, 1);
				if(r[i]) tmp = xorBlocks(tmp, DD);
				if (!block_cmp(&tmp, &MAC[i], 1))
					cout <<i<<"\tWRONG ABIT!"<<endl<<flush;
			}
			io->send_block(&fpre->Delta, 1);
			io->send_block(KEY, length*3);
		}
		io->flush();
	}

	void check2(block & MAC, block & KEY, bool  &r) {
		if (party == ALICE) {
			io->send_block(&fpre->Delta, 1);
			io->send_block(&KEY, 1);
			block DD;io->recv_block(&DD, 1);
			for(int i = 0; i < 1; ++i) {
				block tmp;io->recv_block(&tmp, 1);
				if(r) tmp = xorBlocks(tmp, DD);
				if (!block_cmp(&tmp, &MAC, 1))
					cout <<i<<"\tWRONG ABIT!2"<<endl<<flush;
			}
		} else {
			block DD;io->recv_block(&DD, 1);
			for(int i = 0; i < 1; ++i) {
				block tmp;io->recv_block(&tmp, 1);
				if(r) tmp = xorBlocks(tmp, DD);
				if (!block_cmp(&tmp, &MAC, 1))
					cout <<i<<"\tWRONG ABIT!2"<<endl<<flush;
			}
			io->send_block(&fpre->Delta, 1);
			io->send_block(&KEY, 1);
		}
		io->flush();
	}

	void Hash(block H[4][2], const block & a, const block & b, uint64_t i) {
		block A[2], B[2];
		A[0] = a; A[1] = xorBlocks(a, fpre->Delta);
		B[0] = b; B[1] = xorBlocks(b, fpre->Delta);
		A[0] = double_block(A[0]);
		A[1] = double_block(A[1]);
		B[0] = double_block(double_block(B[0]));
		B[1] = double_block(double_block(B[1]));

		H[0][1] = H[0][0] = xorBlocks(A[0], B[0]);
		H[1][1] = H[1][0] = xorBlocks(A[0], B[1]);
		H[2][1] = H[2][0] = xorBlocks(A[1], B[0]);
		H[3][1] = H[3][0] = xorBlocks(A[1], B[1]);
		for(uint64_t j = 0; j < 4; ++j) {
			H[j][0] = xorBlocks(H[j][0], _mm_set_epi64x(4*i+j, 0ULL));
			H[j][1] = xorBlocks(H[j][1], _mm_set_epi64x(4*i+j, 1ULL));
		}
		prp.permute_block((block *)H, 8);
	}

	void Hash(block H[2], block a, block b, uint64_t i, uint64_t row) {
		a = double_block(a);
		b = double_block(double_block(b));
		H[0] = H[1] = xorBlocks(a, b);
		H[0] = xorBlocks(H[0], _mm_set_epi64x(4*i+row, 0ULL));
		H[1] = xorBlocks(H[1], _mm_set_epi64x(4*i+row, 1ULL));
		prp.permute_block((block *)H, 2);
	}

	bool logic_xor(bool a, bool b) {
		return a!= b;
	}
	string tostring(bool a) {
		if(a) return "T";
		else return "F";
	}

	bool pbkdf_output(int idx, bool zmsk, bool s) {
		uint8_t tmp;
		//printf("pbkdf_output call: %d, %d, %d, %d, %d\n", 
				//idx, 0xff, zmsk, s, 1);
		pbkdf(&tmp, idx, 0xff, (uint8_t) zmsk, (uint8_t) s, 1);
		return ((tmp % 2) == 1);
	}

	bool pbkdf_input(block& out, int idx, bool x_in) {
		// outputs N+1 bits: N=blocklen stored in out, 1 given as output
		const int outlen = sizeof(block) + 1;
		uint8_t tmp[outlen];
		//printf("pbkdf_input call: %d, %d, %d, %d, %d\n", idx, x_in, 
				//0xff, 0xff, outlen);
		pbkdf(tmp, idx, (uint8_t) x_in, 0xff, 0xff, outlen);
		memcpy(&out, tmp, sizeof(block));
		return ((tmp[outlen-1] % 2) == 1);
	}

	void pbkdf(uint8_t* out, int idx, uint8_t x_in, uint8_t zmsk, uint8_t s, uint32_t outlen) {
		// abstraction of password entry process, cannot be compelled during this function
		// input to PBKDF: 
		// index (4B) || x_in (1B) || zmsk (1B) || s (1B) || password (32B) 
		// (plus salt as part of actual pbkdf function)
		uint8_t ad[7];
		memcpy(ad, &idx, 4);
		memset(ad+4, x_in, 1);
		memset(ad+5, zmsk, 1);
		memset(ad+6, s, 1);

		// Get password.  In real execution, would want to read password from stdin.
		// But here we just read from a file for simplicity.
		//cout << "Enter password: ";
		char pw[MAXPWLEN];
		std::fill(pw, pw+MAXPWLEN, 0);
		std::ifstream pwfile;
		pwfile.open("ALICE_password.txt");
		pwfile >> pw;
		pwfile.close();
		//cin.getline(pw, MAXPWLEN);

		raw_pbkdf(out, (uint8_t*) &_salt, (uint8_t*) pw, ad, 
				outlen, sizeof(block), MAXPWLEN, 7);
		memset(pw, 0, MAXPWLEN);
	}

	void raw_pbkdf(uint8_t* out, uint8_t* salt, uint8_t* pw, uint8_t* ad,
			uint32_t outlen, uint32_t saltlen, uint32_t pwlen, uint32_t adlen) {

		// argon2 parameters cranked down to be pretty weak due to speed
		//const uint32_t T_COST = 5; // num passes
		//const uint32_t M_COST = 1 << 20; // 1GB
		//const uint32_t PAR = 4; // number of threads and compute lanes
		const uint32_t T_COST = 1;
		const uint32_t M_COST = 1 << 10;
		const uint32_t PAR = 4;

		// account for min 
		uint32_t tmpoutlen = outlen;
		if (outlen < ARGON2_MIN_OUTLEN) {
			tmpoutlen = ARGON2_MIN_OUTLEN;
		}
		uint8_t tmpout[tmpoutlen];
		argon2_context ctx = {tmpout, tmpoutlen, pw, pwlen,
				salt, saltlen, NULL, 0, ad, adlen,
				T_COST, M_COST, PAR, PAR, ARGON2_VERSION_13, 
				NULL, NULL, ARGON2_FLAG_CLEAR_PASSWORD};
		int rc = argon2i_ctx(&ctx);
		if (rc != ARGON2_OK) 
			printf("Argon2 error: %s\n", argon2_error_message(rc));
		memcpy(out, tmpout, outlen);
		memset(tmpout, 0, tmpoutlen);
		memset(pw, 0, pwlen);
	}
};
}
#endif// C2PC_H__
