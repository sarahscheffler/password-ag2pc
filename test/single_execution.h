#include <emp-tool/emp-tool.h>
#include "password-ag2pc/password-ag2pc.h"
using namespace std;
using namespace emp;

const string circuit_file_location = macro_xstr(EMP_CIRCUIT_PATH);

string partystr(int party) {
	if(party==ALICE) return "ALICE";
	else if(party==BOB) return "BOB";
	else assert(false);
}

string get_run() {
	string toret;
	ifstream infile;
	infile.open("pbkdf_file.txt");
	getline(infile, toret);
	infile.close();
	return toret;
}

void test(int party, NetIO* io, string name, string check_output = "") {
	string file = name;//circuit_file_location + name;
	CircuitFile cf(file.c_str());
	auto t1 = clock_start();
	C2PC twopc(io, party, &cf);
	io->flush();
	cout << "one time setup:\t"<<party<<"\t" <<time_from(t1)<<endl;

	t1 = clock_start();
	twopc.function_independent();
	io->flush();
	cout << "indep PP:\t"<<party<<"\t"<<time_from(t1)<<endl;

	t1 = clock_start();
	twopc.function_dependent();
	io->flush();
	cout << "func dep PP:\t"<<party<<"\t"<<time_from(t1)<<endl;

	t1 = clock_start();
	twopc.selfgarble_io();
	io->flush();
	cout << "Alice self-garbling IO tables:\t"<<party<<"\t"<<time_from(t1)<<endl;

	bool *in = new bool[max(cf.n1, cf.n2)];
	bool * out = new bool[cf.n3];
	memset(in, false, max(cf.n1, cf.n2));
	memset(out, false, cf.n3);

	t1 = clock_start();
	twopc.handle_input(in);
	io->flush();
	cout << "Handle input:\t"<<party<<"\t"<<time_from(t1)<<endl;

	t1 = clock_start();
	twopc.online();
	io->flush();
	cout << "online:\t"<<party<<"\t"<<time_from(t1)<<endl;

	t1 = clock_start();
	twopc.process_outputs(out);
	if(party == ALICE and check_output.size() > 0){
		printf("ALICE:\n");
		string res = "";
		for(int i = 0; i < cf.n3; ++i)
			res += (out[i]?"1":"0");
		cout << "res: " << res << endl;
		cout << "che: " << hex_to_binary(check_output) << endl;
		cout << (res == hex_to_binary(check_output)? "GOOD!":"BAD!")<<endl;
	}
	/*if(party == BOB){
		printf("BOB:\n");
		string res = "";
		for(int i = 0; i < cf.n3; ++i)
			res += (out[i]?"1":"0");
		cout << "res: " << res << endl;
		cout << "che: " << hex_to_binary(check_output) << endl;
		cout << (res == hex_to_binary(check_output)? "GOOD!":"BAD!")<<endl;
	}*/
	delete[] in;
	delete[] out;
}


void bench(int party, NetIO* io, string name, string check_output = "") {
	string file = name;//circuit_file_location + name;
	CircuitFile cf(file.c_str());
	ofstream outfile;
	if (party == ALICE) outfile.open("ALICE_results_file.txt");
	else if (party == BOB) outfile.open("BOB_results_file.txt");
	else assert(false);
	string run = get_run();

	auto t1 = clock_start();
	C2PC twopc(io, party, &cf);
	io->flush();
	auto t2=time_from(t1);
	outfile << run << ":" << partystr(party) << ":OTS:" << t2 << endl;
	cout << "one time setup:\t"<<party<<"\t" << t2 <<endl;

	t1 = clock_start();
	twopc.function_independent();
	io->flush();
	t2 = time_from(t1);
	outfile << run << ":" << partystr(party) << ":FIPP:" << t2 << endl;
	cout << "indep PP:\t"<<party<<"\t"<< t2 <<endl;

	t1 = clock_start();
	twopc.function_dependent();
	io->flush();
	t2 = time_from(t1);
	outfile << run << ":" << partystr(party) << ":FDPP:" << t2 << endl;
	cout << "func dep PP:\t"<<party<<"\t"<<t2<<endl;

	t1 = clock_start();
	twopc.selfgarble_io();
	io->flush();
	t2 = time_from(t1);
	outfile << run << ":" << partystr(party) << ":SG:" << t2 << endl;
	cout << "Alice self-garbling IO tables:\t"<<party<<"\t"<<t2<<endl;

	bool *in = new bool[max(cf.n1, cf.n2)];
	bool * out = new bool[cf.n3];
	memset(in, false, max(cf.n1, cf.n2));
	memset(out, false, cf.n3);

	t1 = clock_start();
	twopc.handle_input(in);
	io->flush();
	t2 = time_from(t1);
	outfile << run << ":" << partystr(party) << ":INP:" << t2 << endl;
	cout << "Handle input:\t"<<party<<"\t"<<t2<<endl;

	t1 = clock_start();
	twopc.online();
	io->flush();
	t2 = time_from(t1);
	outfile << run << ":" << partystr(party) << ":ON:" << t2 << endl;
	cout << "online:\t"<<party<<"\t"<<t2<<endl;

	t1 = clock_start();
	twopc.process_outputs(out);
	io->flush();
	t2 = time_from(t1);
	outfile << run << ":" << partystr(party) << ":OUT:" << t2 << endl;
	cout << "process output:\t"<<party<<"\t"<<t2<<endl;
	if(party == ALICE and check_output.size() > 0){
		printf("ALICE:\n");
		string res = "";
		for(int i = 0; i < cf.n3; ++i)
			res += (out[i]?"1":"0");
		cout << "res: " << res << endl;
		cout << "che: " << hex_to_binary(check_output) << endl;
		cout << (res == hex_to_binary(check_output)? "GOOD!":"BAD!")<<endl;
	}
	/*if(party == BOB){
		printf("BOB:\n");
		string res = "";
		for(int i = 0; i < cf.n3; ++i)
			res += (out[i]?"1":"0");
		cout << "res: " << res << endl;
		cout << "che: " << hex_to_binary(check_output) << endl;
		cout << (res == hex_to_binary(check_output)? "GOOD!":"BAD!")<<endl;
	}*/
	delete[] in;
	delete[] out;
	outfile.close();
}

