#include <emp-tool/emp-tool.h>
#include "test/single_execution.h"
using namespace std;
using namespace emp;

int main(int argc, char** argv) {
	int party, port;
	parse_party_and_port(argv, &party, &port);
	NetIO* io = new NetIO(party==ALICE ? nullptr:IP, port);
	io->set_nodelay();
	// hack so don't have to constantly `make`
	string torun;
	std::ifstream infile("pbkdf_file.txt");
	getline(infile, torun);
	infile.close();
	bench(party, io, torun);
	delete io;
	return 0;
}
