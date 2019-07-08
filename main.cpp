#include "Sha256.h"

#include <iostream>

int main()
{
	unsigned char abc[4] = "abc";
	unsigned char abcd[57] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	SHA256Hash H1 = SHA256(abc, 3);
	SHA256Hash H2 = SHA256Read("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	SHA256Hash H3 = SHA256(abcd, 56);
	SHA256Hash H4 = SHA256Read("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
	if (H3 == H4)
	{
		std::cout << "Worked\n";
		H1.print();
		std::cout << "\n";
		H2.print();
	}
	else
	{
		std::cout << "Did not Work\n";
		H1.print();
		std::cout << "\n";
		H2.print();
	}
	std::cin.ignore();
	return 0;
}