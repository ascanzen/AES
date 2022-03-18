// ConsoleApplication1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <vector>
#include <algorithm>

#include "../src/AES.h"
#include "../src/base64.h"

using namespace std;

#define AES128_KEYLEN 16
//填充
unsigned char *PKCS5Padding(string strParams)
{
	int nRaw_size = strParams.size();
	int i = 0, j = nRaw_size / AES128_KEYLEN + 1, k = nRaw_size % AES128_KEYLEN;
	int nPidding_size = AES128_KEYLEN - k;
	unsigned char *szArray;
	szArray = (unsigned char *)malloc(nRaw_size + nPidding_size);
	memcpy(szArray, (unsigned char *)strParams.c_str(), nRaw_size);
	for (int i1 = nRaw_size; i1 < (nRaw_size + nPidding_size); i1++)
	{
		// PKCS5Padding 算法：
		szArray[i1] = nPidding_size;
	}

	// printf("padding size: %d\n", nPidding_size);
	return szArray;
}
unsigned char *PKCS5Padding(unsigned char in[], unsigned int inLen)
{
	return PKCS5Padding(std::string((char *)in, inLen));
}



//https://github.com/SergeyBel/AES
auto aesEncrypt(const std::string &plain,const std::string &key = "Tt5CPXUAUZ2kxn9S") -> std::string
{
	const unsigned int BLOCK_BYTES_LENGTH = 16 * sizeof(unsigned char);

	AES aes(AESKeyLength::AES_128);

	//现在的加密是nopadding的，需要加上PKCS5Padding
	auto padding = PKCS5Padding(plain);
	auto padding_len = AES128_KEYLEN * (plain.length() / AES128_KEYLEN + 1);
	unsigned char *out = aes.EncryptECB(padding, padding_len,(unsigned char *) key.c_str());
	string base64Encrpt = base64_encode(out, padding_len);
	delete[] out;

	return base64Encrpt;
}

auto aesDEncrypt(const std::string &cipher, const std::string &key = "Tt5CPXUAUZ2kxn9S") -> std::string
{
	const unsigned int BLOCK_BYTES_LENGTH = 16 * sizeof(unsigned char);

	AES aes(AESKeyLength::AES_128);
	
	std::string encrypt_str = base64_decode(cipher);
	unsigned char *decrptOut = aes.DecryptECB((unsigned char *)encrypt_str.c_str(), encrypt_str.length(), (unsigned char *)key.c_str());

	// unpad with pkcs5, remove unused charactors
	uint8_t lastASIIC = (uint8_t)decrptOut[encrypt_str.length() - 1];
	auto len = encrypt_str.length() - lastASIIC;
	if (len < 0 || len >= encrypt_str.length())
	{
		printf("AES_ECB_Cipher::decode, fail to decrypt src");
		return std::string("");
	}
	auto plain = std::string((char*)decrptOut,len);
	delete[] decrptOut;
	return plain;
}

//https://github.com/SergeyBel/AES
void AesTest()
{
	const unsigned int BLOCK_BYTES_LENGTH = 16 * sizeof(unsigned char);

	AES aes(AESKeyLength::AES_128);
	//输入是unsigned char ，最好改成std::string

	unsigned char plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
							 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
							 0x12, 0x12, 0x12, 0x12, 0x12, 0x12};

	unsigned char key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
						   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	unsigned char right[] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
							 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};

	std::cout << "input:     ";
	for (int i = 0; i < (int)sizeof(plain); i++)
		printf("0x%02x,", plain[i]);
	printf("\n");

	//现在的加密是nopadding的，需要加上PKCS5Padding
	auto padding = PKCS5Padding(plain, sizeof(plain));
	auto padding_len = AES128_KEYLEN * (sizeof(plain) / AES128_KEYLEN + 1);
	unsigned char *out = aes.EncryptECB(padding, padding_len, key);
	//  unsigned char *out = aes.EncryptECB(plain, BLOCK_BYTES_LENGTH, key);

	string base64Encrpt = base64_encode(out, padding_len);

	cout << "base64Encode :" << base64Encrpt << endl;

	std::string encrypt_str = base64_decode(base64Encrpt);

	unsigned char *decrptOut = aes.DecryptECB((unsigned char *)encrypt_str.c_str(), encrypt_str.length(), key);

	// unpad with pkcs5, remove unused charactors
	uint8_t lastASIIC = (uint8_t)decrptOut[encrypt_str.length() - 1];
	auto len = encrypt_str.length() - lastASIIC;
	if (len < 0 || len >= encrypt_str.length())
	{
		printf("AES_ECB_Cipher::decode, fail to decrypt src");
		return;
	}

	std::cout << "decrptOut: ";
	auto i = encrypt_str.length();
	for (i = 0; i < encrypt_str.length() - lastASIIC; i++)
		printf("0x%02x,", decrptOut[i]);
	printf("\n");

	delete[] decrptOut;
	/* delete[] szDataOut;*/

	delete[] out;
}

int main()
{
	std::cout<< "aesEncrypt(abc,Tt5CPXUAUZ2kxn9S) = " << aesEncrypt("abc") << std::endl;
	std::cout<< "aesDEncrypt((aesEncrypt(abc,Tt5CPXUAUZ2kxn9S)) = " << aesDEncrypt( aesEncrypt("abc"))<< std::endl;

	AesTest();
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started:
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
