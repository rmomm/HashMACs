#include <iostream>
#include <string>
#include <fstream>
#include <random>

#include <cryptopp/ripemd.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

using namespace std;

string getHash(const string& msg) {
    CryptoPP::RIPEMD320 hash;
    string result;

    CryptoPP::StringSource(msg, true,
        new CryptoPP::HashFilter(hash,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(result), false)));

    return result;
}

int findPreimage(const string& msg) {
    string target = getHash(msg).substr(0, 4);

    for (int i = 1; ; i++) {
        string test = msg + to_string(i);
        string hash = getHash(test);

        if (hash.substr(0, 4) == target) {
            return i;
        }
    }
}

string randomMod(const string& msg) {
    static random_device rd;
    static mt19937 gen(rd());

    const string symbols =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "$#@!";

    string mod = msg;

    uniform_int_distribution<int> posDist(0, mod.size() - 1);
    uniform_int_distribution<int> symbolDist(0, symbols.size() - 1);

    int pos = posDist(gen);
    mod[pos] = symbols[symbolDist(gen)];

    return mod;
}

int findRandom(const string& msg, string& foundMsg) {
    string target = getHash(msg).substr(0, 4);

    int counter = 0;
    string curMsg = msg;

    while (true) {
        counter++;

        curMsg = randomMod(curMsg);
        string hash = getHash(curMsg);

        if (hash.substr(0, 4) == target) {
            foundMsg = curMsg;
            return counter;
        }

        if (counter % 10000 == 0) {
            cout << "Random attack: " << counter << " attempts." << endl;
        }
    }
}
int main() {
    ifstream inputFile("input.txt");

    string msg;
    getline(inputFile, msg);
    string bMsg = msg + " birthday";

    inputFile.close();

    string result = getHash(msg);

    string bHash = getHash(bMsg);
    string bTr = bHash.substr(0, 8);

    string tr = result.substr(0, 4);
    int num = findPreimage(msg);

    string foundMsg = msg + to_string(num);
    string foundHash = getHash(foundMsg);
    string foundTruncated = foundHash.substr(0, 4);

    string randomMsg;
    int randomCounter = findRandom(msg, randomMsg);

    ofstream outputFile("results.txt");

    outputFile << "Message: " << msg << endl;
    outputFile << "RIPEMD-320: " << result << endl;
    outputFile << "16-bit hash: " << tr << endl;

    outputFile << endl;

    outputFile << "Birthday attack message:" << endl;
    outputFile << "Message: " << bMsg << endl;
    outputFile << "RIPEMD-320: " << bHash << endl;
    outputFile << "32-bit hash: " << bTr << endl;

    outputFile << endl;

    outputFile << "Sequential preimage attack:" << endl;
    outputFile << "Found number: " << num << endl;
    outputFile << "Attempts: " << num << endl;

    outputFile << endl;

    outputFile << "Random preimage attack:" << endl;
    outputFile << "Attempts: " << randomCounter << endl;

    outputFile.close();


    return 0;
}