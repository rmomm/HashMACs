#include <iostream>
#include <string>
#include <fstream>
#include <random>
#include <unordered_map>
#include <vector>

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

string get16BitHash(const string& hash) {
    return hash.substr(hash.size() - 4);
}

string get32BitHash(const string& hash) {
    return hash.substr(hash.size() - 8);
}


int findPreimage(const string& msg, ofstream& outputFile) {
    string target = get16BitHash(getHash(msg));

    for (int i = 1; ; i++) {
        string test = msg + to_string(i);
        string hash = getHash(test);

        if (i <= 30) {
            outputFile << i << ": " << test << endl;
            outputFile << "Hash: " << hash << endl;
        }

        if (get16BitHash(hash) == target) {
            if (i > 30) {
                outputFile << "..." << endl;
                outputFile << i << ": " << test << endl;
                outputFile << "Hash: " << hash << endl;
            }

            return i;
        }
    }
}

int findPreimageAttempts(const string& msg) {
    string target = get16BitHash(getHash(msg));

    for (int i = 1; ; i++) {
        string test = msg + to_string(i);
        string hash = getHash(test);

        if (get16BitHash(hash) == target) {
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
    string target = get16BitHash(getHash(msg));

    int counter = 0;
    string curMsg = msg;

    while (true) {
        counter++;

        curMsg = randomMod(curMsg);
        string hash = getHash(curMsg);

        if (get16BitHash(hash) == target) {
            foundMsg = curMsg;
            return counter;
        }

        if (counter % 10000 == 0) {
            cout << "Random attack: " << counter << " attempts." << endl;
        }
    }
}

string randomMsg(const string& msg) {
    static random_device rd;
    static mt19937 gen(rd());

    const string symbols =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";

    string result = msg + "_";

    uniform_int_distribution<int> symbolDist(0, symbols.size() - 1);

    for (int i = 0; i < 10; i++) {
        result += symbols[symbolDist(gen)];
    }

    return result;
}

int findBirthday(const string& msg, string& msg1, string& msg2, string& colHash) {
    unordered_map<string, string> hashes;

    for (int i = 1; ; i++) {
        string test = msg + to_string(i);
        string hash = get32BitHash(getHash(test));

        if (hashes.count(hash)) {
            msg1 = hashes[hash];
            msg2 = test;
            colHash = hash;

            return i;
        }

        hashes[hash] = test;
    }
}

int findRandomBirthday(const string& msg, string& msg1, string& msg2, string& colHash) {
    unordered_map<string, string> hashes;

    int counter = 0;

    while (true) {
        counter++;

        string curMsg = randomMsg(msg);
        string hash = get32BitHash(getHash(curMsg));

        if (hashes.count(hash)) {
            if (hashes[hash] != curMsg) {
                msg1 = hashes[hash];
                msg2 = curMsg;
                colHash = hash;

                return counter;
            }
        }
        else {
            hashes[hash] = curMsg;
        }

        if (counter % 10000 == 0) {
            cout << "Random birthday attack: " << counter << " attempts." << endl;
        }
    }
}

int main() {
    ifstream inputFile("input.txt");

    string msg;
    getline(inputFile, msg);
    string bMsg = msg + " birthday";

    inputFile.close();

    string hash = getHash(msg);

    string bHash = getHash(bMsg);
    string bTr = get32BitHash(bHash);

    string tr = get16BitHash(hash);

    ofstream preimageFile("pr.txt");

    int num = findPreimage(msg, preimageFile);

    preimageFile.close();;

    string randomMsg;
    int randomCounter = findRandom(msg, randomMsg);

    string msg1, msg2, colHash;
    int birthdayCounter = findBirthday(bMsg, msg1, msg2, colHash);

    string rMsg1, rMsg2, rColHash;
    int randomBirthdayCounter = findRandomBirthday(bMsg, rMsg1, rMsg2, rColHash);

    ofstream outputFile("results.txt");

    outputFile << "Message: " << msg << endl;
    outputFile << "RIPEMD-320: " << hash << endl;
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

    outputFile << endl;

    outputFile << "Sequential birthday attack:" << endl;
    outputFile << "Message 1: " << msg1 << endl;
    outputFile << "Message 2: " << msg2 << endl;
    outputFile << "32-bit hash: " << colHash << endl;
    outputFile << "Attempts: " << birthdayCounter << endl;

    outputFile << endl;
    outputFile << "Random birthday attack:" << endl;
    outputFile << "Message 1: " << rMsg1 << endl;
    outputFile << "Message 2: " << rMsg2 << endl;
    outputFile << "32-bit hash: " << rColHash << endl;
    outputFile << "Attempts: " << randomBirthdayCounter << endl;

    outputFile.close();


    return 0;
}