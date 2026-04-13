#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <openssl/des.h>
using namespace std;

// Convert 16-bit salt to hexadecimal
string saltToHex(unsigned short salt) {
    stringstream ss;
    ss << uppercase << hex << setw(4) << setfill('0') << salt;
    return ss.str();
}

// Convert hexadecimal back to number
unsigned short hexToSalt(string s) {
    return (unsigned short)strtoul(s.c_str(), NULL, 16);
}

// Convert the encrypted 8 byte block to hexadecimal
string blockToHex(unsigned char block[8]) {
    stringstream ss;
    ss << uppercase << hex << setfill('0');

    for (int i = 0; i < 8; i++) {
        ss << setw(2) << (int)block[i];
    }

    return ss.str();
}

// Encrypt a password using DES with 16 bit salt for 25 rounds
string encryptPassword(string password, unsigned short salt) {
    DES_cblock key = {0};
    DES_cblock block = {0};
    DES_cblock out;
    DES_key_schedule schedule;

    for (int i = 0; i < 8 && i < (int)password.length(); i++) {
        key[i] = password[i] << 1;
    }

    DES_set_odd_parity(&key);
    DES_set_key_unchecked(&key, &schedule);

    block[0] = (salt >> 8) & 0xFF;
    block[1] = salt & 0xFF;

    for (int i = 0; i < 25; i++) {
        DES_ecb_encrypt(&block, &out, &schedule, DES_ENCRYPT);
        memcpy(block, out, 8);
    }

    return blockToHex((unsigned char*)block);
}

// Generate and save 10 encrypted usernames and passwords in a file
void generatePasswords() {
    string usernames[10] = {
        "user1", "user2", "user3", "user4", "user5",
        "user6", "user7", "user8", "user9", "user10"
    };

    string passwords[10] = {
        "apple123", "orange45", "banana77", "grape999", "melon321",
        "peach888", "mango555", "lemon111", "berry246", "kiwi909"
    };

    ofstream file("passwords.txt");

    for (int i = 0; i < 10; i++) {
        unsigned short salt = rand() % 65536;
        string hash = encryptPassword(passwords[i], salt);
        file << usernames[i] << " " << saltToHex(salt) << " " << hash << endl;
    }

    file.close();
}

// Check if the original password matches the saved encrypted password
bool checkPassword(string username, string password) {
    ifstream file("passwords.txt");
    string savedUser, savedSalt, savedHash;

    while (file >> savedUser >> savedSalt >> savedHash) {
        if (savedUser == username) {
            unsigned short salt = hexToSalt(savedSalt);
            string newHash = encryptPassword(password, salt);
            file.close();
            return newHash == savedHash;
        }
    }

    file.close();
    return false;
}

// Run the program and generate passwords and test user login
int main() {
    srand(time(0));

    generatePasswords();

    cout << "10 encrypted passwords saved in passwords.txt" << endl;

    string username, password;

    cout << "Enter username: ";
    cin >> username;

    cout << "Enter password: ";
    cin >> password;

    if (checkPassword(username, password))
        cout << "Password is valid" << endl;
    else
        cout << "Password is not valid" << endl;

    return 0;
}