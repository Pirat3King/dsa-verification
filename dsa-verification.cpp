// ---------------------------------------------------------------------------
// Project: DSA Verification
// Description: Demonstrates the security of DSA signatures and the verification
//              algorithm by attempting to sign two different hashes with the same
//              signature.
// Author: Pirat3King
// Date: 2023-04-17
// ---------------------------------------------------------------------------

#include <boost/multiprecision/cpp_int.hpp> //Allows large integers >64 bits
#include <iostream>


using namespace boost::multiprecision;

// ---------------------------------------------------------------------------
// Function Prototypes
// ---------------------------------------------------------------------------

void printBanner();
void readInput(cpp_int& p, cpp_int& q, cpp_int& h, cpp_int& x, 
    cpp_int& k, cpp_int& hm1, cpp_int& hm2);
cpp_int modExp(cpp_int b, cpp_int e, cpp_int m);
cpp_int pow(cpp_int b, cpp_int e);
cpp_int modInverse(cpp_int a, cpp_int m);
bool verifySignature(cpp_int p, cpp_int q, cpp_int g, cpp_int y, cpp_int r, 
    cpp_int s, cpp_int hash, cpp_int& w, cpp_int& u1, cpp_int& u2, cpp_int& v);

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main()
{
    cpp_int p = 0, q = 0, h = 0, x = 0, k = 0, hash1 = 0, hash2 = 0; //user provided
    cpp_int g = 0, y = 0, r = 0, s = 0, w = 0, u1 = 0, u2 = 0, v = 0; //caluclated
    bool verified;

    printBanner();
    readInput(p, q, h, x, k, hash1, hash2);

    //Calculate g value and public key.
    cpp_int temp = (p - 1) / q;

    g = modExp(h, temp, p);
    y = modExp(g, x, p);

    std::cout << "\n----------------------Output----------------------\n\n"
              << "g: " << g << "\n"
              << "y: " << y << std::endl;
    
    //Calculate signature r,s
    cpp_int k_inv = modInverse(k, q);

    r = (modExp(g, k, p)) % q;
    s = (k_inv * (hash1 + x * r)) % q;

    //Check for valid signature
    if (r < 1 || s < 1)
    {
        std::cout << "Invalid signature. Choose a different nonce k." << std::endl;
        return -1;
    }

    std::cout << "r: " << r << "\n"
              << "s: " << s << std::endl;

    //Confirm that hash1 signature is valid for hash1
    verified = verifySignature(p, q, g, y, r, s, hash1, w, u1, u2, v);

    std::cout << "\nH(M1):\n"
              << "w: " << w << "\n"
              << "u1: " << u1 << "\n"
              << "u2: " << u2 << "\n"
              << "v: " << v << "\n"
              << "v == r: " << std::boolalpha << verified << std::endl;

    //Confirm that hash1 signature is not valid for hash2
    verified = verifySignature(p, q, g, y, r, s, hash2, w, u1, u2, v);

    std::cout << "\nH(M2):\n"
              << "w: " << w << "\n"
              << "u1: " << u1 << "\n"
              << "u2: " << u2 << "\n"
              << "v: " << v << "\n"
              << "v == r: " << std::boolalpha << verified << std::endl;

    return 0;
}

// ---------------------------------------------------------------------------
// Function Definitions
// ---------------------------------------------------------------------------

//Display banner
void printBanner()
{
    std::cout << "---------------------------------------------------\n"
              << "            DSA Signature Verification             \n"
              << "---------------------------------------------------\n" << std::endl;
}

//Prompt and read user input
void readInput(cpp_int& p, cpp_int& q, cpp_int& h, cpp_int& x, 
    cpp_int& k, cpp_int& hash1, cpp_int& hash2)
{
    std::cout << "Please input the following values:\n\n"
                 "p: ";
    std::cin >> p;

    std::cout << "q: ";
    std::cin >> q;

    std::cout << "h: ";
    std::cin >> h;

    std::cout << "x: ";
    std::cin >> x;

    std::cout << "k: ";
    std::cin >> k;

    std::cout << "H(M1) (real hash): ";
    std::cin >> hash1;

    std::cout << "H(M2) (fake hash): ";
    std::cin >> hash2;
}

//Modular exponentiation. Returns x such that b^e mod m = x
cpp_int modExp(cpp_int b, cpp_int e, cpp_int m)
{
    cpp_int x = 1;

    b %= m; // update b if >= m 

    while (e > 0)
    {
        if (e % 2 == 1) //exponent is odd
            x = (x * b) % m;

        b = (b * b) % m;
        e = e / 2;
    }

    return x;
}

//Binary Extended Euclidian Algorithm to find the modular 
//multiplicative inverse x: ax = 1 (mod m) 
cpp_int modInverse(cpp_int a, cpp_int m)
{
    cpp_int m0 = m;
    cpp_int y = 0, x = 1; //Bezout coefficients

    if (m == 1)
        return 0;

    while (a > 1) //continue until a and m are coprime (a = 1)
    {
        cpp_int q = a / m; //quotient
        cpp_int t = m;

        //m is remainder now
        m = a % m;

        //swaps
        a = t;
        t = y;

        // Update x and y
        y = x - q * y;
        x = t;
    }

    //If a == gcd(a,m) != 1, then no inverse exists
    if (a != 1)
        return 0;

    // Make x positive
    if (x < 0)
        x += m0;

    return x;
}

//Verify signature given a hash value 'hash'
bool verifySignature(cpp_int p, cpp_int q, cpp_int g, cpp_int y, cpp_int r, 
    cpp_int s, cpp_int hash, cpp_int& w, cpp_int& u1, cpp_int& u2, cpp_int& v)
{
    w = modInverse(s, q);

    u1 = (hash * w) % q;
    u2 = (r * w) % q;
    
    // v = ((g^u1 * y^u2) mod p) mod q
    cpp_int t1 = pow(g, u1);
    cpp_int t2 = pow(y, u2);
    
    v = ((t1 * t2) % p) % q;

    return (v == r);
}

//Exponentiation by squaring
cpp_int pow(cpp_int b, cpp_int e)
{
    cpp_int x = 1;

    while (e > 0)
    {
        if (e % 2 == 1) //exponent is odd
            x = x * b;

        b = b * b;
        e = e / 2;
    }

    return x;
}