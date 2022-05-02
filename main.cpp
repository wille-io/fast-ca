#include <botan/x509_ca.h>
#include <botan/x509cert.h>
#include <botan/x509self.h>
#include <botan/rsa.h>
#include <botan/pk_keys.h>
#include <botan/bigint.h>
#include <botan/auto_rng.h>
#include <botan/pubkey.h> // bug: botan 2.12.1 does a sizeof for (undefined) PK_Signer when using X509CA
#include <botan/pkcs8.h>
#include <botan/hex.h>

#include <sys/stat.h> // mkdir
#include <stdio.h>
#include <string>
#include <memory>
#include <vector>
#include <unistd.h> // grr.. not portable
#include <termios.h> // blank pwd / echo on/off
#include <iostream>


using namespace Botan;
termios t;


void echoRestore()
{
  tcsetattr(STDIN_FILENO, TCSANOW, &t);
}


void echoOff()
{
  termios _t;
  tcgetattr(STDIN_FILENO, &_t);
  t = _t;

  _t.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSAFLUSH, &_t);
}


int main(int argc, char **argv)
{
  puts("fast-ca");
  std::string pwd;
  std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
  std::string caKeyFilename = "./ca.pem";
  std::string caCrtFilename = "./ca.crt";
  std::string taKeyFilename = "./ta.key";

  if (access(caKeyFilename.c_str(), F_OK) == -1)
  {
    // if there is no ca.pem, fast-ca hasn't created the CA yet, generate it:
    puts("No CA found - creating new CA");

    AutoSeeded_RNG rng;

    puts("Creating root keys ...");
    RSA_PrivateKey rootCertPrivKey(rng, 4096);


    // ask for a password to encrypt the private key for the CA
    bool askForPwd = true;
    while (askForPwd)
    {
      printf("> Enter a secure password for encrypting the CA's private keys: ");

      echoOff();
      std::cin >> pwd;
      echoRestore();
      printf("\n");

      if (pwd.length() < 3)
      {
        puts("Password too short!");
        continue;
      }

      printf("> Repeat the password: ");

      std::string pwd2;
      echoOff();
      std::cin >> pwd2;
      echoRestore();
      printf("\n");

      if (pwd != pwd2)
      {
        puts("> Passwords do not match!");
        continue;
      }

      askForPwd = false;
    }

    //std::cerr << "pwd: '" << pwd << "'" << std::endl;


    // encrypt the private key and write it to disk
    std::string rootCertPrivKeyString = PKCS8::PEM_encode(rootCertPrivKey, rng, pwd);    
    FILE *f = fopen(caKeyFilename.c_str(), "w");

    if (!f)
    {
      puts("writing root keys failed!");
      return -1;
    }

    fwrite(rootCertPrivKeyString.data(), 1, rootCertPrivKeyString.size(), f);
    fclose(f);

    
    // generate the certificate from the CA's private keys, with these options:
    X509_Cert_Options opts("", 10 * 365 * 24 * 60 * 60);
    opts.common_name = "fast-ca Root Certificate";
    opts.add_constraints(Key_Constraints::DIGITAL_SIGNATURE);
    opts.add_ex_constraint("PKIX.ServerAuth");
    opts.add_ex_constraint("PKIX.ClientAuth");
    opts.CA_key(1);

    puts("Creating root certificate ...");
    X509_Certificate rootCert = X509::create_self_signed_cert(opts, rootCertPrivKey, "SHA-256", rng);

    puts("Writing root certificate ...");
    std::string rootCertData(rootCert.PEM_encode());
    f = fopen(caCrtFilename.c_str(), "w");

    if (!f)
    {
      puts("Writing CA certificate failed!");
      return -1;
    }

    fwrite(rootCertData.data(), 1, rootCertData.size(), f);
    fclose(f);


    // generate ta static key file
    puts("Creating ta static key file");

    const auto taKeyData = rng.random_vec(256); // 2048 bit random key
    std::string taKeyString = Botan::hex_encode(taKeyData);

    for (int i = 0; i < 16; i++)
      taKeyString.insert(i * 32 + i, "\n");

    taKeyString.insert(0,
      "# 2048 bit OpenVPN static key\n"
      "-----BEGIN OpenVPN Static key V1-----");

    taKeyString.append("\n-----END OpenVPN Static key V1-----");

    f = fopen(taKeyFilename.c_str(), "w");

    if (!f)
    {
      puts("Writing TA static key file failed!");
      return -1;
    }

    fwrite(taKeyString.data(), 1, taKeyString.size(), f);
    fclose(f);

    puts("CA initialized");
  }
  else
  {
    puts("CA available");
  }


  if (argc < 2)
  {
    printf("usage: %s <fqdn>\n", argv[0]);
    return -1;
  }


  puts("Loading CA certificate ...");
  X509_Certificate caCert = X509_Certificate(caCrtFilename);
  AutoSeeded_RNG rng;


  puts("Loading CA keys ...");
  Private_Key *caPrivKey = nullptr;  

  bool askForPwd = pwd.empty(); // only ask for the password if the user didn't enter it yet
  while (askForPwd)
  {
    printf("> Enter the CA's private key's password: ");

    echoOff();
    std::cin >> pwd;
    echoRestore();
    printf("\n");

    if (pwd.length() < 3)
      puts("Password too short!");
    else
    {
      try
      {
        caPrivKey = PKCS8::load_key(caKeyFilename, rng, pwd);
      }
      catch(...)
      {
        puts("CA keys couldn't be unlocked with the given password!");
        continue;
      }

      askForPwd = false;
    }
  }

  if (!askForPwd)
  {
    try
    {
      caPrivKey = PKCS8::load_key(caKeyFilename, rng, pwd);
    }
    catch(...)
    {
      puts("CA keys couldn't be unlocked with the given password!");
      return -1;
    }
  }


  puts("Initializing CA ...");
  X509_CA ca = X509_CA(caCert, *caPrivKey, "SHA-256", rng);
  // TODO: free caPrivKey


  puts("Creating client keys ...");
  RSA_PrivateKey privKey = RSA_PrivateKey(rng, 4096);
  std::string fqdn(argv[1]);
  std::string privKeyData = PKCS8::PEM_encode(privKey);
  int status = mkdir(argv[1], S_IRWXU | S_IRWXG);
  
  if (status == -1)
  {
    puts("Could not create directory for client certificate!");
    return -1;
  }

  std::string privKeyDataPath("./" + fqdn + "/" + fqdn + ".pem");
  FILE *f = fopen(privKeyDataPath.c_str(), "w");

  if (!f)
  {
    puts("Writing client keys failed!");
    return -1;
  }
  
  puts("Writing client keys ...");
  fwrite(privKeyData.data(), 1, privKeyData.size(), f);
  fclose(f);


  puts("Creating client certificate request ...");
  X509_Cert_Options opts("");  
  opts.common_name = fqdn;
  opts.dns = fqdn;
  opts.add_constraints(Key_Constraints::DIGITAL_SIGNATURE);
  opts.add_ex_constraint("PKIX.ServerAuth");
  opts.add_ex_constraint("PKIX.ClientAuth");
  PKCS10_Request request = X509::create_cert_req(opts, privKey, "SHA-256", rng);


  puts("Creating client certificate ...");
  X509_Certificate cert = ca.sign_request(request, rng, X509_Time(now), 
#if __cplusplus > 201703L // std::chrono::years only available in c++20
                                          X509_Time(now + std::chrono::years(10))); // create a certificate that is valid from now, for 10 years
#else                                          
                                          X509_Time(now + std::chrono::hours(87660))); // create a certificate that is valid from now, for 10 years (87.660 hours)
#endif
  
  
  
  std::string certData = cert.PEM_encode();
  std::string certDataPath("./" + fqdn + "/" + fqdn + ".crt");
  f = fopen(certDataPath.c_str(), "w");

  if (!f)
  {
    puts("Writing client certificate failed!");
    return -1;
  }
  
  puts("Writing client certificate ...");
  fwrite(certData.data(), 1, certData.size(), f);
  fclose(f);
  puts("Done!");

  return 0;
}
