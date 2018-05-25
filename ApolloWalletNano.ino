/**
   @file ApolloWalletNano.ino
   @brief Appllo wallet nano is cryptocurrency hardware wallet.
   @author Shota Moriyasu (shota.moriyasu@gmail.com)
   @author Kazuho Kanahara
   @date 2018/03/05
   @license GNU General Public License v3.0
*/

#include <stdint.h>
#include <RandomGenerator.h>
#include <uECC.h>
#include <uECC_vli.h>
#include <SHA256.h>
#include <Crypto.h>
#include <AES.h>
#include <EEPROM.h>

/***********************************
  Using uECC
************************************/
const struct uECC_Curve_t *curve;

/***********************************
  Using deterministicSign function
************************************/
SHA256 deterministicSignSHA256;

typedef struct SHA256_CTX {
  uint32_t state[8];
  uint64_t bitcount;
  uint8_t buffer[64];
} SHA256_CTX;

typedef struct SHA256_HashContext {
  uECC_HashContext uECC;
  SHA256_CTX ctx;
} SHA256_HashContext;

static void initDeterministicSignSHA256(const uECC_HashContext *base) {
  deterministicSignSHA256.reset();
}

static void updateDeterministicSignSHA256(const uECC_HashContext *base, const uint8_t *message, uint16_t message_size) {
  deterministicSignSHA256.update(message, message_size);
}

static void finishDeterministicSignSHA256(const uECC_HashContext *base, uint8_t *hash_result) {
  deterministicSignSHA256.finalize(hash_result, 32);
}

/***********************************
  Functions
************************************/
/**
  Compute uncompress public key
  @input privateKey: Private key (32Bytes)
         publicKey : Public key (64Bytes)
  @return 0: OK
          1: Failed
*/
int8_t computeUncompressPublicKey(const uint8_t (&privateKey)[32], uint8_t (&publicKey)[64]) {
  // Public key
  if (!uECC_compute_public_key(privateKey, publicKey, curve)) {
    // Failed
    return 1;
  }

  // Validate
  if (!uECC_valid_public_key(publicKey, curve)) {
    // Failed
    return 1;
  }

  return 0;
}

/**
  Compute compress public key
  @input privateKey: Private key (32Bytes)
         publicKey : Public key (33Bytes)
  @return 0: OK
          1: Failed
*/
int8_t computePublicKey(const uint8_t (&privateKey)[32], uint8_t (&publicKey)[33]) {
  uint8_t uncompressPublicKey[64];

  // Public key
  if (computeUncompressPublicKey(privateKey, uncompressPublicKey)) {
    // Failed
    return 1;
  }

  // Compress
  uECC_compress(uncompressPublicKey, publicKey, curve);

  return 0;
}

/**
  Compute HASH256
  HASH256 = SHA256(SHA256(data))
  @input data      : Source data
         sizeOfData: Size of source data
  @output hash256: Hash of HASH256 (32Bytes)
*/
void computeHASH256(const uint8_t *data, const uint16_t sizeOfData, uint8_t (&hash256)[32]) {
  computeSHA256(data, sizeOfData, hash256);
  computeSHA256(hash256, 32, hash256);
}

/**
  Compute SHA256
  @input data      : Source data
         sizeOfData: Size of source data
  @output hash: Hash of SHA256 (32Bytes)
*/
void computeSHA256(const uint8_t *data, const uint16_t sizeOfData, uint8_t (&hash)[32]) {
  SHA256 sha256;

  sha256.reset();
  sha256.update(data, sizeOfData);
  sha256.finalize(hash, 32);
}

/**
  Deterministic sign
  @input privateKey: Private key (32Bytes)
         publicKey : Public key (33Bytes)
         unsignedData: Unsigned Data (32Bytes)
                       Bitcoin transaction is HASH256.
  @output signature: Deterministic signature (64Bytes)
  @return 0: OK
          1: NG
*/
int8_t deterministicSign(const uint8_t (&privateKey)[32], const uint8_t (&publicKey)[33], const uint8_t (&unsignedData)[32], uint8_t (&signature)[64]) {
  uint8_t tmp[128];
  SHA256_HashContext ctx = {{&initDeterministicSignSHA256, &updateDeterministicSignSHA256, &finishDeterministicSignSHA256, 64, 32, tmp}};

  if (!uECC_sign_deterministic(privateKey, unsignedData, sizeof(unsignedData), &ctx.uECC, signature, curve)) {
    // Failed
    return 1;
  }

  return 0;
}

/**
  Encrypt private key (AES256)
  @input privateKey   : Private key (32Bytes)
         encryptionKey: Encryption key (32Bytes)
  @output encryptPrivateKey: Encrypt private key (32Bytes)
*/
void encryptPrivateKeyWithAES256(const uint8_t (&privateKey)[32], const uint8_t (&encryptionKey)[32], uint8_t (&encryptPrivateKey)[32]) {
  AES256 aes256;

  aes256.setKey(encryptionKey, aes256.keySize());
  aes256.encryptBlock(encryptPrivateKey, privateKey);
  aes256.encryptBlock(encryptPrivateKey + 16, privateKey + 16);
}

/**
  Decrypt private key (AES256)
  @input encryptPrivateKey: Encrypt private key (32Bytes)
         encryptionKey    : Encryption key (32Bytes)
  @output privateKey: Private key (32Bytes)
*/
void decryptPrivateKeyWithAES256(const uint8_t (&encryptPrivateKey)[32], const uint8_t (&encryptionKey)[32], uint8_t (&privateKey)[32]) {
  AES256 aes256;

  aes256.setKey(encryptionKey, aes256.keySize());
  aes256.decryptBlock(privateKey, encryptPrivateKey);
  aes256.decryptBlock(privateKey + 16, encryptPrivateKey + 16);
}

/**
  Receive 32Bytes Data
  @output data: Receive data (32Bytes)
*/
void receive32BytesData(uint8_t(&data)[32]) {
  uint8_t c = 0;
  while(c < 32){
    if (Serial.available() > 0) {
      data[c] = Serial.read();
      c++;
    }
  }
}

/**
  Hex data serial print
  @input data      : Data
         sizeOfData: Size of data
*/
void hexSerialPrint(const uint8_t *data, const uint16_t sizeOfData) {
  for (uint16_t i = 0; i < sizeOfData; i++) {
    Serial.write("0123456789ABCDEF"[data[i] >> 4]);
    Serial.write("0123456789ABCDEF"[data[i] & 0xf]);
  }
  Serial.println();
  Serial.flush();
}

/***********************************
  Global variables
************************************/
/*
  Encrypt private key
*/
uint8_t _encryptPrivateKey[32];

/*
  Public key
*/
uint8_t _publicKey[33];

/***********************************
  Main function
************************************/
void setup() {
  // Initialize serial
  Serial.begin(115200);

  // Initialize random generator
  initRandomGenerator();

  // Initialize uECC
  curve = uECC_secp256k1();

  // All reset
  // Short circuit D12
  pinMode(12, INPUT_PULLUP);
  if (digitalRead(12) == LOW) {
    Serial.println(F("Reset"));
    Serial.flush();
    for (uint16_t i = 0; i < EEPROM.length(); i++) {
      EEPROM.write(i, 0);
    }
  }

  // Initial state
  if (EEPROM.read(0) == 0) {
    uint8_t privateKey[32];
    uint8_t encryptionKey[32];

    // Generate normal private key
    // Generate normal public key
    do {
      for (uint8_t i = 0; i < 32; i++) {
        privateKey[i] = generateRandom();
      }
    } while (computePublicKey(privateKey, _publicKey) != 0);

    // Receive encryption key
    // EncryptionKey = SHA256(Password)
    Serial.println(F("[INPUT]NewEncryptionKey"));
    Serial.flush();
    receive32BytesData(encryptionKey);

    // Encrypt private key
    encryptPrivateKeyWithAES256(privateKey, encryptionKey, _encryptPrivateKey);

    // Write encrypt private key to EEPROM
    // Address: 1 - 32
    for (uint8_t i = 0; i < 32; i++) {
      EEPROM.write(i + 1, _encryptPrivateKey[i]);
    }

    // Write public key to EEPROM
    // Address: 33 - 65
    for (uint8_t i = 0; i < 33; i++) {
      EEPROM.write(i + 33, _publicKey[i]);
    }

    // Output encrypt private key
    Serial.println(F("[OUTPUT]Backup"));
    Serial.flush();
    hexSerialPrint(_encryptPrivateKey, 32);

    // Rewrite initial state flag
    // Address: 0
    EEPROM.write(0, 1);
  }

  // Read Encrypt private key from EEPROM
  // Address: 1 - 32
  // Read public key from EEPROM
  // Address: 33 - 65
  for (uint8_t i = 1; i <= 32; i++) {
    _encryptPrivateKey[i] = EEPROM.read(i);
    _publicKey[i] = EEPROM.read(i + 32);
  }
  _publicKey[i] = EEPROM.read(65);
  
}

void loop() {
  Serial.println(F("[INPUT]SelectActions"));
  Serial.flush();

  while (1) {
    if (Serial.available() > 0) {
      String dataString = Serial.readStringUntil('\r');

      if (!dataString.compareTo("PublicKey")) {
        // Output public key
        Serial.println(F("[OUTPUT]PublicKey"));
        Serial.flush();
        hexSerialPrint(_publicKey, 33);
      } else if (!dataString.compareTo("Sign")) {
        // Sign
        uint8_t encryptionKey[32];
        uint8_t privateKey[32];
        uint8_t unsignedData[32];
        uint8_t signature[64];

        // Receive encryption key
        Serial.println(F("[INPUT]EncryptionKey"));
        Serial.flush();
        receive32BytesData(encryptionKey);

        // Decrypt private key
        decryptPrivateKeyWithAES256(_encryptPrivateKey, encryptionKey, privateKey);

        // Receive unsigned data
        Serial.println(F("[INPUT]UnsignedData"));
        Serial.flush();
        receive32BytesData(unsignedData);

        // Sign
        deterministicSign(privateKey, _publicKey, unsignedData, signature);

        // Output signature
        Serial.println(F("[OUTPUT]Signature"));
        Serial.flush();
        hexSerialPrint(signature, 64);
      } else if (!dataString.compareTo("Backup")) {
        // Output encrypt private key
        Serial.println(F("[OUTPUT]Backup"));
        Serial.flush();
        hexSerialPrint(_encryptPrivateKey, 32);
      } else {
        // Error
        Serial.println(F("Error"));
        Serial.flush();
      }

      break;
    }
  }
}
