# Enigma

Enigma is a .NET cryptography library based on `BouncyCastle.Cryptography`.

[Bouncy Castle GitHub repository](https://github.com/bcgit/bc-csharp)

[Bouncy Castle Official website](https://www.bouncycastle.org/download/bouncy-castle-c/)

---

## Block ciphers

### Sizes

| Cipher Name      | Block Size (bits) | Supported Key Size(s) (bits) | Notes                                                                     |
|------------------|-------------------|------------------------------|---------------------------------------------------------------------------|
| AES              | 128               | 128, 192, 256                | Current global standard. Recommended for new applications.                |
| DES              | 64                | 56 (effective)               | Insecure. Broken due to small key size. Do not use.                       |
| 3DES (TripleDES) | 64                | 112, 168 (effective)         | Slow, small block size. Largely superseded by AES. Use with caution.      |
| Blowfish         | 64                | 32 - 448 (variable)          | Older cipher, 64-bit block size can be problematic (Sweet32).             |
| Twofish          | 128               | 128, 192, 256                | AES finalist. Strong, but less widely adopted than AES.                   |
| Serpent          | 128               | 128, 192, 256                | AES finalist. Known for conservative security margin, slower in software. |
| Camellia         | 128               | 128, 192, 256                | ISO/NESSIE/CRYPTREC standard. Similar performance/security to AES.        |
| CAST-128 (CAST5) | 64                | 40 - 128 (variable)          | Used in older PGP/GPG. 64-bit block size limitation.                      |
| IDEA             | 64                | 128                          | Used in older PGP. Patented until ~2012. 64-bit block size limit.         |
| SEED             | 128               | 128                          | South Korean standard.                                                    |
| ARIA             | 128               | 128, 192, 256                | South Korean standard, successor to SEED.                                 |
| SM4              | 128               | 128                          | Chinese national standard.                                                |

Classes :

- `BlockCipherService`: Service for encryption/decryption with block ciphers
- `BlockCipherServiceFactory`: IBlockCipherService factory
- `BlockCipherEngineFactory`: IBlockCipher factory
- `BlockCipherPaddingFactory`: IBlockCipherPadding factory
- `BlockCipherParametersFactory`: ICipherParameters factory

Create block cipher service with algorithm name :

```csharp
var service = new BlockCipherService("AES/CBC/PKCS7Padding");
```

Create block cipher service with algorithm name (no padding) :

```csharp
var service = new BlockCipherService("AES/CBC/NoPadding");
```

Create block cipher service with factories :

```csharp
var engineFactory = new BlockCipherEngineFactory();
var paddingFactory = new BlockCipherPaddingFactory();
var service = new BlockCipherServiceFactory().CreateCbcService(engineFactory.CreateAesEngine, paddingFactory.CreatePkcs7Padding);
```

Create block cipher service with factories (no padding) :

```csharp
var engineFactory = new BlockCipherEngineFactory();
var service = new BlockCipherServiceFactory().CreateCbcService(engineFactory.CreateAesEngine);
```

AES-256 GCM example :

```csharp
// Create block cipher service
var service = new BlockCipherService("AES/GCM");

// Generate random key and iv
var key = RandomUtils.GenerateRandomBytes(32);
var nonce = RandomUtils.GenerateRandomBytes(12);
var parameters = new BlockCipherParametersFactory().CreateGcmParameters(key, nonce, "associated data".GetUtf8Bytes());

var data = "This is a secret message !".GetUtf8Bytes();

// Encrypt
using var inputEnc = new MemoryStream(data);
using var outputEnc = new MemoryStream();
await service.EncryptAsync(inputEnc, outputEnc, parameters);

var encrypted = outputEnc.ToArray();

// Decrypt
using var inputDec = new MemoryStream(encrypted);
using var outputDec = new MemoryStream();
await service.DecryptAsync(inputDec, outputDec, parameters);

var decrypted = outputDec.ToArray();
```

AES-256 CBC example :

```csharp
// Create block cipher service
var service = new BlockCipherService("AES/CBC/PKCS7Padding");

// Generate random key and iv
var key = RandomUtils.GenerateRandomBytes(32);
var iv = RandomUtils.GenerateRandomBytes(16);
var parameters = new BlockCipherParametersFactory().CreateCbcParameters(key, iv);

var data = "This is a secret message !".GetUtf8Bytes();

// Encrypt
using var inputEnc = new MemoryStream(data);
using var outputEnc = new MemoryStream();
await service.EncryptAsync(inputEnc, outputEnc, parameters);

var encrypted = outputEnc.ToArray();

// Decrypt
using var inputDec = new MemoryStream(encrypted);
using var outputDec = new MemoryStream();
await service.DecryptAsync(inputDec, outputDec, parameters);

var decrypted = outputDec.ToArray();
```

---

## Stream ciphers

Classes :

- `StreamCipherService`: Service for encryption/decryption with stream ciphers
- `StreamCipherServiceFactory`: IStreamCipherService factory

Full example :

```csharp
// Create stream cipher service
var service = new StreamCipherServiceFactory().CreateChaCha7539Service();

// Generate random key and nonce
var key = RandomUtils.GenerateRandomBytes(32);
var nonce = RandomUtils.GenerateRandomBytes(12);

var data = "This is a secret message !".GetUtf8Bytes();

// Encrypt
using var inputEnc = new MemoryStream(data);
using var outputEnc = new MemoryStream();
await service.EncryptAsync(inputEnc, outputEnc, key, nonce);

var encrypted = outputEnc.ToArray();

// Decrypt
using var inputDec = new MemoryStream(encrypted);
using var outputDec = new MemoryStream();
await service.DecryptAsync(inputDec, outputDec, key, nonce);

var decrypted = outputDec.ToArray();
```

---

## Public-key

Classes :

- `PublicKeyService`: Service for public-key encryption/decryption and signing/verifying
- `PublicKeyServiceFactory`: IPublicKeyService factory

Full example :

```csharp
// Create RSA public-key service
var service = new PublicKeyServiceFactory().CreateRsaService();

// Generate 4096-bits key pair
var keyPair = service.GenerateKeyPair(4096);

var data = "This is a secret message".GetUtf8Bytes();

// Encrypt/decrypt data
var enc = service.Encrypt(data, keyPair.Public);
var dec = service.Decrypt(enc, keyPair.Private);

// Sign/verify data
var signature = service.Sign(data, keyPair.Private);
var verified = service.Verify(data, signature, keyPair.Public);

// Save public key in PEM format
using var publicOutput = new MemoryStream();
PemUtils.SaveKey(keyPair.Public, publicOutput);

// Save and encrypt private key in PEM format
using var privateOutput = new MemoryStream();
PemUtils.SavePrivateKey(keyPair.Private, privateOutput, "yourpassword", algorithm: "AES-256-CBC");

// Load public key from PEM format
using var publicInput = new MemoryStream(publicOutput.ToArray());
var publicKey = PemUtils.LoadKey(publicInput);

// Load and decrypt private key from PEM format
using var privateInput = new MemoryStream(privateOutput.ToArray());
var privateKey = PemUtils.LoadPrivateKey(privateInput, "yourpassword");
```

---

## Post-Quantum Cryptography (PQC)

Classes :

- `MLDsaService`: Service Module-Lattice-Based digital signature algorithm (ML-DSA)
- `MLDsaServiceFactory`: IMLDsaService factory
- `MLKemService`: Service for Module-Lattice-Based key-encapsulation mechanism (ML-KEM)
- `MLKemServiceFactory`: IMLKemService factory

ML-DSA example :

```csharp
// Create ML-DSA-65 service
var service = new MLDsaServiceFactory().CreateDsa65Service();

// Generate key pair
var keyPair = service.GenerateKeyPair();

var data = "Data to sign".GetUtf8Bytes();

// Sign/verify data
var signature = service.Sign(data, keyPair.Private);
var verified = service.Verify(data, signature, keyPair.Public);

// Save public key in PEM format
using var publicOutput = new MemoryStream();
PemUtils.SaveKey(keyPair.Public, publicOutput);

// Save and encrypt private key in PEM format
using var privateOutput = new MemoryStream();
PemUtils.SavePrivateKey(keyPair.Private, privateOutput, "yourpassword", algorithm: "AES-256-CBC");

// Load public key from PEM format
using var publicInput = new MemoryStream(publicOutput.ToArray());
var publicKey = PemUtils.LoadKey(publicInput);

// Load and decrypt private key from PEM format
using var privateInput = new MemoryStream(privateOutput.ToArray());
var privateKey = PemUtils.LoadPrivateKey(privateInput, "yourpassword");
```

ML-KEM example :

```csharp
// Create ML-KEM-1024 service
var service = new MLKemServiceFactory().CreateKem1024();

// Generate key pair
var keyPair = service.GenerateKeyPair();

// Encapsulate secret key
var (encapsulation, secret) = service.Encapsulate(keyPair.Public);

// Decapsulate secret key
var secretDec = service.Decapsulate(encapsulation, keyPair.Private);

// Save public key in PEM format
using var publicOutput = new MemoryStream();
PemUtils.SaveKey(keyPair.Public, publicOutput);

// Save and encrypt private key in PEM format
using var privateOutput = new MemoryStream();
PemUtils.SavePrivateKey(keyPair.Private, privateOutput, "yourpassword", algorithm: "AES-256-CBC");

// Load public key from PEM format
using var publicInput = new MemoryStream(publicOutput.ToArray());
var publicKey = PemUtils.LoadKey(publicInput);

// Load and decrypt private key from PEM format
using var privateInput = new MemoryStream(privateOutput.ToArray());
var privateKey = PemUtils.LoadPrivateKey(privateInput, "yourpassword");
```

---

## Data encoding

Classes :

- `Base64Service`: Service for base64 encoding/decoding
- `HexService`: Service for hexadecimal encoding/decoding

Full example :

```csharp
var data = "This is some data".GetUtf8Bytes();

// Encode/decode with hex
var hex = new HexService();
var hexEncoded = hex.Encode(data);
var hexDecoded = hex.Decode(hexEncoded);

// Encode/decode with base64
var base64 = new Base64Service();
var base64Encoded = base64.Encode(data);
var base64Decoded = base64.Decode(base64Encoded);
```

With extension methods :

```csharp
var data = "This is some data".GetUtf8Bytes();

// Encode/decode with hex
var hexEncoded = data.ToHexString();
var hexDecoded = hexEncoded.FromHexString();

// Encode/decode with base64
var base64Encoded = data.ToBase64String();
var base64Decoded = base64Encoded.FromBase64String();
```

---

## Hash

Classes :

- `HashService`: Hash service
- `HashServiceFactory`: IHashService factory

Full example :

```csharp
var data = "Data to hash".GetUtf8Bytes();

// Create SHA3 hash service
var service = new HashServiceFactory().CreateSha3Service();

// Hash data
using var input = new MemoryStream(data);
var hash = await service.HashAsync(input);
```

---

## KDF

Classes :

- `Pbkdf2Service`: PBKDF2 service
- `Argon2Service`: Argon2 PBE service

PBKDF2 example :

```csharp
var service = new Pbkdf2Service();

var salt = "5775ada0513d7d7d7316de8d72d1f4d2".FromHexString();

// Generate a 32 bytes key based on a password and salt
var key = service.GenerateKey(size: 32, password: "yourpassword", salt, iterations: 10_000);
```

Argon2 example :

```csharp
var service = new Argon2Service();

var passwordData = "yourpassword".GetUtf8Bytes();
var salt = RandomUtils.GenerateRandomBytes(16);

// Generate a 32 bytes key based on a password and salt
var key = service.GenerateKey(32, passwordData, salt);
```

---

## Padding

Classes :

- `NoPaddingService`: No-padding service
- `PaddingService`: Padding service
- `PaddingServiceFactory`: IPaddingService factory

Full example :

```csharp
var data = "Data to pad".GetUtf8Bytes();

// Create a PKCS7 padding service
var service = new PaddingServiceFactory().CreatePkcs7Service();

// Pad/unpad data with a 16 bytes block size
var padded = service.Pad(data, blockSize: 16);
var unpadded = service.Unpad(padded, blockSize: 16);
```

---

Copyright (c) 2025 Josué Clément