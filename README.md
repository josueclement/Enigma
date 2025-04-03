# Enigma

Enigma is a .NET cryptography library based on `BouncyCastle.Cryptography`.

## Acknowledgements

Thanks to the BouncyCastle team for their outstanding work on `BouncyCastle.Cryptography`, which made this project possible.

[GitHub repository](https://github.com/bcgit/bc-csharp)

[Official website](https://www.bouncycastle.org/download/bouncy-castle-c/)

---

## Block ciphers

Classes :

- `BlockCipherService`: Service for encryption/decryption with block ciphers
- `BlockCipherServiceFactory`: IBlockCipherService factory
- `BlockCipherEngineFactory`: IBlockCipher factory
- `BlockCipherPaddingFactory`: IBlockCipherPadding factory

Create block cipher service with algorithm name :

```csharp
// AES-CBC without padding
var service = new BlockCipherService("AES/CBC/NoPadding");

// AES-CBC with PKCS7 padding
var service = new BlockCipherService("AES/CBC/PKCS7Padding");
```

Create block cipher service with factories :

```csharp
// AES-CBC without padding
var engineFactory = new BlockCipherEngineFactory();
var service = new BlockCipherServiceFactory().CreateCbcService(engineFactory.CreateAesEngine);

// AES-CBC with PKCS7 padding
var engineFactory = new BlockCipherEngineFactory();
var paddingFactory = new BlockCipherPaddingFactory();
var service = new BlockCipherServiceFactory().CreateCbcService(engineFactory.CreateAesEngine, paddingFactory.CreatePkcs7Padding);
```

Full example :

```csharp
// Create a block cipher service for AES/CBC/PKCS7Padding
var service = new BlockCipherService("AES/CBC/PKCS7Padding");

// Get the key and IV sizes
var (keySizeInBytes, ivSizeInBytes) = service.GetKeyIvSize();

// Generate random key and iv
var key = RandomUtils.GenerateRandomBytes(keySizeInBytes);
var iv = RandomUtils.GenerateRandomBytes(ivSizeInBytes);
var parameters = new ParametersWithIV(new KeyParameter(key), iv);

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
// Create a stream cipher service for ChaCha7539
var service = new StreamCipherServiceFactory().CreateChaCha7539Service();

// Get the key and nonce sizes
var (keySizeInBytes, nonceSizeInBytes) = service.GetKeyNonceSize();

// Generate random key and nonce
var key = RandomUtils.GenerateRandomBytes(keySizeInBytes);
var nonce = RandomUtils.GenerateRandomBytes(nonceSizeInBytes);

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