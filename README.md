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

var data = Encoding.UTF8.GetBytes("This is a secret message !");

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

var data = Encoding.UTF8.GetBytes("This is a secret message !");

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

var data = Encoding.UTF8.GetBytes("This is a secret message");

// Encrypt/decrypt data
var enc = service.Encrypt(data, keyPair.Public);
var dec = service.Decrypt(enc, keyPair.Private);

// Sign/verify data
var signature = service.Sign(data, keyPair.Private);
var verified = service.Verify(data, signature, keyPair.Public);

// Save public key in PEM format
using var publicOutput = new MemoryStream();
service.SaveKey(keyPair.Public, publicOutput);

// Save and encrypt private key in PEM format
using var privateOutput = new MemoryStream();
service.SavePrivateKey(keyPair.Private, privateOutput, "yourpassword", algorithm: "AES-256-CBC");

// Load public key from PEM format
using var publicInput = new MemoryStream(publicOutput.ToArray());
var publicKey = service.LoadKey(publicInput);

// Load and decrypt private key from PEM format
using var privateInput = new MemoryStream(privateOutput.ToArray());
var privateKey = service.LoadPrivateKey(privateInput, "yourpassword");
```

---

## Data encoding

Classes :

- `Base64Service`: Service for base64 encoding/decoding
- `HexService`: Service for hexadecimal encoding/decoding

Full example :

```csharp
var data = Encoding.UTF8.GetBytes("This is some data");

// Encode/decode with hex
var hex = new HexService();
var hexEncoded = hex.Encode(data);
var hexDecoded = hex.Decode(hexEncoded);

// Encode/decode with base64
var base64 = new Base64Service();
var base64Encoded = base64.Encode(data);
var base64Decoded = base64.Decode(base64Encoded);
```

---

## Hash

Classes :

- `HashService`: Hash service
- `HashServiceFactory`: IHashService factory

Full example :

```csharp
var data = Encoding.UTF8.GetBytes("Data to hash");

// Create SHA3 hash service
var service = new HashServiceFactory().CreateSha3Service();

// Hash data
using var input = new MemoryStream(data);
var hash = await service.HashAsync(input);
```

---

## KDF

Classes :

- `Pbkdf2Service`: Password-based key derivation function service

Full example :

```csharp
var service = new Pbkdf2Service();

var salt = new HexService().Decode("5775ada0513d7d7d7316de8d72d1f4d2");

// Generate a 32 bytes key based on a password and salt
var key = service.GenerateKey(size: 32, password: "yourpassword", salt, iterations: 10_000);
```

---

## Padding

Classes :

- `NoPaddingService`: No-padding service
- `PaddingService`: Padding service
- `PaddingServiceFactory`: IPaddingService factory

Full example :

```csharp
var data = Encoding.UTF8.GetBytes("Data to pad");

// Create a PKCS7 padding service
var service = new PaddingServiceFactory().CreatePkcs7Service();

// Pad/unpad data with a 16 bytes block size
var padded = service.Pad(data, blockSize: 16);
var unpadded = service.Unpad(padded, blockSize: 16);
```