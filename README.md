# Enigma

Enigma is a .NET cryptography library based on `BouncyCastle.Cryptography`.

## Acknowledgements

Thanks to the BouncyCastle team for their outstanding work on `BouncyCastle.Cryptography`, which made this project possible.

[GitHub repository](https://github.com/bcgit/bc-csharp)

[Official website](https://www.bouncycastle.org/download/bouncy-castle-c/)

---

## Block ciphers

| Class                     | Description                                                  |
|---------------------------|--------------------------------------------------------------|
| BlockCipherService        | Service for symmetric block cipher encryption/decryption     |
| BlockCipherServiceFactory | Factory class that creates block cipher services with a mode |
| BlockCipherEngineFactory  | Factory class that creates block cipher engines              |

```csharp
// Create a block cipher service for AES-CBC
var engineFactory = new BlockCipherEngineFactory();
var service = new BlockCipherServiceFactory().CreateCbcBlockCipherService(engineFactory.CreateAesEngine);

// Create a PKCS7 padding service
var padding = new PaddingServiceFactory().CreatePkcs7PaddingService();

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
await service.EncryptAsync(inputEnc, outputEnc, parameters, padding);

var encrypted = outputEnc.ToArray();

// Decrypt
using var inputDec = new MemoryStream(encrypted);
using var outputDec = new MemoryStream();
await service.DecryptAsync(inputDec, outputDec, parameters, padding);

var decrypted = outputDec.ToArray();
```

---

## Stream ciphers

| Class                      | Description                                               |
|----------------------------|-----------------------------------------------------------|
| StreamCipherService        | Service for symmetric stream cipher encryption/decryption |
| StreamCipherServiceFactory | Factory class that creates stream cipher services         |

```csharp
// Create a stream cipher service for ChaCha7539
var service = new StreamCipherServiceFactory().CreateChaCha20Rfc7539StreamCipherService();

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

| Class                   | Description                                                        |
|-------------------------|--------------------------------------------------------------------|
| PublicKeyService        | Service for public-key encryption/decryption and signing/verifying |
| PublicKeyServiceFactory | Factory class that creates public-key services                     |

```csharp
// Create RSA public-key service
var service = new PublicKeyServiceFactory().CreateRsaPublicKeyService();

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

| Class         | Description                               |
|---------------|-------------------------------------------|
| Base64Service | Service for base64 encoding/decoding      |
| HexService    | Service for hexadecimal encoding/decoding |

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

| Class              | Description                              |
|--------------------|------------------------------------------|
| HashService        | Hash service                             |
| HashServiceFactory | Factory class that creates hash services |

```csharp
var data = Encoding.UTF8.GetBytes("Data to hash");

// Create SHA3 hash service
var service = new HashServiceFactory().CreateSha3HashService();

// Hash data
using var input = new MemoryStream(data);
var hash = await service.HashAsync(input);
```

---

## KDF

| Class         | Description                                    |
|---------------|------------------------------------------------|
| Pbkdf2Service | Password-based key derivation function service |

```csharp
var service = new Pbkdf2Service();

var salt = new HexService().Decode("5775ada0513d7d7d7316de8d72d1f4d2");

// Generate a 32 bytes key based on a password and salt
var key = service.GenerateKey(size: 32, password: "yourpassword", salt, iterations: 10_000);
```

---

## Padding

| Class                 | Description                                  |
|-----------------------|----------------------------------------------|
| NoPaddingService      | No-padding service                           |
| PaddingService        | Padding service                              |
| PaddingServiceFactory | Factory class that creates a padding service |

```csharp
var data = Encoding.UTF8.GetBytes("Data to pad");

// Create a PKCS7 padding service
var service = new PaddingServiceFactory().CreatePkcs7PaddingService();

// Pad/unpad data with a 16 bytes block size
var padded = service.Pad(data, blockSize: 16);
var unpadded = service.Unpad(padded, blockSize: 16);
```