using System.Collections.Generic;
using Enigma.Extensions;
using Enigma.KDF;

namespace UnitTests.KDF;

public class Argon2IdTests
{
    [Theory]
    [MemberData(nameof(GetTestValues))]
    public void KeyGenerationTest(
        int size,
        byte[] passwordBytes,
        byte[] salt,
        int iterations,
        int parallelism,
        int memoryPowOfTwo,
        byte[] expectedKey)
    {
        var service = new Argon2Service();
        var key = service.GenerateKey(
            size: size,
            passwordBytes: passwordBytes,
            salt: salt,
            iterations: iterations,
            parallelism: parallelism,
            memoryPowOfTwo: memoryPowOfTwo);
        Assert.Equal(expectedKey, key);
    }
    
    public static IEnumerable<object[]> GetTestValues()
    {
        yield return
        [
            32, // size
            "0101010101010101010101010101010101010101010101010101010101010101".FromHexString(), // password
            "02020202020202020202020202020202".FromHexString(), // salt
            3, // iterations
            4, // parallelism
            5, // memoryPowOfTwo
            "03aab965c12001c9d7d0d2de33192c0494b684bb148196d73c1df1acaf6d0c2e".FromHexString() // expected key
        ];
        
        yield return
        [
            32, // size
            "".FromHexString(), // password
            "02020202020202020202020202020202".FromHexString(), // salt
            3, // iterations
            4, // parallelism
            5, // memoryPowOfTwo
            "0a34f1abde67086c82e785eaf17c68382259a264f4e61b91cd2763cb75ac189a".FromHexString() // expected key
        ];
    }
}