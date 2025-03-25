﻿using Enigma.DataEncoding;
using Enigma.Padding;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace UnitTests.Padding;

public class Iso7816PaddingServiceTests
{
    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public void CsvPadTest(byte[] data, byte[] paddedData)
    {
        var srvc = new Iso7816PaddingService();
        var padded = srvc.Pad(data, 16);
        Assert.Equal(paddedData, padded);
    }
    
    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public void CsvUnpadTest(byte[] data, byte[] paddedData)
    {
        var srvc = new Iso7816PaddingService();
        var unpaddedData = srvc.Unpad(paddedData, 16);
        Assert.Equal(data, unpaddedData);
    }
    
    public static IEnumerable<object[]> GetCsvValues()
    {
        var hex = new HexService();
        
        return File.ReadAllLines(@"Padding\iso7816.csv")
            .Skip(1)
            .Select(line =>
            {
                var values = line.Split(',');
                return new object[]
                {
                    hex.Decode(values[0]), // data
                    hex.Decode(values[1]), // padded
                };
            });
    }
}