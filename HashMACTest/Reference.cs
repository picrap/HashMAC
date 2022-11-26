using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using NUnit.Framework;

namespace HashMACTest;

[TestFixture]
public class Reference
{
    [Test]
    [TestCase(new byte[0], new byte[0])]
    [TestCase(new byte[] { 1, 2, 3 }, new byte[0])]
    [TestCase(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, new byte[0])]
    [TestCase(new byte[] { 1, 2, 3 }, new byte[] { 4, 5, 6 })]
    public void MD5DotNet(byte[] key, byte[] message)
    {
        using var dotNetHMAC = new HMACMD5(key);
        var reference = dotNetHMAC.ComputeHash(message);
        using var hashMAC = new HashMAC.HashMAC(key, MD5.Create(), 64);
        var result = hashMAC.ComputeHash(message);
        Assert.That(result, Is.EqualTo(reference));
    }

    [Test]
    [TestCase(new byte[0], new byte[0])]
    [TestCase(new byte[] { 1, 2, 3 }, new byte[0])]
    [TestCase(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, new byte[0])]
    [TestCase(new byte[] { 1, 2, 3 }, new byte[] { 4, 5, 6 })]
    public void SHA1DotNet(byte[] key, byte[] message)
    {
        using var dotNetHMAC = new HMACSHA1(key);
        var reference = dotNetHMAC.ComputeHash(message);
        using var hashMAC = new HashMAC.HashMAC(key, SHA1.Create(), 64);
        var result = hashMAC.ComputeHash(message);
        Assert.That(result, Is.EqualTo(reference));
    }

    [Test]
    [TestCase(new byte[0], new byte[0])]
    [TestCase(new byte[] { 1, 2, 3 }, new byte[0])]
    [TestCase(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, new byte[0])]
    [TestCase(new byte[] { 1, 2, 3 }, new byte[] { 4, 5, 6 })]
    public void SHA256DotNet(byte[] key, byte[] message)
    {
        using var dotNetHMAC = new HMACSHA256(key);
        var reference = dotNetHMAC.ComputeHash(message);
        using var hashMAC = new HashMAC.HashMAC(key, SHA256.Create(), 64);
        var result = hashMAC.ComputeHash(message);
        Assert.That(result, Is.EqualTo(reference));
    }

    [Test]
    [TestCase(new byte[0], new byte[0])]
    [TestCase(new byte[] { 1, 2, 3 }, new byte[0])]
    [TestCase(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, new byte[0])]
    [TestCase(new byte[] { 1, 2, 3 }, new byte[] { 4, 5, 6 })]
    public void SHA384DotNet(byte[] key, byte[] message)
    {
        using var dotNetHMAC = new HMACSHA384(key);
        var reference = dotNetHMAC.ComputeHash(message);
        using var hashMAC = new HashMAC.HashMAC(key, SHA384.Create(), 128);
        var result = hashMAC.ComputeHash(message);
        Assert.That(result, Is.EqualTo(reference));
    }

    [Test]
    [TestCase(new byte[0], new byte[0])]
    [TestCase(new byte[] { 1, 2, 3 }, new byte[0])]
    [TestCase(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }, new byte[0])]
    [TestCase(new byte[] { 1, 2, 3 }, new byte[] { 4, 5, 6 })]
    public void SHA512DotNet(byte[] key, byte[] message)
    {
        using var dotNetHMAC = new HMACSHA512(key);
        var reference = dotNetHMAC.ComputeHash(message);
        using var hashMAC = new HashMAC.HashMAC(key, SHA512.Create(), 128);
        var result = hashMAC.ComputeHash(message);
        Assert.That(result, Is.EqualTo(reference));
    }
}