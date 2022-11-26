using System;
using System.Security.Cryptography;

namespace HashMAC;

public class HashMAC : HMAC
{
    private readonly HashAlgorithm _hashAlgorithm;

    public override int HashSize => _hashAlgorithm.HashSize;

    public HashMAC(HashAlgorithm hashAlgorithm, byte[] key)
    {
        _hashAlgorithm = hashAlgorithm;
        Key = (byte[])key.Clone();
    }

    protected override void Dispose(bool disposing)
    {
        _hashAlgorithm.Dispose();
        base.Dispose(disposing);
    }

    public override void Initialize()
    {
        base.Initialize();
    }

    protected override void HashCore(byte[] rgb, int ib, int cb)
    {
        _hashAlgorithm.TransformBlock(rgb, ib, cb, null, 0);
    }

    protected override byte[] HashFinal()
    {
        return base.HashFinal();
    }

}
