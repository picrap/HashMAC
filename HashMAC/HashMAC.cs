using System;
using System.Security.Cryptography;

namespace HashMAC;

public class HashMAC : HMAC
{
    protected HashAlgorithm HashAlgorithm { get; }

    public override int HashSize => HashAlgorithm.HashSize;

    protected int BlockSizeBytes { get; }

    protected readonly byte[] NoByte = new byte[0];

    public static HashMAC Create(byte[] key, HashAlgorithm hashAlgorithm, int? blockSizeBytes = null)
    {
        if (hashAlgorithm.InputBlockSize == 1)
            return new HashMAC(key, hashAlgorithm, blockSizeBytes);
        return new BufferedHashMAC(key, hashAlgorithm, blockSizeBytes);
    }

    public HashMAC(byte[] key, HashAlgorithm hashAlgorithm, int? blockSizeBytes = null)
    {
        HashAlgorithm = hashAlgorithm;
        Key = (byte[])key.Clone();
        BlockSizeBytes = blockSizeBytes ?? hashAlgorithm.InputBlockSize;
        Initialize();
    }

    protected override void Dispose(bool disposing)
    {
        HashAlgorithm.Dispose();
        base.Dispose(disposing);
    }

    public override void Initialize()
    {
        var ipad = GetIPad(); // must be computed before hash initialization
        HashAlgorithm.Initialize();
        HashAlgorithm.TransformBlock(ipad, 0, ipad.Length, null, 0);
    }

    protected virtual byte[] GetIPad() => GetIPad(GetHashableKey());
    protected virtual byte[] GetIPad(byte[] key) => GetPad(key, 0x36);
    protected virtual byte[] GetOPad() => GetOPad(GetHashableKey());
    protected virtual byte[] GetOPad(byte[] key) => GetPad(key, 0x5C);

    protected virtual byte[] GetPad(byte[] key, byte padValue)
    {
        var ipad = new byte[BlockSizeBytes];
        for (int ipadIndex = 0; ipadIndex < ipad.Length; ipadIndex++)
        {
            ipad[ipadIndex] = padValue;
            if (ipadIndex < key.Length)
                ipad[ipadIndex] ^= key[ipadIndex];
        }

        return ipad;
    }

    protected override void HashCore(byte[] rgb, int ib, int cb)
    {
        HashAlgorithm.TransformBlock(rgb, ib, cb, null, 0);
    }

    private byte[] GetHashableKey()
    {
        if (Key.Length <= BlockSizeBytes)
            return Key;
        return HashAlgorithm.ComputeHash(Key);
    }

    protected virtual void HashLast()
    {
        HashAlgorithm.TransformFinalBlock(NoByte, 0, 0);
    }

    protected override byte[] HashFinal()
    {
        HashLast();
        var hash = HashAlgorithm.Hash;
        HashAlgorithm.Initialize();
        var opad = GetOPad();
        var final = new byte[opad.Length + hash.Length];
        Buffer.BlockCopy(opad, 0, final, 0, opad.Length);
        Buffer.BlockCopy(hash, 0, final, opad.Length, hash.Length);
        return HashAlgorithm.ComputeHash(final);
    }
}
