using System;
using System.Security.Cryptography;

namespace HashMAC;

public class HashMAC : HMAC
{
    private readonly HashAlgorithm _hashAlgorithm;

    public override int HashSize => _hashAlgorithm.HashSize;
    private int BlockSizeBytes { get; }

    private byte[] _buffer;
    private int _bufferSize;

    public HashMAC(byte[] key, HashAlgorithm hashAlgorithm, int? blockSize = null)
    {
        _hashAlgorithm = hashAlgorithm;
        Key = (byte[])key.Clone();
        BlockSizeBytes = blockSize ?? hashAlgorithm.InputBlockSize;
        Initialize();
    }

    protected override void Dispose(bool disposing)
    {
        _hashAlgorithm.Dispose();
        base.Dispose(disposing);
    }

    public override void Initialize()
    {
        var ipad = GetIPad(); // must be computed before hash initialization
        _hashAlgorithm.Initialize();
        _hashAlgorithm.TransformBlock(ipad, 0, ipad.Length, null, 0);
        _buffer = new byte[BlockSizeBytes];
        _bufferSize = 0;
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
        while (cb > 0)
        {
            var left = Math.Min(cb, BlockSizeBytes - _bufferSize);
            Buffer.BlockCopy(rgb, ib, _buffer, _bufferSize, left);
            _bufferSize += left;
            if (_bufferSize > BlockSizeBytes)
            {
                _hashAlgorithm.TransformBlock(_buffer, 0, _bufferSize, null, 0);
                _bufferSize = 0;
            }

            cb -= left;
            ib += left;
        }
    }

    private byte[] GetHashableKey()
    {
        if (Key.Length <= BlockSizeBytes)
            return Key;
        return _hashAlgorithm.ComputeHash(Key);
    }

    protected override byte[] HashFinal()
    {
        _hashAlgorithm.TransformFinalBlock(_buffer, 0, _bufferSize);
        var hash = _hashAlgorithm.Hash;
        _hashAlgorithm.Initialize();
        var opad = GetOPad();
        var final = new byte[opad.Length + hash.Length];
        Buffer.BlockCopy(opad, 0, final, 0, opad.Length);
        Buffer.BlockCopy(hash, 0, final, opad.Length, hash.Length);
        return _hashAlgorithm.ComputeHash(final);
    }
}
