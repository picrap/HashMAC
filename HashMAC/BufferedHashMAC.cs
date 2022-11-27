using System;
using System.Security.Cryptography;

namespace HashMAC;

public class BufferedHashMAC : HashMAC
{
    private byte[] _buffer;
    private int _bufferSize;

    public BufferedHashMAC(byte[] key, HashAlgorithm hashAlgorithm, int? blockSizeBytes = null)
        : base(key, hashAlgorithm, blockSizeBytes)
    {
    }

    public override void Initialize()
    {
        base.Initialize();
        _buffer = new byte[BlockSizeBytes];
        _bufferSize = 0;
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
                HashAlgorithm.TransformBlock(_buffer, 0, _bufferSize, null, 0);
                _bufferSize = 0;
            }

            cb -= left;
            ib += left;
        }
    }

    protected override void HashLast()
    {
        HashAlgorithm.TransformFinalBlock(_buffer, 0, _bufferSize);
    }
}
