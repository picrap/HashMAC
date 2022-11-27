# HashMAC

A flexible [HMAC implementation](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmac), allowing to specify any `HashAlgorithm` as input.  
Available as a [![NuGet](https://img.shields.io/nuget/v/HashMAC.svg?style=flat-square)](https://www.nuget.org/packages/HashMAC) package.

# How to use it

## `HashMAC` itself

Short answer: as a [standard HMAC](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmac) 😉  
The `HMAC` base class derives itself from `HashAlgorithm`, so except the constructor which takes a secret key, the usage is the same.

## Using it with other hashes

### SHA3

NuGet packages:
- [SHA3](https://www.nuget.org/packages/SHA3): not not maintained anymore
- [SHA3.net](https://www.nuget.org/packages/SHA3.Net): embeds code from Bouncy Castle

Hashes block sizes (required by `HashMAC.Create()`):

| SHA3 size (bits) | Block size (bits) | Block size (bytes) |
|-|-|-|
| 224 | 1152 | 144 |
| 256 | 1088 | 136 |
| 384 | 832 | 104 |
| 512 | 576 | 72 |

# References

- [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104): the reference
- [Wikipedia](https://fr.wikipedia.org/wiki/HMAC): a human-readable description

# Thank you

- [Web Vectors by Vecteezy](https://www.vecteezy.com/free-vector/web)
