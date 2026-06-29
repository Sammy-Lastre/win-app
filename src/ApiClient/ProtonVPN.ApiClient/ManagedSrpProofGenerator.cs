using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace ProtonVPN.ApiClient;

public sealed class ManagedSrpProofGenerator : ISrpProofGenerator
{
    private const int BitLength = 2048;
    private const int ByteLength = BitLength / 8;
    private static readonly BigInteger Generator = new(2);
    private static readonly Encoding PasswordEncoding = Encoding.UTF8;

    public SrpProof GenerateProof(string password, AuthInfoResponse authInfo)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(password);

        if (authInfo.Modulus is null || authInfo.ServerEphemeral is null || authInfo.Salt is null || authInfo.SrpSession is null)
        {
            throw new ProtonVpnApiException(null, authInfo.Code, "The auth info response is missing SRP fields.");
        }

        byte[] modulusBytes = DecodeModulus(authInfo.Modulus);
        byte[] serverEphemeralBytes = Convert.FromBase64String(authInfo.ServerEphemeral);
        byte[] saltBytes = authInfo.Version >= 3 ? Convert.FromBase64String(authInfo.Salt) : [];

        BigInteger modulus = FromLittleEndian(modulusBytes);
        BigInteger serverEphemeral = FromLittleEndian(serverEphemeralBytes);
        CheckParameters(serverEphemeral, modulus);

        byte[] hashedPasswordBytes = HashPassword(authInfo.Version, password, saltBytes, modulusBytes);
        BigInteger hashedPassword = FromLittleEndian(hashedPasswordBytes);
        BigInteger modulusMinusOne = modulus - BigInteger.One;
        BigInteger multiplier = ComputeMultiplier(modulus);

        while (true)
        {
            BigInteger clientSecret = GenerateClientSecret(modulusMinusOne);
            byte[] clientEphemeralBytes = ToLittleEndian(BigInteger.ModPow(Generator, clientSecret, modulus));
            BigInteger scramblingParameter = FromLittleEndian(ExpandHash(Concat(clientEphemeralBytes, serverEphemeralBytes)));
            if (scramblingParameter.IsZero)
            {
                continue;
            }

            BigInteger baseValue = PositiveMod(serverEphemeral - multiplier * BigInteger.ModPow(Generator, hashedPassword, modulus), modulus);
            BigInteger exponent = PositiveMod(clientSecret + scramblingParameter * hashedPassword, modulusMinusOne);
            byte[] sharedSecretBytes = ToLittleEndian(BigInteger.ModPow(baseValue, exponent, modulus));

            byte[] clientProof = ExpandHash(Concat(clientEphemeralBytes, serverEphemeralBytes, sharedSecretBytes));
            byte[] expectedServerProof = ExpandHash(Concat(clientEphemeralBytes, clientProof, sharedSecretBytes));

            CryptographicOperations.ZeroMemory(hashedPasswordBytes);
            return new SrpProof(
                Convert.ToBase64String(clientEphemeralBytes),
                Convert.ToBase64String(clientProof),
                Convert.ToBase64String(expectedServerProof));
        }
    }

    private static byte[] DecodeModulus(string signedModulus)
    {
        string modulus = ExtractClearSignedPayload(signedModulus);
        return Convert.FromBase64String(modulus);
    }

    private static string ExtractClearSignedPayload(string signedMessage)
    {
        const string header = "-----BEGIN PGP SIGNED MESSAGE-----";
        const string signature = "-----BEGIN PGP SIGNATURE-----";

        if (!signedMessage.Contains(header, StringComparison.Ordinal))
        {
            return signedMessage.Trim();
        }

        int bodyStart = signedMessage.IndexOf("\n\n", StringComparison.Ordinal);
        if (bodyStart < 0)
        {
            bodyStart = signedMessage.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (bodyStart < 0)
            {
                throw new ProtonVpnApiException(null, null, "The signed SRP modulus is malformed.");
            }

            bodyStart += 4;
        }
        else
        {
            bodyStart += 2;
        }

        int signatureStart = signedMessage.IndexOf(signature, bodyStart, StringComparison.Ordinal);
        if (signatureStart < 0)
        {
            throw new ProtonVpnApiException(null, null, "The signed SRP modulus has no signature block.");
        }

        return signedMessage[bodyStart..signatureStart]
            .Replace("\r", string.Empty, StringComparison.Ordinal)
            .Replace("\n", string.Empty, StringComparison.Ordinal)
            .Trim();
    }

    private static byte[] HashPassword(int version, string password, byte[] salt, byte[] modulus)
    {
        return version switch
        {
            3 or 4 => HashPasswordVersion3(password, salt, modulus),
            _ => throw new ProtonVpnApiException(null, null, $"Unsupported Proton SRP auth version '{version}'.")
        };
    }

    private static byte[] HashPasswordVersion3(string password, byte[] salt, byte[] modulus)
    {
        byte[] saltWithSuffix = Concat(salt, "proton"u8.ToArray());
        string bcryptSalt = BCryptBase64Encode(saltWithSuffix);
        string bcryptHash = global::BCrypt.Net.BCrypt.HashPassword(password, "$2y$10$" + bcryptSalt);
        if (bcryptHash.StartsWith("$2a$", StringComparison.Ordinal) ||
            bcryptHash.StartsWith("$2b$", StringComparison.Ordinal))
        {
            bcryptHash = "$2y$" + bcryptHash[4..];
        }

        return ExpandHash(Concat(Encoding.ASCII.GetBytes(bcryptHash), modulus));
    }

    private static string BCryptBase64Encode(byte[] data)
    {
        const string alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder encoded = new((data.Length * 4 + 2) / 3);

        int offset = 0;
        while (offset < data.Length)
        {
            int c1 = data[offset++];
            encoded.Append(alphabet[c1 >> 2]);
            c1 = (c1 & 0x03) << 4;

            if (offset >= data.Length)
            {
                encoded.Append(alphabet[c1]);
                break;
            }

            int c2 = data[offset++];
            c1 |= c2 >> 4;
            encoded.Append(alphabet[c1]);
            c1 = (c2 & 0x0f) << 2;

            if (offset >= data.Length)
            {
                encoded.Append(alphabet[c1]);
                break;
            }

            c2 = data[offset++];
            c1 |= c2 >> 6;
            encoded.Append(alphabet[c1]);
            encoded.Append(alphabet[c2 & 0x3f]);
        }

        return encoded.ToString();
    }

    private static byte[] ExpandHash(byte[] data)
    {
        byte[] result = new byte[SHA512.HashSizeInBytes * 4];
        Span<byte> input = stackalloc byte[data.Length + 1];
        data.CopyTo(input);

        for (int i = 0; i < 4; i++)
        {
            input[^1] = (byte)i;
            SHA512.HashData(input, result.AsSpan(i * SHA512.HashSizeInBytes, SHA512.HashSizeInBytes));
        }

        return result;
    }

    private static BigInteger ComputeMultiplier(BigInteger modulus)
    {
        BigInteger multiplier = FromLittleEndian(ExpandHash(Concat(ToLittleEndian(Generator), ToLittleEndian(modulus)))) % modulus;
        if (multiplier <= BigInteger.One || multiplier >= modulus - BigInteger.One)
        {
            throw new ProtonVpnApiException(null, null, "The SRP multiplier is out of bounds.");
        }

        return multiplier;
    }

    private static void CheckParameters(BigInteger serverEphemeral, BigInteger modulus)
    {
        if (modulus.GetBitLength() != BitLength)
        {
            throw new ProtonVpnApiException(null, null, "The SRP modulus has an unexpected size.");
        }

        if (serverEphemeral <= BigInteger.One || serverEphemeral >= modulus - BigInteger.One)
        {
            throw new ProtonVpnApiException(null, null, "The SRP server ephemeral is out of bounds.");
        }

        if (modulus % 8 != 3)
        {
            throw new ProtonVpnApiException(null, null, "The SRP modulus is invalid.");
        }
    }

    private static BigInteger GenerateClientSecret(BigInteger modulusMinusOne)
    {
        while (true)
        {
            byte[] candidateBytes = RandomNumberGenerator.GetBytes(ByteLength);
            BigInteger secret = FromLittleEndian(candidateBytes) % modulusMinusOne;
            if (secret > BitLength * 2 && secret < modulusMinusOne)
            {
                return secret;
            }
        }
    }

    private static BigInteger PositiveMod(BigInteger value, BigInteger modulus)
    {
        BigInteger result = value % modulus;
        return result.Sign < 0 ? result + modulus : result;
    }

    private static BigInteger FromLittleEndian(byte[] bytes)
        => new(bytes, isUnsigned: true, isBigEndian: false);

    private static byte[] ToLittleEndian(BigInteger value)
    {
        byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: false);
        if (bytes.Length == ByteLength)
        {
            return bytes;
        }

        byte[] padded = new byte[ByteLength];
        bytes.CopyTo(padded, 0);
        return padded;
    }

    private static byte[] Concat(params byte[][] values)
    {
        int length = values.Sum(static value => value.Length);
        byte[] result = new byte[length];
        int offset = 0;

        foreach (byte[] value in values)
        {
            Buffer.BlockCopy(value, 0, result, offset, value.Length);
            offset += value.Length;
        }

        return result;
    }
}
