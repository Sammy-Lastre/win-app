using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ProtonVPN.ApiClient;

public sealed class NativeSrpProofGenerator : ISrpProofGenerator
{
    public SrpProof GenerateProof(string password, AuthInfoResponse authInfo)
    {
        if (authInfo.Salt is null || authInfo.Modulus is null || authInfo.ServerEphemeral is null)
        {
            throw new ProtonVpnApiException(null, authInfo.Code, "The auth info response is missing SRP fields.");
        }

        byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
        nint passwordPtr = Marshal.AllocHGlobal(passwordBytes.Length);
        try
        {
            Marshal.Copy(passwordBytes, 0, passwordPtr, passwordBytes.Length);
            int result = NativeMethods.GenerateProof(
                passwordPtr,
                (nuint)passwordBytes.Length,
                authInfo.Salt,
                authInfo.Modulus,
                authInfo.ServerEphemeral,
                out FfiSrpProof ffiProof,
                out nint errorPtr);

            if (result != 0)
            {
                string error = ReadAndFreeString(errorPtr);
                throw new ProtonVpnApiException(null, authInfo.Code, $"SRP proof generation failed: {error}");
            }

            try
            {
                return new SrpProof(
                    Marshal.PtrToStringUTF8(ffiProof.ClientEphemeral) ?? string.Empty,
                    Marshal.PtrToStringUTF8(ffiProof.ClientProof) ?? string.Empty,
                    Marshal.PtrToStringUTF8(ffiProof.ExpectedServerProof) ?? string.Empty);
            }
            finally
            {
                NativeMethods.FreeProof(ref ffiProof);
            }
        }
        catch (DllNotFoundException ex)
        {
            throw new ProtonVpnSrpUnavailableException(ex);
        }
        catch (EntryPointNotFoundException ex)
        {
            throw new ProtonVpnSrpUnavailableException(ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
            Marshal.FreeHGlobal(passwordPtr);
        }
    }

    private static string ReadAndFreeString(nint stringPtr)
    {
        if (stringPtr == nint.Zero)
        {
            return "unknown error";
        }

        try
        {
            return Marshal.PtrToStringUTF8(stringPtr) ?? "unknown error";
        }
        finally
        {
            NativeMethods.FreeString(stringPtr);
        }
    }
}

[StructLayout(LayoutKind.Sequential)]
internal struct FfiSrpProof
{
    public nint ClientEphemeral;
    public nint ClientProof;
    public nint ExpectedServerProof;
}

internal static partial class NativeMethods
{
    private const string BinaryName = "proton_srp_cffi";

    [LibraryImport(BinaryName, EntryPoint = "generate_proof", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int GenerateProof(
        nint passwordPtr,
        nuint passwordLength,
        string salt,
        string modulus,
        string serverChallenge,
        out FfiSrpProof proof,
        out nint errorPtr);

    [LibraryImport(BinaryName, EntryPoint = "free_c_string")]
    internal static partial void FreeString(nint stringPtr);

    [LibraryImport(BinaryName, EntryPoint = "free_proof")]
    internal static partial void FreeProof(ref FfiSrpProof proof);
}
