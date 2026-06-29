using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace ProtonVPN.ApiClient.Tests;

[TestClass]
public sealed class ManagedSrpProofGeneratorTests
{
    [TestMethod]
    public void GenerateProof_WithKnownProtonSrpChallenge_ReturnsWireReadyBase64Proofs()
    {
        ManagedSrpProofGenerator generator = new();

        SrpProof proof = generator.GenerateProof("abc123", new AuthInfoResponse
        {
            Code = ProtonResponse.OkCode,
            Version = 4,
            Salt = "yKlc5/CvObfoiw==",
            SrpSession = "session",
            Modulus = TestModulusClearSign,
            ServerEphemeral = TestServerEphemeral
        });

        Convert.FromBase64String(proof.ClientEphemeral).Should().HaveCount(256);
        Convert.FromBase64String(proof.ClientProof).Should().HaveCount(256);
        Convert.FromBase64String(proof.ExpectedServerProof).Should().HaveCount(256);
    }

    private const string TestServerEphemeral =
        "l13IQSVFBEV0ZZREuRQ4ZgP6OpGiIfIjbSDYQG3Yp39FkT2B/k3n1ZhwqrAdy+qvPPFq/le0b7UDtayoX4aOTJihoRvifas8Hr3icd9nAHqd0TUBbkZkT6Iy6UpzmirCXQtEhvGQIdOLuwvy+vZWh24G2ahBM75dAqwkP961EJMh67/I5PA5hJdQZjdPT5luCyVa7BS1d9ZdmuR0/VCjUOdJbYjgtIH7BQoZs+KacjhUN8gybu+fsycvTK3eC+9mCN2Y6GdsuCMuR3pFB0RF9eKae7cA6RbJfF1bjm0nNfWLXzgKguKBOeF3GEAsnCgK68q82/pq9etiUDizUlUBcA==";

    private const string TestModulusClearSign =
        """
        -----BEGIN PGP SIGNED MESSAGE-----
        Hash: SHA256

        W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==
        -----BEGIN PGP SIGNATURE-----
        Version: ProtonMail
        Comment: https://protonmail.com

        wl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIa
        GO86yMV4zDZEZcDSJo0fgr8A/AlupGN9EdHlsrZLmTA1vhIx+rOgxdEff28N
        kvNM7qIK
        =q6vu
        -----END PGP SIGNATURE-----
        """;
}
