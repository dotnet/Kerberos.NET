using Kerberos.NET;
using Kerberos.NET.Crypto;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Threading.Tasks;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class DelegationTests : BaseTest
    {
        private const string TicketContainingDelegation = "YIIN3gYGKwYBBQUCoIIN0jCCDc6gMDAuBgkqhkiC9xIBAgIGCSqGSIb3EgECAgYKKwYBBAGCNwICHgYKKwYBBAGCNwICCq" +
            "KCDZgEgg2UYIINkAYJKoZIhvcSAQICAQBugg1/MIINe6ADAgEFoQMCAQ6iBwMFACAAAACjggVLYYIFRzCCBUOgAwIBBaEfGx1DT1JQLklERU5USVRZSU5URVJWRU5USU9OLkNPTaI0MD" +
            "KgAwIBAqErMCkbBGhvc3QbIWFwcC5jb3JwLmlkZW50aXR5aW50ZXJ2ZW50aW9uLmNvbaOCBOMwggTfoAMCARehAwIBA6KCBNEEggTNYb+bd5txM65Saj1CDgQqRXlbBPHPGAlwjZYIQe" +
            "KQCk1GU/eXthXiOPgBESM10io9mhBY8cKFXXTxUCYSWpd2z1XQx+FRvuSS/E2MC4jNgcarnJKpLdjDOkvAakQ61OC2S+Sy/9VBxRcy8UHlk9OQxxxsf4ut46sGi68WJIUnM6aN/yvZK1" +
            "Thm0qW7ygJcOKkLBqyoCrddBv0bpiCuX1QCuwAWQ2axn0L3okIwpdmVHeBaHuToieunT2R4QBsAC1VxVbhSDIlWJXF/Y//goL0Wr9jWtP58AixpykRPBBNIcPlpq5RWXbBYIlhypd7hP" +
            "t/rua3bCSM9SdEfIu1Qhjou1Kebe00a7CnsEjCJaDN+AArigV/4gqdDb1M/T3qP2SerzX2qmjHME/w4vULBfczpqFCcITrN1c60C0rbwU+6CGAXZW+k8qnvGThh0Xm6q7z4y0vU+aK3V" +
            "1tMrrtg9a3VXqHZNFlH33tUcBd9PvQEGySOq2xzE4NHEH5D62LbxkA9Y5siupyiIR08wVdAhfAIzHAj+mWk742raLbFsCgvSi2BQHnb8aKJg5clChMV9JgIkhXvSc/H7lxLPvWCSRoJn" +
            "lNn8/c3eObRPhabyS8mTZUnA8//qtPI+ZRyfwee2U0pWo4kCo0QodpTwFVAh+m0RE5tKFYwWtCXrOdLmdmoFYfmUEJDxYPVQnfZncKBs/m5duX5JBrADMhP5ErwHUqzAjotTMUlP7L9b" +
            "XS+cCeuQNX9r7kkA5aK0Z+O/gzdM+CQ1kWnNHNEp8cd+pRgI5txYFBj+3IM3Z1fRyAvw0pSr9rGEnFU5dyL/3WX+gVX3V2PIkdr5qLoOvwC02n3xn7FSTFgfzZFOq9KxBRibCoWqdsdf" +
            "lC4OILUumcFnw9dQCa6KhptOegyQi6KaWFZaviLRiyuGoniVpNTm46KvH0up7wdlSKH3a5emHcfYdsbMur32FiOLGQjNDP+/WZjlbVWC34eTsNKaDrzF9QV3z3YPwdenUr5pGBQtAPuL" +
            "t06/BVECt9tiNCKjueWhZ18dSkD+XusU3AUl+y5hR8L5ZYe5GbPA/oatyGRl4uQgmN2CdjB3UQh3Mbud1CWCmorYAyVKCWuz6Jzffk4oomKS3ptMDz3tmZ5Qt6YESMv0xmwwrnxmkS0e" +
            "Xn6DJevW18nCqTwLJo7/VyDnkQeIKWKGrYmZG8dU1D+w/0tT01IZyTKR3z41DlhQQyfF6mfs5qjQP3WaIizN1EPY5iRfr6KQ16LjreO2ngOD6YQc/HxEMJupAyi+JkK6Ig+cN/R5avoY" +
            "MDE5oqhGsXDhGl84E1uTB8dwME5gQifMJIk1U6zvaP5gtZIAKkfRw1KPfnlF+V60Ok2aL+ZF9ra+8PC4MSnZNfwhFOZBowCSTE9Ba0eV2ciO2SR3vvEXUQ6vo8c5Hn49MdCW7dp9YmII" +
            "cG8DrjuiNHnKM2zRLAk3Nt3mPwLSmqPeoTyCLjdM9aYVjYWOhJvdilNoUws2VRF3QsbLSZZepMc74ywD2lcVPCZcd2ujXVfTze9o/oH+RtEBHkOkAZ/5/pQnnthmKsH3deFvmCJMGuGU" +
            "Sikjjy3wyyyXChdOxt0Qp+5gxrsO/5Lfnw42U1DPIals8hfZVZ6An9g8WZ+pqkgggVMIIIEaADAgEXooIICASCCASiSdnOwSoc8GJlGvuAZ46vrGv1a0FcYx1UcgqZx5Iaxn0BmUnWfX" +
            "bxji6aMdP8YA+TPoz0R4cfWAEBykwaQ/Xm+5kcL0JbjBDGRFV5iMXN8kb1YYdZ904IzlnXSbhNzyw1NyMAx0A8d/HjoHo5vTMEdx3OwdrfhYGKtnYSYPXo2oF4YxSD9GiJwbHD7EExTa" +
            "eOGRVDXEGbM/hoUe6LjketuXOErfDhjW6LK8MpTryRGriPM4ovyuoWTTXGlltkiuun5wjqtXc5nkTWeSWkYkPz5+JFWwsGM67twE+2xLHOZqqyw5bHuk5qZ77ikiIZa+Nbg2kPSZwBJ8" +
            "mPLRJ28f4UiWh2VWTQT2AhvubalWeyOkEKam4RMJBiT4uc8nIkDRdHursczloSiLJqMgOg0cVHVmGRelYaWKmMLHwZvwlLjEBdM6didf2eK0L7fKwLGLkSFWojCzl619NzSOYpqPF4aU" +
            "BSNVurCuOLGBNdwDgGOKFjtRNWyc/7Nnlq2vsYr8fXYcavSQgjvv6T/7WSoNODf/RLDtNQPBO9Qu49t9Hh8XeJAHQmrVoj3IMO5A7HnQuDhXl9mCOKEuMNKLTd4u9qTJwej3yaiCqPLB" +
            "+UbTHUthqqX0v/huiBmdsm/mFddfVrjAWcuHctB8K5rFzyJ5KJ+5rhp0lWFGQcATO8FoSO75ZBoo4fprxXFDCP4msUBXkpYr4UPN8gHMis4LtRcq4rGQF99DMHNf9zM7Yl//H5sW0qEU" +
            "SuV8lnnfiLnXiEI/QDJqkgLWzv5FyAH40eVZA90UCX/14lDokuoYX3RsMAmhbI/FW/B/E+JNOhwSKGpzpgnDYaUJ48X6rEBv7bFFD5ugMiIObZOynaLaGzy8X9urftO29+81MtqiKSLq" +
            "eTiYctOIIaGAxhf9MojcMc48ML4tj7t6t/wtj61iZhysctT6tYBPNXvgzMcaAGglDskrnkUVS4I2p9L1VxIqfZTIQRJnaGrVrWbZge4xovnocFdTra9ENRezCRwXJpy6EpUfIuQl0nn5" +
            "fcXgKTi6sS2hTlvExj+TVzTTU64TF6S9mxdJIno1HOK8oZ4r+M6HmcFq6f5F2jn+oDsyEiZvZjO7GJRYieir51xGVLH/YNFu3gzYBuEfQzu7SxvjL23mRGlLxe//1TcrgaK24vybR09U" +
            "7bVc2hleqtRZEvDfNgFGR2fasEMEOhhLQlhalv1c+gPQiUMs1CX1LhOeU8fktlybHCoE6blXhVLAigun3wdPYm9tB0YJPortQUtbemRtpM8g+WP0RwaCykn669crblCxbCdC63WXYJcW" +
            "oRF41dZ55meHUsFHLpNgcOeoNBfvEByvMz9cjJT40C1/nykBwHMDX23IS3RU1hUU/c1I9lqQDVfw14QeDSW2Br5fd461dMo6rzrRJ5mfpQ5CHcljLkz61oViBY0E+qOK1IDPjg2rCjw2" +
            "8bhjdkWrePKAS8wb6OuXfUAwbJnzzwJrb48ZzYFZqUxS41jjsQAdelRdiEZp0550MuYA/iWPcWkpNFEvVtkRMgAbPllMv0WA1pl3mwpcA5gRVvFeZWHTVH0ncfLQ8ghAfZkEV8yVtbox" +
            "/ZM6MbsIN3VuGs4DAc8GdKGGZAB5eKA0rALiRhb4vHD/iUhIJlGL+7sI3aWSvG1cq9cpMg0QsKBkiSljGKxoPMXLFKwmmLTw8PXe/whnc55QH6bR62SbDJWwwM0WzeEVL9p2WWrNTGvH" +
            "ESD8cgQU3RltmGvJ1bakRS3cqK4SrPhWPJxhRacTVnbCvXo/zT38aUeNK4Ro3gsJS1EFM6Lptn27V6MJUXhg7m7B+C5WQTOW9QWmdRCBzm46Ye3NZ8QycVHwJRQTIDdLLlAa6L3isMfQ" +
            "9f54IaITpto2ImTR6lJLEfNYxWbezX0qpvVJhWZ2Ne5klvyWCf+bhM163lmAMZv5onJZkKQuxZdA6JmVpiWdiDoAa5Th/Vn/aZaqyoXeCXTsy5i2h1NsoSD7qxN+FW0EGYX3SbHWVDIt" +
            "u9umZeBza6TFgiczx62v48foqYlNS9TYhMF19zldTRtnF2DCid/FOAFMw2PAXHrL0nFA8lTIafWTHFnmX60xA+pwzXsm9hNNefRK2vSUYkFZE5fegK4NN96dTX7kaAudLs3PGPpw5g5J" +
            "BZSGzPAkBVQZYg1dAeQhyKfkn69+hQFMca75hImY1yEx/1paXmel1KmtQjZIgkg+KWEzrFtwUFiHABI2sIS1nDYRwAyVo5HZ1/z/TMVC1zd9Dn0cdRcE8UM5Og1bjES5NE9Jc/Lvgbcu" +
            "PbBAF22IQM73NmZ19wu9zFhKja5Ly7V+P2785fel9YxqdC3vcgM8IaX1RLsxyZyc8H5VYB6Eb2oUJnkDwTLmTtmO32LM322Y3yoU0ZdnP4z0FIEEvW5SO+V7lQcnGrrPqgkxctyaGPMD" +
            "w4vA6I0ib2hn2+yLW3D3w2QMLx4aaW2U2FwzU+aHvbpyMqDx4Fw72eaeEhDXwQGGelSwSh10V6MbL92uPgSERWCKGaG0bRKJ21ZIw2aTo7DK06osv4qsV5QGrWMQVqylWWg7i4JBaXOU" +
            "AFffP2PNqYn95dA4HD/On0QpOkNykZ3JBzSLnEr0+lo7bgZOTAF5m1IBwwEMdMhZRYudg4/MRPgKSzAx2cDfFfqe3c5a/e8IjYdZHI3fmQa1rPXn5XQ03aw9YJNkW1VNb0+n5JGR4Jge" +
            "C12oQyIh4DSu3XGvlXi+swg90=";

        [TestMethod]
        public async Task TestDelegationRetrieval()
        {
            var validator = new KerberosValidator(new KerberosKey("P@ssw0rd!")) { ValidateAfterDecrypt = DefaultActions };

            var data = await validator.Validate(Convert.FromBase64String(TicketContainingDelegation));

            Assert.IsNotNull(data);

            var cred = data?.Authenticator?.Checksum?.Delegation?.DelegationTicket?.Credential?.CredentialPart;

            Assert.IsNotNull(cred);

            Assert.AreEqual(1, cred.Tickets.Count());

            var ticket = cred.Tickets.First();

            Assert.AreEqual("Administrator", ticket.PrincipalName.Names.First());
            Assert.AreEqual("krbtgt/CORP.IDENTITYINTERVENTION.COM", ticket.SName.Names.First());

            Assert.IsNotNull(ticket.Key);
            Assert.IsNotNull(ticket.Key.RawKey);
        }
    }
}
