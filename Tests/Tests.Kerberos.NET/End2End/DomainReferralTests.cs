using System;
using System.Linq;
using System.Threading.Tasks;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json;
using static Tests.Kerberos.NET.KdcListener;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class DomainReferralTests : KdcListenerTestBase
    {
        [TestMethod]
        public async Task DomainRefersToOther()
        {
            var port = NextPort();

            using (var listener = StartListener(port))
            {
                await RequestAndValidateTickets(
                    listener,
                    AdminAtCorpUserName,
                    FakeAdminAtCorpPassword,
                    $"127.0.0.1:{port}",
                    spn: FakeAppServiceInOtherRealm,
                    includePac: false
                );

                listener.Stop();
            }
        }

        private const string ReferralTicket = "boIFxDCCBcCgAwIBBaEDAgEOogcDBQAAAAAAo4IEvmGCBLowggS2oAMCAQWhHxsdQ09SUC5JREVOVElUWUlOVEVSVkVOVElPTi5DT02iMjAwoAMCAQ" +
            "KhKTAnGwZrcmJ0Z3QbHVRFU1QuSURFTlRJVFlJTlRFUlZFTlRJT04uQ09No4IEWDCCBFSgAwIBEqKCBEsEggRHupaNLejMw6N/+FsL7aGbyeKM7n3p6mZLhRf5iFWdXZ3jk9MVBFtvRxyTqLrXwm" +
            "HuclkY2RQydmRqooNi4LDL+bTQf5fj/oEbm4N56iCSSFBvAH0VNLRZCPo0R7wJejTI9SjFxzMsEIQ+Rj4GEmKWMAe4OgwPpjuq9QCG0kPmvuNLFFsvsAOV1TFCceaZLeHHiC7ItR0xosmmlBMmw5" +
            "1EkQa6pMfH6/m9zRYWm918v8dMXRYu8AbFrlZrqcRFkLyQninDm6wCw75qut/7ua391zKyWef+fsi3vVBw1XN27yhFXi+gJx7uNZShMqCDZbi2SZUXU4y1GAcGDyuineV/G1NBhF7tidEz7G42Xp" +
            "nSsRrlrSuvUP7Aj5AgfOvI5SEfDhbrQmNGCRLtBYJDOcYxBvOGoY+83EGjX3f4r/5BRLRwdQ7C+PbPcJvQhDAr9QwdynC2QrYZ2Q2d1Jfou/ECcxrZ52MMw/UviLy9y1yHiU965zt80olxU9+8qv" +
            "hAw4kBFgqRWSVdcWtyDut9sGD910BdUisw+YKQ99rOBUO83PmcfELv/W2AGdV7/ralRO6f6SIcHIKqkfCWqvyIhXoIAn9ZiVmcvInCuJ2+Qyu6Do7Mxca5EEUW7lt4wOmOtnwexzHYoT5mjyIJbI" +
            "3MiNbEGs7GRG5p/3ohb09VMvoMNR0ao1KGe1ZdEl3+IQHvi/UwNXzFlBAM44GQacVyJ+GVTJgruhBhPN4PBmOKSTewi7XVQUjP8CVJi3wdj4XSv4l0pM5n1TyBwoWg3+5nx25eOcHiB1paa0GmhW" +
            "LKVTtj/IzW06QQlIrGgAMqzoSfD5Rlozr14ciEKQcjWIW6QFcGr8fWbSnHPLdCMPfijVv+tnmg38zXA1Efny+OMTfSGO9GAJJsVAzfBBAOb5sPsW/QyF0iDZBkkI8TUR6aMLuheMqHMY5RC0P/FR" +
            "cJPAy6hzpCRzLj69DBVvfblljpx8Ndd/ISuc0BwFEzux1u+oRDCOYP/pzkleEWas9SufaErw8tWUy7RjTaCTPw5aELL5tyArelvf0f8GTypaAi17SkyCOkcEzXm2ruPpPUN5d1Gu58sC/GQDjU5d" +
            "h757ERwiT4gdNYvNG+4M30qoFWqf1LN35ggt5gr5WzqGKb4T+nUWJpKwgQcGkrFFB8z5bHgxIHwtEvPOmtN3o0PBFxNSkj7JQ1axAquwjUJuCiUFzU0c3Jz98IbODhikXJtpS/uShJjfzoRyeDnM" +
            "6Vp21hzl8j+7fSMoHQrel4tOVWKXOEoN651zgdKmyvHvbwPtgxa2ACeLgMxOA50AfKksFp7c7qFkKf84jcnO0VOq13//n9j5r0LU/9LrDjT1IRF1/wp1Uu1TvUS4zO3PJdS052UGRZbRUem+Zbk9" +
            "F2LamKd/ZofTKtPaDunsCIqS3yCXFL23JiiZYQVbx6rFnC5F3bZ/X2OTVkDyOwjnFgpIHoMIHloAMCARKigd0EgdrdRopzqg2zDotbJPMAdTtJkaboz4uYVRlf1ac9v2sBgiZxwI7gErmSoqbQaI" +
            "0QeMzwT4owaF0bsaM/E8XXHrETO7fIBoECwjVSUcKguoE+Qm2FNAb6Ys/rvZU8CFDs0F5jccm9wA+xtDn7TBhiaQux5LlT4GTk0GhhGHHv0g9UCvDNN6GDQZi2J3phdUrO2Sk7qqNqf7FgGGLHop" +
            "8dtTUPZStOzcJWzTeYd9CTF/oQk3e1AWO+qTk3+zZI1z1QfmZeULU49e44iSnxtHLPCDJ6ybsEwyBKtPB6Bw==";

        private const string CRealm = "CORP.IDENTITYINTERVENTION.COM";

        [TestMethod]
        public void DecryptReferralTgt()
        {
            var ticket = KrbApReq.DecodeApplication(Convert.FromBase64String(ReferralTicket));

            var apreq = new DecryptedKrbApReq(ticket, MessageType.KRB_AS_REQ);

            var key = new KerberosKey(
                "P@ssw0rd!",
                new PrincipalName(
                    PrincipalNameType.NT_SRV_INST,
                    CRealm,
                    new[] { "krbtgt", "TEST.IDENTITYINTERVENTION.COM" }
                ),
                saltType: SaltType.Rfc4120
            );

            apreq.Decrypt(key);

            Assert.IsNotNull(apreq.Ticket);
            Assert.AreEqual("Administrator", apreq.Ticket.CName.FullyQualifiedName);
            Assert.AreEqual(CRealm, apreq.Ticket.CRealm);

            var serialized = JsonConvert.SerializeObject(
                new {
                    ApReq = ticket,
                    Ticket = apreq.Ticket,
                    Authenticator = apreq.Authenticator
                },
                Formatting.Indented,
                new JsonSerializerSettings() { ReferenceLoopHandling = ReferenceLoopHandling.Ignore }
            );

            var adif = apreq.Ticket.AuthorizationData.FirstOrDefault(f => f.Type == AuthorizationDataType.AdIfRelevant).DecodeAdIfRelevant();

            var pacStr = adif.FirstOrDefault(f => f.Type == AuthorizationDataType.AdWin2kPac);

            var pac = new PrivilegedAttributeCertificate(pacStr);

            Assert.IsNotNull(pac);

            Assert.AreEqual(500u, pac.LogonInfo.UserId);
        }
    }
}
