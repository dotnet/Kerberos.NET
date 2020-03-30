using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
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
    }
}
