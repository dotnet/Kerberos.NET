using System.Text;
using Kerberos.NET.Configuration;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class Krb5ConfTests : BaseTest
    {
        [TestMethod]
        public void ParseBasicConfiguration()
        {
            var file = ReadDataFile("Configuration\\krb5.conf");

            var conf = new Krb5Configuration(Encoding.Default.GetString(file));

            ;

            var roundtrip = conf.Serialize();

            ;
        }
    }
}
