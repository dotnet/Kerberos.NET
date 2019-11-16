using Kerberos.NET.Ndr;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class NdrBufferTests
    {
        [TestMethod]
        public void SingleWrite()
        {
            var buffer = new NdrBuffer();

            buffer.WriteSpan(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 });

            Assert.AreEqual(20, buffer.Offset);
        }

        [TestMethod]
        public void BufferExpansion()
        {
            var buffer = new NdrBuffer();

            for (var i = 0; i < 1000; i++)
            {
                buffer.WriteSpan(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 });
            }

            Assert.AreEqual(20_000, buffer.Offset);
        }
    }
}
