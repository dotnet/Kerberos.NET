// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

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
            using (var buffer = new NdrBuffer())
            {
                buffer.WriteSpan(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 });

                Assert.AreEqual(20, buffer.Offset);
            }
        }

        [TestMethod]
        public void BufferExpansion()
        {
            using (var buffer = new NdrBuffer())
            {
                for (var i = 0; i < 1000; i++)
                {
                    buffer.WriteSpan(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 });
                }

                Assert.AreEqual(20_000, buffer.Offset);
            }
        }
    }
}