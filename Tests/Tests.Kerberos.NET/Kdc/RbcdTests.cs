// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class RbcdTests : BaseTest
    {
        [TestMethod]
        public void PacOptions_ResourceBasedConstrainedDelegation_FlagExists()
        {
            var flag = PacOptions.ResourceBasedConstrainedDelegation;

            Assert.AreEqual(1 << 28, (int)flag);
            Assert.IsTrue(Enum.IsDefined(typeof(PacOptions), flag));
        }

        [TestMethod]
        public void KdcOptions_ConstrainedDelegation_FlagExists()
        {
            var flag = KdcOptions.ConstrainedDelegation;

            Assert.AreEqual(1 << 17, (int)flag);
            Assert.IsTrue(Enum.IsDefined(typeof(KdcOptions), flag));
        }

        [TestMethod]
        public void PacOptions_Encode_Decode_RoundTrip()
        {
            var original = new KrbPaPacOptions
            {
                Flags = PacOptions.ResourceBasedConstrainedDelegation | PacOptions.Claims | PacOptions.BranchAware
            };

            var encoded = original.Encode();

            Assert.IsTrue(encoded.Length > 0);

            var decoded = KrbPaPacOptions.Decode(encoded);

            Assert.AreEqual(original.Flags, decoded.Flags);
            Assert.IsTrue(decoded.Flags.HasFlag(PacOptions.ResourceBasedConstrainedDelegation));
            Assert.IsTrue(decoded.Flags.HasFlag(PacOptions.Claims));
            Assert.IsTrue(decoded.Flags.HasFlag(PacOptions.BranchAware));
        }

        [TestMethod]
        public void KdcOptions_ConstrainedDelegation_CombinedWithOtherFlags()
        {
            var combined = KdcOptions.ConstrainedDelegation | KdcOptions.Canonicalize | KdcOptions.Renewable;

            Assert.IsTrue(combined.HasFlag(KdcOptions.ConstrainedDelegation));
            Assert.IsTrue(combined.HasFlag(KdcOptions.Canonicalize));
            Assert.IsTrue(combined.HasFlag(KdcOptions.Renewable));
            Assert.IsFalse(combined.HasFlag(KdcOptions.Forwardable));
        }
    }
}
