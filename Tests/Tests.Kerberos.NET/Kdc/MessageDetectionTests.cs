// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using Kerberos.NET.Entities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Kerberos.NET
{
    [TestClass]
    public class MessageDetectionTests
    {
        [TestMethod]
        public void ValidateKnownMessageTypes()
        {
            Assert.IsTrue(MessageType.KRB_AP_REP.IsValidMessageType());
            Assert.IsTrue(MessageType.KRB_AP_REQ.IsValidMessageType());
            Assert.IsTrue(MessageType.KRB_AS_REP.IsValidMessageType());
            Assert.IsTrue(MessageType.KRB_AS_REQ.IsValidMessageType());
            Assert.IsTrue(MessageType.KRB_CRED.IsValidMessageType());
            Assert.IsTrue(MessageType.KRB_ERROR.IsValidMessageType());
            Assert.IsTrue(MessageType.KRB_PRIV.IsValidMessageType());
            Assert.IsTrue(MessageType.KRB_RESERVED16.IsValidMessageType());
            Assert.IsTrue(MessageType.KRB_RESERVED17.IsValidMessageType());
            Assert.IsTrue(MessageType.KRB_SAFE.IsValidMessageType());
            Assert.IsTrue(MessageType.KRB_TGS_REP.IsValidMessageType());
            Assert.IsTrue(MessageType.KRB_TGS_REQ.IsValidMessageType());
        }

        [TestMethod]
        public void ValidateUnknownMessageTypesFails()
        {
            Assert.IsFalse(((MessageType)0).IsValidMessageType());
            Assert.IsFalse(((MessageType)1).IsValidMessageType());
            Assert.IsFalse(((MessageType)2).IsValidMessageType());
            Assert.IsFalse(((MessageType)3).IsValidMessageType());
            Assert.IsFalse(((MessageType)4).IsValidMessageType());
            Assert.IsFalse(((MessageType)5).IsValidMessageType());
            Assert.IsFalse(((MessageType)6).IsValidMessageType());
            Assert.IsFalse(((MessageType)7).IsValidMessageType());
            Assert.IsFalse(((MessageType)8).IsValidMessageType());
            Assert.IsFalse(((MessageType)9).IsValidMessageType());

            Assert.IsTrue(((MessageType)10).IsValidMessageType());
            Assert.IsTrue(((MessageType)11).IsValidMessageType());
            Assert.IsTrue(((MessageType)12).IsValidMessageType());
            Assert.IsTrue(((MessageType)13).IsValidMessageType());
            Assert.IsTrue(((MessageType)14).IsValidMessageType());
            Assert.IsTrue(((MessageType)15).IsValidMessageType());
            Assert.IsTrue(((MessageType)16).IsValidMessageType());
            Assert.IsTrue(((MessageType)17).IsValidMessageType());

            Assert.IsFalse(((MessageType)18).IsValidMessageType());
            Assert.IsFalse(((MessageType)19).IsValidMessageType());

            Assert.IsTrue(((MessageType)20).IsValidMessageType());
            Assert.IsTrue(((MessageType)21).IsValidMessageType());
            Assert.IsTrue(((MessageType)22).IsValidMessageType());

            Assert.IsFalse(((MessageType)23).IsValidMessageType());
            Assert.IsFalse(((MessageType)24).IsValidMessageType());
            Assert.IsFalse(((MessageType)25).IsValidMessageType());
            Assert.IsFalse(((MessageType)26).IsValidMessageType());
            Assert.IsFalse(((MessageType)27).IsValidMessageType());
            Assert.IsFalse(((MessageType)28).IsValidMessageType());
            Assert.IsFalse(((MessageType)29).IsValidMessageType());

            Assert.IsTrue(((MessageType)30).IsValidMessageType());

            Assert.IsFalse(((MessageType)31).IsValidMessageType());
        }
    }
}