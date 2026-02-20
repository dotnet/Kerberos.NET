// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.IO;
using System.Security.Cryptography;

namespace Kerberos.NET.Entities
{
    /// <summary>
    /// Represents gss_channel_bindings_struct per RFC 4121 section 4.1.1.2.
    /// </summary>
    public class GssChannelBindings
    {
        public int InitiatorAddrType { get; set; }

        public ReadOnlyMemory<byte> InitiatorAddress { get; set; }

        public int AcceptorAddrType { get; set; }

        public ReadOnlyMemory<byte> AcceptorAddress { get; set; }

        /// <summary>
        /// Protocol-specific channel binding data
        /// e.g. tls-server-end-point or tls-unique as per RFC 5929
        /// </summary>
        public ReadOnlyMemory<byte> ApplicationData { get; set; }

        /// <summary>
        /// Computes the 16-byte MD5 binding hash (Bnd field) per RFC 4121 section 4.1.1.2.
        /// </summary>
        public ReadOnlyMemory<byte> ComputeBindingHash()
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream);

            writer.Write(this.InitiatorAddrType);
            writer.Write(this.InitiatorAddress.Length);

            if (this.InitiatorAddress.Length > 0)
            {
                writer.Write(this.InitiatorAddress.ToArray());
            }

            writer.Write(this.AcceptorAddrType);
            writer.Write(this.AcceptorAddress.Length);

            if (this.AcceptorAddress.Length > 0)
            {
                writer.Write(this.AcceptorAddress.ToArray());
            }

            writer.Write(this.ApplicationData.Length);

            if (this.ApplicationData.Length > 0)
            {
                writer.Write(this.ApplicationData.ToArray());
            }

            var data = stream.ToArray();

            using var md5 = MD5.Create();
            return md5.ComputeHash(data);
        }
    }
}
