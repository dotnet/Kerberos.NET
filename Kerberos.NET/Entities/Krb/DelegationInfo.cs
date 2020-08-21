// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.IO;

namespace Kerberos.NET.Entities
{
    [Flags]
#pragma warning disable CA1714 // Flags enums should have plural names
    public enum GssContextEstablishmentFlag
    {
        GSS_C_NONE = -1,

        GSS_C_DELEG_FLAG = 1 << 0,
        GSS_C_MUTUAL_FLAG = 1 << 1,
        GSS_C_REPLAY_FLAG = 1 << 2,
        GSS_C_SEQUENCE_FLAG = 1 << 3,
        GSS_C_CONF_FLAG = 1 << 4,
        GSS_C_INTEG_FLAG = 1 << 5,
        GSS_C_ANON_FLAG = 1 << 6,
        GSS_C_PROT_READY_FLAG = 1 << 7,
        GSS_C_TRANS_FLAG = 1 << 8,

        GSS_C_DCE_STYLE = 1 << 12,
        GSS_C_IDENTIFY_FLAG = 1 << 13,
        GSS_C_EXTENDED_ERROR_FLAG = 1 << 14
    }

    public class DelegationInfo
    {
        public const int GSS_C_AF_NETBIOS = 0x14;

        public const int ChannelBindingLength = 0x10;

        public DelegationInfo()
        {
        }

        public DelegationInfo(RequestServiceTicket rst)
        {
            this.Flags = rst.GssContextFlags;
        }

        public ReadOnlyMemory<byte> Encode()
        {
            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream))
            {
                if (this.ChannelBinding.Length == 0)
                {
                    this.ChannelBinding = new byte[ChannelBindingLength];
                }

                writer.Write(this.ChannelBinding.Length);
                writer.Write(this.ChannelBinding.ToArray());

                if (this.DelegationTicket != null)
                {
                    this.Flags |= GssContextEstablishmentFlag.GSS_C_DELEG_FLAG;
                }

                writer.Write((int)this.Flags);

                if (this.DelegationTicket != null)
                {
                    writer.Write((short)this.DelegationOption);

                    var deleg = this.DelegationTicket.EncodeApplication();

                    writer.Write((short)deleg.Length);

                    writer.Write(deleg.ToArray());
                }

                return stream.ToArray();
            }
        }

        public DelegationInfo Decode(ReadOnlyMemory<byte> value)
        {
            using (var reader = new BinaryReader(new MemoryStream(value.ToArray())))
            {
                this.Length = reader.ReadInt32();

                this.ChannelBinding = reader.ReadBytes(this.Length);

                this.Flags = (GssContextEstablishmentFlag)reader.ReadBytes(4).AsLong(littleEndian: true);

                if (reader.BytesAvailable() > 0)
                {
                    this.DelegationOption = reader.ReadInt16();
                }

                int delegationLength = 0;

                if (reader.BytesAvailable() > 0)
                {
                    delegationLength = reader.ReadInt16();
                }

                byte[] delegationTicket = null;

                if (reader.BytesAvailable() > 0)
                {
                    delegationTicket = reader.ReadBytes(delegationLength);
                }

                if (delegationTicket != null && delegationTicket.Length > 0)
                {
                    this.DelegationTicket = KrbCred.DecodeApplication(delegationTicket);
                }

                if (reader.BytesAvailable() > 0)
                {
                    this.Extensions = reader.ReadBytes((int)reader.BytesAvailable());
                }
            }

            return this;
        }

        public int Length { get; set; }

        public ReadOnlyMemory<byte> ChannelBinding { get; set; }

        public GssContextEstablishmentFlag Flags { get; set; }

        public int DelegationOption { get; set; }

        public KrbCred DelegationTicket { get; set; }

        public ReadOnlyMemory<byte> Extensions { get; set; }
    }
}