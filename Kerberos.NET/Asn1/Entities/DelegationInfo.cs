using Kerberos.NET.Entities;
using System;
using System.IO;
using System.Security.Cryptography.Asn1;

namespace Kerberos.NET.Asn1.Entities
{
    [Flags]
    public enum ChecksumFlag
    {
        GSS_C_DELEG_FLAG = 1 << 0,
        GSS_C_MUTUAL_FLAG = 1 << 1,
        GSS_C_REPLAY_FLAG = 1 << 2,
        GSS_C_SEQUENCE_FLAG = 1 << 3,
        GSS_C_CONF_FLAG = 1 << 4,
        GSS_C_INTEG_FLAG = 1 << 5,
        GSS_C_ANON_FLAG = 1 << 6,
        GSS_C_PROT_READY_FLAG = 1 << 7,
        GSS_C_TRANS_FLAG = 1 << 8,

        GSS_C_DCE_STYLE = 0x1000,
        GSS_C_IDENTIFY_FLAG = 0x2000,
        GSS_C_EXTENDED_ERROR_FLAG = 0x4000,
        GSS_C_AF_NETBIOS = 0x14
    }

    public class DelegationInfo
    {
        public DelegationInfo Decode(byte[] value)
        {
            var reader = new BinaryReader(new MemoryStream(value));

            Length = reader.ReadInt32();

            ChannelBinding = reader.ReadBytes(Length);

            Flags = (ChecksumFlag)BitConverter.ToInt32(reader.ReadBytes(4), 0);

            if (reader.BytesAvailable() > 0)
            {
                DelegationOption = reader.ReadInt16();
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
                DelegationTicket = Asn1.Entities.KrbCredApplication.Decode(delegationTicket, AsnEncodingRules.DER);
            }

            if (reader.BytesAvailable() > 0)
            {
                Extensions = reader.ReadBytes((int)reader.BytesAvailable());
            }

            return this;
        }

        public int Length;

        public byte[] ChannelBinding;

        public ChecksumFlag Flags;

        public int DelegationOption;

        public Asn1.Entities.KrbCredApplication DelegationTicket;

        public byte[] Extensions;
    }
}
