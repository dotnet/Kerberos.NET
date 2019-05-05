using Kerberos.NET.Crypto;
using System;
using System.IO;

namespace Kerberos.NET.Entities
{
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
                DelegationTicket = new DelegationTicket().Decode(new Asn1Element(delegationTicket));
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

        public DelegationTicket DelegationTicket;

        public byte[] Extensions;
    }
}
