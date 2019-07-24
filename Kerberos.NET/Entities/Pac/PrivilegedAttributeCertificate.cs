using Kerberos.NET.Crypto;
using Kerberos.NET.Entities.Pac;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Kerberos.NET.Entities
{
    public enum PacType
    {
        LOGON_INFO = 1,
        CREDENTIAL_TYPE = 2,
        SERVER_CHECKSUM = 6,
        PRIVILEGE_SERVER_CHECKSUM = 7,
        CLIENT_NAME_TICKET_INFO = 0x0000000A,
        CONSTRAINED_DELEGATION_INFO = 0x0000000B,
        UPN_DOMAIN_INFO = 0x0000000C,
        CLIENT_CLAIMS = 0x0000000D,
        DEVICE_INFO = 0x0000000E,
        DEVICE_CLAIMS = 0x0000000F
    }

    public class PacCredentialInfo : NdrObject
    {
        public PacCredentialInfo(byte[] info)
            : base(info)
        {
            Version = Stream.ReadInt();

            EncryptionType = (EncryptionType)Stream.ReadInt();

            SerializedData = Stream.ReadToEnd();
        }

        public int Version { get; }

        public EncryptionType EncryptionType { get; }

        public byte[] SerializedData { get; }
    }

    public class PrivilegedAttributeCertificate : NdrObject
    {
        private const int PAC_VERSION = 0;

        private readonly byte[] pacData;

        public PrivilegedAttributeCertificate()
            : base(new NdrBinaryStream())
        { }

        public PrivilegedAttributeCertificate(byte[] pac)
            : base(pac)
        {
            pacData = new byte[pac.Length];

            Buffer.BlockCopy(pac, 0, pacData, 0, pac.Length);

            var count = Stream.ReadInt();
            var version = Stream.ReadInt();

            if (version != PAC_VERSION)
            {
                throw new InvalidDataException($"Unknown PAC Version {version}");
            }

            var errors = new List<PacDecodeError>();

            for (var i = 0; i < count; i++)
            {
                var type = (PacType)Stream.ReadInt();
                var size = Stream.ReadInt();

                var offset = Stream.ReadLong();
                var pacInfoBuffer = new byte[size];

                Buffer.BlockCopy(pac, (int)offset, pacInfoBuffer, 0, size);

                int exclusionStart = 0;
                int exclusionLength = 0;

                try
                {
                    ParsePacType(type, pacInfoBuffer, out exclusionStart, out exclusionLength);
                }
                catch (Exception ex)
                {
                    errors.Add(new PacDecodeError()
                    {
                        Type = type,
                        Data = pacInfoBuffer,
                        Exception = ex
                    });
                }

                if (exclusionStart > 0 && exclusionLength > 0)
                {
                    ZeroArray(pacData, offset + exclusionStart, exclusionLength);
                }
            }

            DecodingErrors = errors;

            HasRequiredFields = ServerSignature != null && KdcSignature != null;
        }

        private static void ZeroArray(byte[] signatureData, long start, int exclusionEnd)
        {
            for (var i = start; i < start + exclusionEnd; i++)
            {
                signatureData[i] = 0;
            }
        }

        public IEnumerable<PacDecodeError> DecodingErrors { get; }

        private void ParsePacType(PacType type, byte[] pacInfoBuffer, out int exclusionStart, out int exclusionLength)
        {
            exclusionStart = 0;
            exclusionLength = 0;

            switch (type)
            {
                case PacType.LOGON_INFO:
                    LogonInfo = new PacLogonInfo(pacInfoBuffer);
                    break;
                case PacType.CREDENTIAL_TYPE:
                    CredentialType = new PacCredentialInfo(pacInfoBuffer);
                    break;
                case PacType.SERVER_CHECKSUM:
                    ServerSignature = new PacSignature(pacInfoBuffer, pacData);

                    exclusionStart = ServerSignature.SignaturePosition;
                    exclusionLength = ServerSignature.Signature.Length;
                    break;
                case PacType.PRIVILEGE_SERVER_CHECKSUM:
                    KdcSignature = new PacSignature(pacInfoBuffer, pacData);

                    exclusionStart = KdcSignature.SignaturePosition;
                    exclusionLength = KdcSignature.Signature.Length;
                    break;
                case PacType.CLIENT_NAME_TICKET_INFO:
                    ClientInformation = new PacClientInfo(pacInfoBuffer);
                    break;
                case PacType.CONSTRAINED_DELEGATION_INFO:
                    DelegationInformation = new PacDelegationInfo(pacInfoBuffer);
                    break;
                case PacType.UPN_DOMAIN_INFO:
                    UpnDomainInformation = new UpnDomainInfo(pacInfoBuffer);
                    break;
                case PacType.CLIENT_CLAIMS:
                    ClientClaims = new ClaimsSetMetadata(pacInfoBuffer);
                    break;
                case PacType.DEVICE_INFO:
                    break;
                case PacType.DEVICE_CLAIMS:
                    DeviceClaims = new ClaimsSetMetadata(pacInfoBuffer);
                    break;
            }
        }

        public long Version { get; private set; }

        public PacLogonInfo LogonInfo { get; private set; }

        public PacSignature ServerSignature { get; private set; }

        public PacCredentialInfo CredentialType { get; private set; }

        public PacSignature KdcSignature { get; private set; }

        public ClaimsSetMetadata ClientClaims { get; private set; }

        public ClaimsSetMetadata DeviceClaims { get; private set; }

        public PacClientInfo ClientInformation { get; private set; }

        public UpnDomainInfo UpnDomainInformation { get; private set; }

        public PacDelegationInfo DelegationInformation { get; private set; }

        public bool HasRequiredFields { get; private set; }

        public ReadOnlyMemory<byte> Encode(KerberosKey kdcKey, KerberosKey serverKey)
        {
            // pac format
            // 
            // int: number of pac elements
            // int: version = 0
            // 
            // for count
            // {
            //    int: pac type
            //    int: element size in bytes
            //    long: offset
            // }
            // 
            // offset
            // {
            // ...
            // }

            var pacElements = CollectElements();

            var pac = GeneratePac(pacElements);

            SignPac(pacElements, pac, kdcKey, serverKey);

            return pac;
        }

        private static void SignPac(IEnumerable<IPacElement> pacElements, Memory<byte> pac, KerberosKey kdcKey, KerberosKey serverKey)
        {
            foreach (var element in pacElements.Where(e => e.RequiresKdcSignature || e.RequiresServerSignature))
            {
                if (element.RequiresServerSignature)
                {
                    element.Sign(pac, serverKey);
                }

                if (element.RequiresKdcSignature)
                {
                    element.Sign(pac, kdcKey);
                }
            }
        }

        private static Memory<byte> GeneratePac(IEnumerable<IPacElement> pacElements)
        {
            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream))
            {
                writer.Write(pacElements.Count());
                writer.Write(PAC_VERSION);

                var headerLength = 8 + (pacElements.Count() * 16);
                var offset = headerLength;

                foreach (var element in pacElements)
                {
                    writer.Write((int)element.PacType);

                    var encoded = element.Encode();

                    writer.Write(encoded.Length);
                    writer.Write(offset);

                    offset += encoded.Length;
                }

                foreach (var element in pacElements)
                {
                    var encoded = element.Encode();

                    writer.Write(encoded.ToArray());
                }

                writer.Flush();

                return stream.ToArray();
            }
        }

        private IEnumerable<IPacElement> CollectElements()
        {
            var elements = new List<IPacElement>();

            return elements;
        }
    }

    internal interface IPacElement
    {
        PacType PacType { get; }

        bool RequiresKdcSignature { get; }

        bool RequiresServerSignature { get; }

        ReadOnlyMemory<byte> Encode();

        void Sign(Memory<byte> pac, KerberosKey key);
    }
}
