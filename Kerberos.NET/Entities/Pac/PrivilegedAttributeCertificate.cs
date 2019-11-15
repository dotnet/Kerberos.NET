using Kerberos.NET.Crypto;
using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Ndr;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

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

    public class PacCredentialInfo : PacObject, IPacElement
    {
        public int Version { get; set; }

        public EncryptionType EncryptionType { get; set; }

        public byte[] SerializedData { get; set; }

        public PacType PacType => PacType.CREDENTIAL_TYPE;

        public override ReadOnlySpan<byte> Marshal()
        {
            var buffer = new NdrBuffer();

            buffer.WriteInt32LittleEndian(Version);
            buffer.WriteInt32LittleEndian((int)EncryptionType);
            buffer.WriteSpan(SerializedData);

            return buffer.ToSpan();
        }

        public override void Unmarshal(ReadOnlyMemory<byte> bytes)
        {
            var stream = new NdrBuffer(bytes);

            Version = stream.ReadInt32LittleEndian();

            EncryptionType = (EncryptionType)stream.ReadInt32LittleEndian();

            SerializedData = stream.Read(stream.BytesAvailable).ToArray();
        }
    }

    public class PrivilegedAttributeCertificate : Restriction
    {
        private const int PAC_VERSION = 0;

        private readonly Memory<byte> pacData;

        public PrivilegedAttributeCertificate() { }

        public PrivilegedAttributeCertificate(KrbAuthorizationData authz)
            : base(authz.Type, AuthorizationDataType.AdWin2kPac)
        {
            var pac = authz.Data;

            var stream = new NdrBuffer(pac, align: false);

            pacData = MemoryMarshal.AsMemory(authz.Data);

            var count = stream.ReadInt32LittleEndian();
            var version = stream.ReadInt32LittleEndian();

            if (version != PAC_VERSION)
            {
                throw new InvalidDataException($"Unknown PAC Version {version}");
            }

            var errors = new List<PacDecodeError>();

            for (var i = 0; i < count; i++)
            {
                var type = (PacType)stream.ReadInt32LittleEndian();
                var size = stream.ReadInt32LittleEndian();

                var offset = stream.ReadInt64LittleEndian();

                var pacInfoBuffer = pac.Slice((int)offset, size);

                int exclusionStart;
                int exclusionLength;
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

                    throw;
                }

                if (exclusionStart > 0 && exclusionLength > 0)
                {
                    pacData.Span.Slice((int)offset + exclusionStart, exclusionLength).Fill(0);
                }
            }

            DecodingErrors = errors;
        }

        public IEnumerable<PacDecodeError> DecodingErrors { get; }

        private void ParsePacType(PacType type, ReadOnlyMemory<byte> pacInfoBuffer, out int exclusionStart, out int exclusionLength)
        {
            exclusionStart = 0;
            exclusionLength = 0;

            switch (type)
            {
                case PacType.LOGON_INFO:
                    LogonInfo = new PacLogonInfo();
                    LogonInfo.Unmarshal(pacInfoBuffer);
                    break;
                case PacType.CREDENTIAL_TYPE:
                    CredentialType = new PacCredentialInfo();
                    CredentialType.Unmarshal(pacInfoBuffer);
                    break;
                case PacType.SERVER_CHECKSUM:
                    ServerSignature = new PacSignature(pacData);
                    ServerSignature.Unmarshal(pacInfoBuffer);

                    exclusionStart = ServerSignature.SignaturePosition;
                    exclusionLength = ServerSignature.Signature.Length;
                    break;
                case PacType.PRIVILEGE_SERVER_CHECKSUM:
                    KdcSignature = new PacSignature(pacData);
                    KdcSignature.Unmarshal(pacInfoBuffer);

                    exclusionStart = KdcSignature.SignaturePosition;
                    exclusionLength = KdcSignature.Signature.Length;
                    break;
                case PacType.CLIENT_NAME_TICKET_INFO:
                    ClientInformation = new PacClientInfo();
                    ClientInformation.Unmarshal(pacInfoBuffer);
                    break;
                case PacType.CONSTRAINED_DELEGATION_INFO:
                    DelegationInformation = new PacDelegationInfo();
                    DelegationInformation.Unmarshal(pacInfoBuffer);
                    break;
                case PacType.UPN_DOMAIN_INFO:
                    UpnDomainInformation = new UpnDomainInfo();
                    UpnDomainInformation.Unmarshal(pacInfoBuffer);
                    break;
                case PacType.CLIENT_CLAIMS:
                    ClientClaims = new ClaimsSetMetadata();
                    ClientClaims.Unmarshal(pacInfoBuffer);
                    break;
                case PacType.DEVICE_INFO:
                    break;
                case PacType.DEVICE_CLAIMS:
                    DeviceClaims = new ClaimsSetMetadata();
                    DeviceClaims.Unmarshal(pacInfoBuffer);
                    break;
            }
        }

        public long Version { get; private set; }

        public PacLogonInfo LogonInfo { get; set; }

        public PacSignature ServerSignature { get; private set; }

        public PacCredentialInfo CredentialType { get; set; }

        public PacSignature KdcSignature { get; set; }

        public ClaimsSetMetadata ClientClaims { get; set; }

        public ClaimsSetMetadata DeviceClaims { get; set; }

        public PacClientInfo ClientInformation { get; set; }

        public UpnDomainInfo UpnDomainInformation { get; set; }

        public PacDelegationInfo DelegationInformation { get; set; }

        public bool HasRequiredFields => ServerSignature != null && KdcSignature != null;

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

            var pacElements = CollectElements(kdcKey, serverKey);

            // signing is weird because you need to generate the pac with the checksums empty
            // then hmac the entire thing before inserting the checksums into the body
            // presumably this should be safe to encode and sign and inject back into the 
            // original elements to then be encoded again.
            //
            // It's not efficient, but it's better than tracking where the checksum will
            // land in the encoded blob

            foreach (var element in pacElements.Where(e => e is PacSignature).Cast<PacSignature>())
            {
                element.Signature.Span.Fill(0);
            }

            var pacUnsigned = GeneratePac(pacElements);

            SignPac(pacElements, pacUnsigned, kdcKey, serverKey);

            return GeneratePac(pacElements);
        }

        private static void SignPac(IEnumerable<IPacElement> pacElements, Memory<byte> pacUnsigned, KerberosKey kdcKey, KerberosKey serverKey)
        {
            foreach (var element in pacElements.Where(e => e is PacSignature).Cast<PacSignature>())
            {
                if (element.PacType == PacType.SERVER_CHECKSUM)
                {
                    element.Sign(pacUnsigned, serverKey);
                }

                if (element.PacType == PacType.PRIVILEGE_SERVER_CHECKSUM)
                {
                    element.Sign(pacUnsigned, kdcKey);
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

                    // encoded value is cached internally within element
                    // unless it's been marked dirty, which only happens
                    // when it's been signed

                    var encoded = element.Encode();

                    writer.Write(encoded.Length);
                    writer.Write((long)offset);

                    offset += encoded.Length;
                }

                foreach (var element in pacElements)
                {
                    // the encoded value is cached internally unless it's marked
                    // as dirty, where it will be regenerated on next call to encode

                    var encoded = element.Encode();

                    writer.Write(encoded.ToArray());
                }

                writer.Flush();

                return stream.ToArray();
            }
        }

        private IEnumerable<IPacElement> CollectElements(KerberosKey kdcKey, KerberosKey serverKey)
        {
            var elements = new List<IPacElement>();

            AddIfNotNull(elements, this.LogonInfo);
            AddIfNotNull(elements, this.CredentialType);
            AddIfNotNull(elements, this.ClientClaims);
            AddIfNotNull(elements, this.DeviceClaims);
            AddIfNotNull(elements, this.ClientInformation);
            AddIfNotNull(elements, this.UpnDomainInformation);
            AddIfNotNull(elements, this.DelegationInformation);

            // don't care if they've been added to the parent PAC
            // explicitly add the server and kdc signatures here
            // so someone can't screw with the values within

            elements.Add(new PacSignature(PacType.SERVER_CHECKSUM, serverKey.EncryptionType));
            elements.Add(new PacSignature(PacType.PRIVILEGE_SERVER_CHECKSUM, kdcKey.EncryptionType));

            return elements;
        }

        private void AddIfNotNull(List<IPacElement> elements, IPacElement element)
        {
            if (element != null)
            {
                elements.Add(element);
            }
        }
    }

    internal interface IPacElement
    {
        PacType PacType { get; }

        ReadOnlyMemory<byte> Encode();
    }
}
