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
    /// <summary>
    /// The Privilege Attribute Certificate contains memberships, additional credential
    /// information, profile and policy information, and supporting security metadata.
    /// </summary>
    public class PrivilegedAttributeCertificate : Restriction
    {
        private const int PAC_VERSION = 0;

        private readonly Memory<byte> pacData;

        public PrivilegedAttributeCertificate() { }

        public PrivilegedAttributeCertificate(KrbAuthorizationData authz)
            : base(authz.Type, AuthorizationDataType.AdWin2kPac)
        {
            var pac = authz.Data;

            pacData = MemoryMarshal.AsMemory(pac);

            var stream = new NdrBuffer(pac, align: false);

            var count = stream.ReadInt32LittleEndian();

            Version = stream.ReadInt32LittleEndian();

            if (Version != PAC_VERSION)
            {
                throw new InvalidDataException($"Unknown PAC Version {Version}");
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
                    pacData.Span.Slice((int)offset + exclusionStart, exclusionLength).Clear();
                }
            }

            DecodingErrors = errors;
        }

        public IEnumerable<PacDecodeError> DecodingErrors { get; }

        private static readonly Dictionary<PacType, Type> KnownTypes = new Dictionary<PacType, Type>
        {
            { PacType.LOGON_INFO, typeof(PacLogonInfo) },
            { PacType.CREDENTIAL_TYPE, typeof(PacCredentialInfo) },
            { PacType.SERVER_CHECKSUM, typeof(PacSignature) },
            { PacType.PRIVILEGE_SERVER_CHECKSUM, typeof(PacSignature) },
            { PacType.CLIENT_NAME_TICKET_INFO, typeof(PacClientInfo) },
            { PacType.CONSTRAINED_DELEGATION_INFO, typeof(PacDelegationInfo) },
            { PacType.UPN_DOMAIN_INFO, typeof(UpnDomainInfo) },
            { PacType.CLIENT_CLAIMS, typeof(ClaimsSetMetadata) },
            //{ PacType.DEVICE_INFO, typeof(PacLogonInfo) },
            { PacType.DEVICE_CLAIMS, typeof(ClaimsSetMetadata) },
        };

        private readonly Dictionary<PacType, PacObject> attributes = new Dictionary<PacType, PacObject>();

        private void ParsePacType(PacType type, ReadOnlyMemory<byte> pacInfoBuffer, out int exclusionStart, out int exclusionLength)
        {
            exclusionStart = 0;
            exclusionLength = 0;

            if (!KnownTypes.TryGetValue(type, out Type pacObjectType))
            {
                return;
            }

            var attribute = (PacObject)Activator.CreateInstance(pacObjectType);

            if (pacInfoBuffer.Length > 0)
            {
                PacSignature signature = null;

                if (attribute is PacSignature)
                {
                    signature = (PacSignature)attribute;
                    signature.SignatureData = pacData;
                }

                attribute.Unmarshal(pacInfoBuffer);

                if (signature != null)
                {
                    exclusionStart = signature.SignaturePosition;
                    exclusionLength = signature.Signature.Length;
                }
            }

            attributes[type] = attribute;
        }

        private T GetAttribute<T>(PacType type)
            where T : PacObject
        {
            if (attributes.TryGetValue(type, out PacObject obj))
            {
                return (T)obj;
            }

            return null;
        }

        /// <summary>
        /// The protocol version of this instance.
        /// </summary>
        public long Version { get; private set; }

        /// <summary>
        /// The KERB_VALIDATION_INFO structure is a subset of the NETLOGON_VALIDATION_SAM_INFO4 structure
        /// ([MS-NRPC] section 2.2.1.4.13). It contains the authorization data of the user including
        /// group memberships.
        /// </summary>
        public PacLogonInfo LogonInfo
        {
            get => GetAttribute<PacLogonInfo>(PacType.LOGON_INFO);
            set => attributes[PacType.LOGON_INFO] = value;
        }

        /// <summary>
        /// Contains the signature of the PAC structure signed using the target service key.
        /// </summary>
        public PacSignature ServerSignature
        {
            get => GetAttribute<PacSignature>(PacType.SERVER_CHECKSUM);
            set => attributes[PacType.SERVER_CHECKSUM] = value;
        }

        /// <summary>
        /// A PAC_CREDENTIAL_INFO structure contains the user's encrypted  credentials. The Key Usage Number [RFC4120] used in
        /// the encryption is KERB_NON_KERB_SALT (16) [MS-KILE] section 3.1.5.9. The encryption key used is the AS reply key.
        /// The PAC credentials buffer is included only when PKINIT [RFC4556] is used. Therefore, the AS reply key is derived based on PKINIT.
        /// </summary>
        public PacCredentialInfo CredentialType
        {
            get => GetAttribute<PacCredentialInfo>(PacType.CREDENTIAL_TYPE);
            set => attributes[PacType.CREDENTIAL_TYPE] = value;
        }

        /// <summary>
        /// Contains the signature of the PAC structure signed using the KDC service key.
        /// </summary>
        public PacSignature KdcSignature
        {
            get => GetAttribute<PacSignature>(PacType.PRIVILEGE_SERVER_CHECKSUM);
            set => attributes[PacType.PRIVILEGE_SERVER_CHECKSUM] = value;
        }

        /// <summary>
        /// Contains the claims optionally issued for the client.
        /// </summary>
        public ClaimsSetMetadata ClientClaims
        {
            get => GetAttribute<ClaimsSetMetadata>(PacType.CLIENT_CLAIMS);
            set => attributes[PacType.CLIENT_CLAIMS] = value;
        }

        /// <summary>
        /// Contains the claims optionally issued for the device.
        /// </summary>
        public ClaimsSetMetadata DeviceClaims
        {
            get => GetAttribute<ClaimsSetMetadata>(PacType.DEVICE_CLAIMS);
            set => attributes[PacType.DEVICE_CLAIMS] = value;
        }

        /// <summary>
        /// It is used to verify that the PAC corresponds to the client of the ticket.
        /// </summary>
        public PacClientInfo ClientInformation
        {
            get => GetAttribute<PacClientInfo>(PacType.CLIENT_NAME_TICKET_INFO);
            set => attributes[PacType.CLIENT_NAME_TICKET_INFO] = value;
        }

        /// <summary>
        /// This structure contains the client's UPN and FQDN.
        /// It is used to provide the UPN and FQDN ) that corresponds to the client of the ticket.
        /// </summary>
        public UpnDomainInfo UpnDomainInformation
        {
            get => GetAttribute<UpnDomainInfo>(PacType.UPN_DOMAIN_INFO);
            set => attributes[PacType.UPN_DOMAIN_INFO] = value;
        }

        /// <summary>
        /// This structure lists the services that have been delegated through this Kerberos
        /// client and subsequent services or servers. The list is used only in a Service
        /// for User to Proxy (S4U2proxy) [MS-SFU] request. This feature could be used multiple
        /// times in succession from service to service.
        /// </summary>
        public PacDelegationInfo DelegationInformation
        {
            get => GetAttribute<PacDelegationInfo>(PacType.CONSTRAINED_DELEGATION_INFO);
            set => attributes[PacType.CONSTRAINED_DELEGATION_INFO] = value;
        }

        /// <summary>
        /// Indicates whether this PAC contains enough of the required fields to be included in the ticket.
        /// </summary>
        public bool HasRequiredFields => ServerSignature != null && KdcSignature != null;

        /// <summary>
        /// Encode the PAC as per [MS-PAC] and sign using both the KDC and service keys.
        /// </summary>
        /// <param name="kdcKey">The KDC service key</param>
        /// <param name="serverKey">The service key</param>
        /// <returns>Returns an encoded PAC structure</returns>
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
                element.Signature.Span.Clear();
            }

            var pacUnsigned = GeneratePac(pacElements);

            SignPac(pacElements, pacUnsigned, kdcKey, serverKey);

            return GeneratePac(pacElements);
        }

        private static void SignPac(IEnumerable<PacObject> pacElements, Memory<byte> pacUnsigned, KerberosKey kdcKey, KerberosKey serverKey)
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

        private static Memory<byte> GeneratePac(IEnumerable<PacObject> pacElements)
        {
            var buffer = new NdrBuffer(align: false);

            buffer.WriteInt32LittleEndian(pacElements.Count());
            buffer.WriteInt32LittleEndian(PAC_VERSION);

            var headerLength = 8 + (pacElements.Count() * 16);
            var offset = headerLength;

            foreach (var element in pacElements)
            {
                buffer.WriteInt32LittleEndian((int)element.PacType);

                // encoded value is cached internally within element
                // unless it's been marked dirty, which only happens
                // when it's been signed

                var encoded = element.Encode();

                buffer.WriteInt32LittleEndian(encoded.Length);
                buffer.WriteInt64LittleEndian(offset);

                offset += encoded.Length;
            }

            foreach (var element in pacElements)
            {
                // the encoded value is cached internally unless it's marked
                // as dirty, where it will be regenerated on next call to encode

                var encoded = element.Encode();

                buffer.WriteSpan(encoded.Span);
            }

            return buffer.ToMemory();
        }

        private IEnumerable<PacObject> CollectElements(KerberosKey kdcKey, KerberosKey serverKey)
        {
            var elements = new List<PacObject>();

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

        private static void AddIfNotNull(List<PacObject> elements, PacObject element)
        {
            if (element != null)
            {
                elements.Add(element);
            }
        }
    }
}
