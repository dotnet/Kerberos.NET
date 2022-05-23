// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities.Pac;
using Kerberos.NET.Ndr;

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

        public PrivilegedAttributeCertificate()
        {
        }

        public PrivilegedAttributeCertificate(KrbAuthorizationData authz, SignatureMode mode = SignatureMode.Kdc)
            : base(authz?.Type ?? 0, AuthorizationDataType.AdWin2kPac)
        {
            var pac = authz.Data;

            this.pacData = new byte[pac.Length];
            this.Mode = mode;

            pac.CopyTo(this.pacData);

            using (var stream = new NdrBuffer(pac, align: false))
            {
                var count = stream.ReadInt32LittleEndian();

                this.Version = stream.ReadInt32LittleEndian();

                if (this.Version != PAC_VERSION)
                {
                    throw new InvalidDataException($"Unknown PAC Version {this.Version}");
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
                        this.ParsePacType(type, pacInfoBuffer, out exclusionStart, out exclusionLength);
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
                        this.pacData.Span.Slice((int)offset + exclusionStart, exclusionLength).Clear();
                    }
                }

                this.DecodingErrors = errors;
            }
        }

        public SignatureMode Mode { get; }

        public IEnumerable<PacDecodeError> DecodingErrors { get; }

        public static void RegisterType(PacType pacType, Type type)
        {
            KnownTypes[pacType] = type;
        }

        [KerberosIgnore]
        public IDictionary<PacType, PacObject> Attributes => this.attributes;

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

            // { PacType.DEVICE_INFO, typeof(PacLogonInfo) },
            { PacType.DEVICE_CLAIMS, typeof(ClaimsSetMetadata) },
        };

        private readonly Dictionary<PacType, PacObject> attributes = new Dictionary<PacType, PacObject>();

        private void ParsePacType(PacType type, ReadOnlyMemory<byte> pacInfoBuffer, out int exclusionStart, out int exclusionLength)
        {
            exclusionStart = 0;
            exclusionLength = 0;

            if (!KnownTypes.TryGetValue(type, out Type pacObjectType))
            {
                this.Attributes[type] = new UnknownPacObject(type, pacInfoBuffer);
                return;
            }

            var attribute = (PacObject)Activator.CreateInstance(pacObjectType);

            if (pacInfoBuffer.Length <= 0)
            {
                return;
            }

            PacSignature signature = null;

            if (attribute is PacSignature sig)
            {
                signature = this.ProcessSignature(sig, type);

                if (!this.Mode.HasFlag(SignatureMode.Kdc) && type == PacType.PRIVILEGE_SERVER_CHECKSUM)
                {
                    signature.Ignored = true;
                }
            }

            attribute.Unmarshal(pacInfoBuffer);

            if (signature != null)
            {
                exclusionStart = signature.SignaturePosition;
                exclusionLength = signature.Signature.Length;
            }

            this.Attributes[type] = attribute;
        }

        private PacSignature ProcessSignature(PacSignature signature, PacType type)
        {
            if (type == PacType.PRIVILEGE_SERVER_CHECKSUM)
            {
                signature.SignatureData = this.ServerSignature.Signature;
            }
            else
            {
                signature.SignatureData = this.pacData;
            }

            return signature;
        }

        private T GetAttribute<T>(PacType type)
            where T : PacObject
        {
            if (this.Attributes.TryGetValue(type, out PacObject obj))
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
            get => this.GetAttribute<PacLogonInfo>(PacType.LOGON_INFO);
            set => this.Attributes[PacType.LOGON_INFO] = value;
        }

        /// <summary>
        /// Contains the signature of the PAC structure signed using the target service key.
        /// </summary>
        public PacSignature ServerSignature
        {
            get => this.GetAttribute<PacSignature>(PacType.SERVER_CHECKSUM);
            set => this.Attributes[PacType.SERVER_CHECKSUM] = value;
        }

        /// <summary>
        /// A PAC_CREDENTIAL_INFO structure contains the user's encrypted  credentials. The Key Usage Number [RFC4120] used in
        /// the encryption is KERB_NON_KERB_SALT (16) [MS-KILE] section 3.1.5.9. The encryption key used is the AS reply key.
        /// The PAC credentials buffer is included only when PKINIT [RFC4556] is used. Therefore, the AS reply key is derived based on PKINIT.
        /// </summary>
        public PacCredentialInfo CredentialType
        {
            get => this.GetAttribute<PacCredentialInfo>(PacType.CREDENTIAL_TYPE);
            set => this.Attributes[PacType.CREDENTIAL_TYPE] = value;
        }

        /// <summary>
        /// Contains the signature of the PAC structure signed using the KDC service key.
        /// </summary>
        public PacSignature KdcSignature
        {
            get => this.GetAttribute<PacSignature>(PacType.PRIVILEGE_SERVER_CHECKSUM);
            set => this.Attributes[PacType.PRIVILEGE_SERVER_CHECKSUM] = value;
        }

        /// <summary>
        /// Contains the claims optionally issued for the client.
        /// </summary>
        public ClaimsSetMetadata ClientClaims
        {
            get => this.GetAttribute<ClaimsSetMetadata>(PacType.CLIENT_CLAIMS);
            set => this.Attributes[PacType.CLIENT_CLAIMS] = value;
        }

        /// <summary>
        /// Contains the claims optionally issued for the device.
        /// </summary>
        public ClaimsSetMetadata DeviceClaims
        {
            get => this.GetAttribute<ClaimsSetMetadata>(PacType.DEVICE_CLAIMS);
            set => this.Attributes[PacType.DEVICE_CLAIMS] = value;
        }

        /// <summary>
        /// It is used to verify that the PAC corresponds to the client of the ticket.
        /// </summary>
        public PacClientInfo ClientInformation
        {
            get => this.GetAttribute<PacClientInfo>(PacType.CLIENT_NAME_TICKET_INFO);
            set => this.Attributes[PacType.CLIENT_NAME_TICKET_INFO] = value;
        }

        /// <summary>
        /// This structure contains the client's UPN and FQDN.
        /// It is used to provide the UPN and FQDN ) that corresponds to the client of the ticket.
        /// </summary>
        public UpnDomainInfo UpnDomainInformation
        {
            get => this.GetAttribute<UpnDomainInfo>(PacType.UPN_DOMAIN_INFO);
            set => this.Attributes[PacType.UPN_DOMAIN_INFO] = value;
        }

        /// <summary>
        /// This structure lists the services that have been delegated through this Kerberos
        /// client and subsequent services or servers. The list is used only in a Service
        /// for User to Proxy (S4U2proxy) [MS-SFU] request. This feature could be used multiple
        /// times in succession from service to service.
        /// </summary>
        public PacDelegationInfo DelegationInformation
        {
            get => this.GetAttribute<PacDelegationInfo>(PacType.CONSTRAINED_DELEGATION_INFO);
            set => this.Attributes[PacType.CONSTRAINED_DELEGATION_INFO] = value;
        }

        /// <summary>
        /// Indicates whether this PAC contains enough of the required fields to be included in the ticket.
        /// </summary>
        public bool HasRequiredFields => this.ServerSignature != null && this.KdcSignature != null;

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

            if (kdcKey == null)
            {
                throw new ArgumentNullException(nameof(kdcKey));
            }

            if (serverKey == null)
            {
                throw new ArgumentNullException(nameof(serverKey));
            }

            var pacElements = this.CollectElements(kdcKey, serverKey);

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
            PacSignature serverSignature = null;

            foreach (var element in pacElements.Where(e => e is PacSignature).OrderBy(e => e.PacType).Cast<PacSignature>())
            {
                if (element.PacType == PacType.SERVER_CHECKSUM)
                {
                    serverSignature = element;

                    element.Sign(pacUnsigned, serverKey);
                }

                if (element.PacType == PacType.PRIVILEGE_SERVER_CHECKSUM)
                {
                    element.Sign(serverSignature.Signature, kdcKey);
                }
            }
        }

        private static int Align(int position, int mask)
        {
            var shift = position & mask - 1;

            return shift == 0 ? 0 : 8 - shift;
        }

        [DebuggerDisplay("{Type} {Offset} {Length}")]
        private struct PacBuffer
        {
            public PacType Type { get; set; }

            public int Length { get; set; }

            public int Offset { get; set; }

            public PacObject Element { get; set; }
        }

        private static Memory<byte> GeneratePac(IEnumerable<PacObject> pacElements)
        {
            var pacCount = pacElements.Count();

            var offset = 8 + (pacCount * 16);

            var buffers = new PacBuffer[pacCount];

            for (var i = 0; i < buffers.Length; i++)
            {
                var element = pacElements.ElementAt(i);

                offset += Align(offset, 8);

                var pacBuffer = new PacBuffer
                {
                    Type = element.PacType,
                    Element = element,
                    Length = element.Encode().Length,
                    Offset = offset
                };

                offset += pacBuffer.Length;

                buffers[i] = pacBuffer;
            }

            using (var bufferRented = CryptoPool.Rent<byte>(offset))
            {
                var memory = bufferRented.Memory.Slice(0, offset);
                // Clean up shared buffer
                memory.Span.Clear();

                using (var buffer = new NdrBuffer(memory, align: false))
                {
                    buffer.WriteInt32LittleEndian(pacCount);
                    buffer.WriteInt32LittleEndian(PAC_VERSION);

                    foreach (var element in buffers)
                    {
                        buffer.WriteInt32LittleEndian((int)element.Type);

                        // encoded value is cached internally within element
                        // unless it's been marked dirty, which only happens
                        // when it's been signed

                        buffer.WriteInt32LittleEndian(element.Length);
                        buffer.WriteInt64LittleEndian(element.Offset);

                        buffer.WriteSpan(element.Element.Encode().Span, element.Offset);
                    }

                    return buffer.ToMemory(alignment: 8);
                }
            }
        }

        private IEnumerable<PacObject> CollectElements(KerberosKey kdcKey, KerberosKey serverKey)
        {
            var elements = new List<PacObject>();

            // don't care if they've been added to the parent PAC
            // explicitly add the server and kdc signatures here
            // so someone can't screw with the values within

            this.ServerSignature = new PacSignature(PacType.SERVER_CHECKSUM, serverKey.EncryptionType);
            this.KdcSignature = new PacSignature(PacType.PRIVILEGE_SERVER_CHECKSUM, kdcKey.EncryptionType);

            foreach (var kv in this.Attributes)
            {
                AddIfNotNull(elements, kv.Value);
            }

            return elements;
        }

        private static void AddIfNotNull(List<PacObject> elements, PacObject element)
        {
            if (element != null)
            {
                element.IsDirty = true;

                elements.Add(element);
            }
        }
    }
}
