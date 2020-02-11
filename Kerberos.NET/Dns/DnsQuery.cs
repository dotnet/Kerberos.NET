using Kerberos.NET.Crypto;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;

namespace Kerberos.NET.Dns
{
    public static class DnsQuery
    {
        public static IEnumerable<DnsRecord> QuerySrv(string query)
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
            {
                throw new InvalidOperationException("DNS query is not supported on non-Win32 platforms yet");
            }

            if (Debug)
            {
                System.Diagnostics.Debug.WriteLine($"Trying to query for {query}");
            }

            return DnsQueryWin32.QuerySrvRecord(query);
        }

        public static bool Debug
        {
            get => DnsQueryWin32.Debug;
            set => DnsQueryWin32.Debug = value;
        }
    }

    [DebuggerDisplay("{Type} {Target} {Weight}")]
    public class DnsRecord
    {
        private readonly DateTimeOffset stamp;

        public DnsRecord()
        {
            stamp = DateTimeOffset.UtcNow;
        }

        public string Name { get; set; }

        public string Target { get; set; }

        public IEnumerable<DnsRecord> Canonical { get; set; } = new List<DnsRecord>();

        public DnsRecordType Type { get; set; }

        public int TimeToLive { get; set; }

        public int Priority { get; set; }

        public int Weight { get; set; }

        public int Port { get; set; }

        public bool Ignore { get; set; }

        public bool Purge => Ignore || Expired;

        public bool Expired => stamp.AddSeconds(TimeToLive) <= DateTimeOffset.UtcNow;
    }

    [Flags]
    public enum DnsQueryOptions
    {
        Standard = 0x0,
        AcceptTruncatedResponse = 0x1,
        UseTcpOnly = 0x2,
        NoRecursion = 0x4,
        BypassCache = 0x8,
        NoWireQuery = 0x10,
        NoLocalName = 0x20,
        NoHostsFile = 0x40,
        NoNetBios = 0x80,
        WireOnly = 0x100,
        ReturnMessage = 0x200,
        MulticastOnly = 0x400,
        NoMulticast = 0x800,
        TreatAsFullyQualifiedDomain = 0x1000,
        AddrConfig = 0x2000,
        DualAddr = 0x4000,
        MulticastWait = 0x20000,
        MulticastVerify = 0x40000,
        DontResetTtlValues = 0x100000,
        DisableIdnEncoding = 0x200000,
        AppendMultiLabel = 0x800000
    }

    public enum DnsRecordType : ushort
    {
        A = 0x0001,
        NS = 0x0002,
        MD = 0x0003,
        MF = 0x0004,
        CNAME = 0x0005,
        SOA = 0x0006,
        MB = 0x0007,
        MG = 0x0008,
        MR = 0x0009,
        NULL = 0x000a,
        WKS = 0x000b,
        PTR = 0x000c,
        HINFO = 0x000d,
        MINFO = 0x000e,
        MX = 0x000f,
        TEXT = 0x0010,
        RP = 0x0011,
        AFSDB = 0x0012,
        X25 = 0x0013,
        ISDN = 0x0014,
        RT = 0x0015,
        NSAP = 0x0016,
        NSAPPTR = 0x0017,
        SIG = 0x0018,
        KEY = 0x0019,
        PX = 0x001a,
        GPOS = 0x001b,
        AAAA = 0x001c,
        LOC = 0x001d,
        NXT = 0x001e,
        EID = 0x001f,
        NIMLOC = 0x0020,
        SRV = 0x0021,
        ATMA = 0x0022,
        NAPTR = 0x0023,
        KX = 0x0024,
        CERT = 0x0025,
        A6 = 0x0026,
        DNAME = 0x0027,
        SINK = 0x0028,
        OPT = 0x0029,
        DS = 0x002B,
        RRSIG = 0x002E,
        NSEC = 0x002F,
        DNSKEY = 0x0030,
        DHCID = 0x0031,
        UINFO = 0x0064,
        UID = 0x0065,
        GID = 0x0066,
        UNSPEC = 0x0067,
        ADDRS = 0x00f8,
        TKEY = 0x00f9,
        TSIG = 0x00fa,
        IXFR = 0x00fb,
        AXFR = 0x00fc,
        MAILB = 0x00fd,
        MAILA = 0x00fe,
        ALL = 0x00ff,
        ANY = 0x00ff,
        WINS = 0xff01,
        WINSR = 0xff02,
        NBSTAT = WINSR
    }

    internal unsafe static class DnsQueryWin32
    {
        private const string DNSAPI = "dnsapi.dll";

        [DllImport(DNSAPI, EntryPoint = "DnsQuery_W", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int DnsQuery(
            [In] string pszName,
            DnsRecordType wType,
            DnsQueryOptions options,
            IntPtr pExtra,
            [Out] out IntPtr ppQueryResults,
            IntPtr pReserved
        );

        [DllImport(DNSAPI, CharSet = CharSet.Auto, SetLastError = true)]
        private static extern void DnsRecordListFree(IntPtr pRecordList, DnsFreeType FreeType);

        internal const DnsQueryOptions DefaultOptions = DnsQueryOptions.BypassCache;

        public static bool Debug { get; set; }

        private static readonly HashSet<int> IgnoredErrors = new HashSet<int>() {
            9002, // server not found
            9003, // record not found
        };

        public static IEnumerable<DnsRecord> QuerySrvRecord(string query, DnsQueryOptions options = DefaultOptions)
        {
            var error = DnsQuery(
                query,
                DnsRecordType.SRV,
                options,
                IntPtr.Zero,
                out IntPtr ppQueryResults,
                IntPtr.Zero
            );

            if (Debug && ppQueryResults != IntPtr.Zero)
            {
                // IntPtr.Size + 2 + 2 + 2 + 4 + 4 + 4;

                var dump = ppQueryResults.DumpHex((uint)Marshal.SizeOf<Win32DnsRecord>());

                System.Diagnostics.Debug.WriteLine(dump);
            }

            var records = new List<DnsRecord>();

            try
            {
                if (IgnoredErrors.Contains(error))
                {
                    return records;
                }

                if (error != 0)
                {
                    throw new Win32Exception(error);
                }

                Win32DnsRecord dnsRecord;

                for (var pNext = ppQueryResults; pNext != IntPtr.Zero; pNext = dnsRecord.pNext)
                {
                    dnsRecord = Marshal.PtrToStructure<Win32DnsRecord>(pNext);

                    switch (dnsRecord.wType)
                    {
                        case DnsRecordType.SRV:
                            var srvRecord = Marshal.PtrToStructure<Win32SrvRecord>(pNext);

                            records.Add(new DnsRecord
                            {
                                Target = srvRecord.pNameTarget,
                                Name = srvRecord.pName,
                                Port = srvRecord.wPort,
                                Priority = srvRecord.wPriority,
                                TimeToLive = srvRecord.dwTtl,
                                Type = srvRecord.wType,
                                Weight = srvRecord.wWeight
                            });
                            break;
                        case DnsRecordType.A:
                            var aRecord = Marshal.PtrToStructure<Win32ARecord>(pNext);
                            records.Add(new DnsRecord
                            {
                                Type = aRecord.wType,
                                Name = aRecord.pName,
                                Target = new IPAddress(aRecord.IPAddress).ToString()
                            });
                            break;

                        case DnsRecordType.AAAA:
                            var aaaaRecord = Marshal.PtrToStructure<Win32AAAARecord>(pNext);

                            records.Add(new DnsRecord
                            {
                                Type = aaaaRecord.wType,
                                Name = aaaaRecord.pName,
                                Target = new IPAddress(aaaaRecord.IPAddress).ToString()
                            });
                            break;
                    }
                }
            }
            finally
            {
                DnsRecordListFree(ppQueryResults, DnsFreeType.DnsFreeRecordList);
            }

            var merged = records.Where(r => r.Type != DnsRecordType.SRV).GroupBy(r => r.Name);

            foreach (var srv in records.Where(r => r.Type == DnsRecordType.SRV))
            {
                var c1 = merged.Where(m => m.Key.Equals(srv.Target, StringComparison.InvariantCultureIgnoreCase));

                var canon = c1.SelectMany(r => r);

                srv.Canonical = canon.ToList();
            }

            return records;
        }

        private enum DnsFreeType
        {
            DnsFreeFlat,
            DnsFreeRecordList,
            DnsFreeParsedMessageFields
        }

        [DebuggerDisplay("{wType} {pName} {wDataLength}")]
        [StructLayout(LayoutKind.Sequential)]
        private struct Win32DnsRecord
        {
            public IntPtr pNext;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pName;
            public DnsRecordType wType;
            public ushort wDataLength;

            public int flags;
            public int dwTtl;
            public int dwReserved;
        }

        [DebuggerDisplay("{wType} {IPAddress}")]
        [StructLayout(LayoutKind.Sequential)]
        private struct Win32ARecord
        {
            public IntPtr pNext;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pName;
            public DnsRecordType wType;
            public ushort wDataLength;

            public int flags;
            public int dwTtl;
            public int dwReserved;

            public long IPAddress;
        }

        [DebuggerDisplay("{wType} {IPAddress}")]
        [StructLayout(LayoutKind.Sequential)]
        private struct Win32AAAARecord
        {
            public IntPtr pNext;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pName;
            public DnsRecordType wType;
            public ushort wDataLength;

            public int flags;
            public int dwTtl;
            public int dwReserved;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] IPAddress;
        }

        [DebuggerDisplay("{wType} {pNameTarget}")]
        [StructLayout(LayoutKind.Sequential)]
        private struct Win32SrvRecord
        {
            public IntPtr pNext;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pName;
            public DnsRecordType wType;
            public ushort wDataLength;

            public int flags;
            public int dwTtl;
            public int dwReserved;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string pNameTarget;
            public ushort wPriority;
            public ushort wWeight;
            public ushort wPort;
            public ushort Pad;
        }
    }
}
