// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Dns
{
    internal static unsafe class DnsQueryWin32
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

        private static readonly HashSet<int> IgnoredErrors = new HashSet<int>()
        {
            9002, // server not found (DNS_ERROR_RCODE_SERVER_FAILURE)
            9003, // record not found (DNS_ERROR_RCODE_NAME_ERROR)
            9501, // record not found (DNS_INFO_NO_RECORDS)
        };

        public static IReadOnlyCollection<DnsRecord> QuerySrvRecord(string query, DnsRecordType type, DnsQueryOptions options = DefaultOptions)
        {
            var error = DnsQuery(
                query,
                type,
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

                for (var pNext = ppQueryResults; pNext != IntPtr.Zero; pNext = dnsRecord.PNext)
                {
                    dnsRecord = Marshal.PtrToStructure<Win32DnsRecord>(pNext);

                    switch (dnsRecord.WType)
                    {
                        case DnsRecordType.SRV:
                            var srvRecord = Marshal.PtrToStructure<Win32SrvRecord>(pNext);

                            records.Add(new DnsRecord
                            {
                                Target = srvRecord.PNameTarget,
                                Name = srvRecord.PName,
                                Port = srvRecord.WPort,
                                Priority = srvRecord.WPriority,
                                TimeToLive = srvRecord.DwTtl,
                                Type = srvRecord.WType,
                                Weight = srvRecord.WWeight
                            });
                            break;
                        case DnsRecordType.A:
                            var aRecord = Marshal.PtrToStructure<Win32ARecord>(pNext);
                            records.Add(new DnsRecord
                            {
                                Type = aRecord.WType,
                                Name = aRecord.PName,
                                Target = new IPAddress(aRecord.IPAddress).ToString()
                            });
                            break;

                        case DnsRecordType.AAAA:
                            var aaaaRecord = Marshal.PtrToStructure<Win32AAAARecord>(pNext);

                            records.Add(new DnsRecord
                            {
                                Type = aaaaRecord.WType,
                                Name = aaaaRecord.PName,
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
            public IntPtr PNext;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string PName;
            public DnsRecordType WType;
            public ushort WDataLength;

            public int Flags;
            public int DwTtl;
            public int DwReserved;
        }

        [DebuggerDisplay("{wType} {IPAddress}")]
        [StructLayout(LayoutKind.Sequential)]
        private struct Win32ARecord
        {
            public IntPtr PNext;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string PName;
            public DnsRecordType WType;
            public ushort WDataLength;

            public int Flags;
            public int DwTtl;
            public int DwReserved;

            public long IPAddress;
        }

        [DebuggerDisplay("{wType} {IPAddress}")]
        [StructLayout(LayoutKind.Sequential)]
        private struct Win32AAAARecord
        {
            public IntPtr PNext;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string PName;
            public DnsRecordType WType;
            public ushort WDataLength;

            public int Flags;
            public int DwTtl;
            public int DwReserved;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] IPAddress;
        }

        [DebuggerDisplay("{wType} {pNameTarget}")]
        [StructLayout(LayoutKind.Sequential)]
        private struct Win32SrvRecord
        {
            public IntPtr PNext;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string PName;
            public DnsRecordType WType;
            public ushort WDataLength;

            public int Flags;
            public int DwTtl;
            public int DwReserved;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string PNameTarget;
            public ushort WPriority;
            public ushort WWeight;
            public ushort WPort;
            public ushort Pad;
        }
    }
}
