// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;

namespace Kerberos.NET.Dns
{
    public unsafe class DnsQueryPOSIX
    {
        private const int NS_PACKETSZ = 512;
        private const int NS_MAXDNAME = 1025;

        private const string LIBC = "libc.so";

        [DllImport(LIBC, EntryPoint = "res_query")]
        private static extern short ResQuery(
            [MarshalAs(UnmanagedType.LPStr)] string dname,
            NsClass @class,
            DnsRecordType type,
            char[] answer,
            int anslen
        );

        [DllImport(LIBC, EntryPoint = "ns_initparse")]
        private static extern short NsInitParse(
            // [MarshalAs(UnmanagedType.LPStr)] string msg,
            char[] msg,
            short msglen,
            NsMsg* handle
        );

        [DllImport(LIBC, EntryPoint = "ns_msg_count")]
        private static extern ushort NsMsgCount(
            NsMsg handle,
            NsSect section
        );

        [DllImport(LIBC, EntryPoint = "ns_parserr")]
        private static extern short NsParserr(
            NsMsg* handle,
            NsSect section,
            short rrnum,
            NsRr* rr
        );

        [DllImport(LIBC, EntryPoint = "ns_rr_type")]
        private static extern DnsRecordType NsRrType(
            NsRr rr
        );

        [DllImport(LIBC, EntryPoint = "ns_msg_base")]
        private static extern string NsMsgBase(
            NsMsg handle
        );

        [DllImport(LIBC, EntryPoint = "ns_msg_end")]
        private static extern string NsMsgEnd(
            NsMsg handle
        );

        [DllImport(LIBC, EntryPoint = "ns_rr_rdata")]
        private static extern string NsRrRdata(
            NsRr rr
        );

        [DllImport(LIBC, EntryPoint = "dn_expand")]
        private static extern short DnExpand(
            [MarshalAs(UnmanagedType.LPStr)] string msg,
            [MarshalAs(UnmanagedType.LPStr)] string eomorig,
            [MarshalAs(UnmanagedType.LPStr)] string comp_dn,
            StringBuilder exp_dn,
            short length
        );

        [DllImport(LIBC, EntryPoint = "ns_rr_name")]
        private static extern string NsRrName(
            NsRr rr
        );

        [DllImport(LIBC, EntryPoint = "inet_ntoa")]
        private static extern string InetNToA(
            InAddr @in
        );

        public static IReadOnlyCollection<DnsRecord> QuerySrvRecord(
            string query,
            DnsRecordType type,
            DnsQueryOptions options = DnsQueryOptions.BypassCache)
        {
            var list = new List<DnsRecord>();
            var buffer = new char[NS_PACKETSZ];

            short respLen = -1;
            if ((respLen = ResQuery(query, NsClass.NsCIn, type, buffer, NS_PACKETSZ)) < 0)
                throw new Exception($"Query for {query} failed!");

            NsMsg handle;
            if (NsInitParse(buffer, respLen, &handle) < 0)
                throw new Exception("Failed to parse response buffer!");

            var count = NsMsgCount(handle, NsSect.NsSAn);
            Debug.WriteLine($"{count} records returned in the answer section.");

            for (short i = 0; i < count; i++)
            {
                NsRr rr;
                if (NsParserr(&handle, NsSect.NsSAn, i, &rr) < 0)
                    throw new Exception("ns_parserr: TODO strerror");

                if (NsRrType(rr) != DnsRecordType.SRV) continue;

                var name = new StringBuilder(1025);
                short ret;
                if ((ret = DnExpand(NsMsgBase(handle),
                        NsMsgEnd(handle),
                        NsRrRdata(rr) + 6,
                        name,
                        1025)) < 0)
                    throw new Exception($"Failed to uncompress name ({ret})");

                Debug.WriteLine(name);

                var p = NsRrRdata(rr);
                var ip = new InAddr
                {
                    s_addr = ((uint) p[3] << 24) | ((uint) p[2] << 16) | ((uint) p[1] << 8) | p[0]
                };

                list.Add(new DnsRecord
                {
                    Target = InetNToA(ip),
                    Name = rr.name.ToString(),
                    //Port =
                    //Priority =
                    TimeToLive = (int) rr.ttl,
                    Type = rr.type,
                    //Weight = rr.
                });
            }

            for (short i = 0; i < NsMsgCount(handle, NsSect.NsSAr); i++)
            {
                NsRr rr;
                if (NsParserr(&handle, NsSect.NsSAr, i, &rr) < 0)
                    throw new Exception("ns_parserr: TODO strerror");

                if (NsRrType(rr) != DnsRecordType.A) continue;

                var p = NsRrRdata(rr);
                var ip = new InAddr
                {
                    s_addr = ((uint) p[3] << 24) | ((uint) p[2] << 16) | ((uint) p[1] << 8) | p[0]
                };

                Debug.WriteLine($"{NsRrName(rr)} has address {InetNToA(ip)}");

                list.Add(new DnsRecord
                {
                    Type = rr.type,
                    Name = rr.name.ToString(),
                    Target = InetNToA(ip)
                });
            }

            return list;
        }

        private struct InAddr
        {
            public uint s_addr;
        }

        private struct NsRr
        {
            [MarshalAs(UnmanagedType.LPArray, SizeConst = NS_PACKETSZ)]
            public char[] name;
            public DnsRecordType type;
            public ushort rr_class;
            public uint ttl;
            public ushort rdlength;
            [MarshalAs(UnmanagedType.LPStr)]
            public string rdata;
        }

        private enum NsSect
        {
            NsSQd = 0, /*%< Query: Question. */
            NsSZn = 0, /*%< Update: Zone. */
            NsSAn = 1, /*%< Query: Answer. */
            NsSPr = 1, /*%< Update: Prerequisites. */
            NsSNs = 2, /*%< Query: Name servers. */
            NsSUd = 2, /*%< Update: Update. */
            NsSAr = 3, /*%< Query|Update: Additional records. */
            NsSMax = 4
        }

        private struct NsMsg
        {
            [MarshalAs(UnmanagedType.LPStr)] public string _msg, _eom;
            public ushort _id, _flags;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = (int) NsSect.NsSMax)]
            public ushort[] _counts;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = (int) NsSect.NsSMax)]
            public string[] _sections;
            public NsSect _sect;
            public short _rrnum;
            [MarshalAs(UnmanagedType.LPStr)]
            public string _msg_ptr;
        }

        private enum NsClass : ushort
        {
            NsCInvalid,
            NsCIn,
            NsC2,
            NsCChaos,
            NsCHs,
            NsCNone = 254,
            NsCAny,
            NsCMax = 65535
        }
    }
}
