using System;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpEDRChecker
{
    internal class DnsCacheChecker : IChecker
    {
        public string Name => "dnscache";
        [DllImport("dnsapi.dll", EntryPoint = "DnsQuery_W", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        private static extern int DnsQuery(
            [MarshalAs(UnmanagedType.LPWStr)] string pszName,
            ushort wType,
            uint options,
            IntPtr pExtra,
            ref IntPtr ppQueryResults,
            IntPtr pReserved);

        [DllImport("dnsapi.dll", EntryPoint = "DnsRecordListFree")]
        private static extern void DnsRecordListFree(IntPtr pRecordList, int freeType);

        private const ushort DNS_TYPE_ANY = 0xFF;
        private const uint DNS_QUERY_CACHE_ONLY = 0x00000080;

        public string Check()
        {
            var summaryBuilder = new StringBuilder();
            IntPtr pDnsRecord = IntPtr.Zero;

            try
            {
                Console.WriteLine("#####################################");
                Console.WriteLine("[!][!][!] Checking DNS Cache [!][!][!]");
                Console.WriteLine("#####################################\n");

                // Query the entire DNS cache
                int result = DnsQuery(null, DNS_TYPE_ANY, DNS_QUERY_CACHE_ONLY, IntPtr.Zero, ref pDnsRecord, IntPtr.Zero);

                if (result == 0 && pDnsRecord != IntPtr.Zero)
                {
                    IntPtr pCurrent = pDnsRecord;
                    while (pCurrent != IntPtr.Zero)
                    {
                        var record = (DNS_RECORD)Marshal.PtrToStructure(pCurrent, typeof(DNS_RECORD));
                        summaryBuilder.Append(CheckDnsRecord(record));

                        pCurrent = record.pNext;
                    }
                }

                var summary = summaryBuilder.ToString();
                if (string.IsNullOrEmpty(summary))
                {
                    Console.WriteLine("[+] No suspicious DNS cache entries found\n");
                    return "\n[+] No suspicious DNS cache entries found\n";
                }
                return $"\n[!] DNS Cache Summary: \n{summary}\n";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking DNS cache: {e.Message}\n{e.StackTrace}");
                return "\n[-] Errored on checking DNS cache\n";
            }
            finally
            {
                if (pDnsRecord != IntPtr.Zero)
                {
                    DnsRecordListFree(pDnsRecord, 1); // 1 for DnsFreeRecordList
                }
            }
        }

        private string CheckDnsRecord(DNS_RECORD record)
        {
            if (string.IsNullOrEmpty(record.pName))
            {
                return "";
            }

            var matches = EDRMatcher.GetMatches(record.pName);
            if (matches.Count > 0)
            {
                Console.WriteLine($"[-] Suspicious DNS cache entry found:" +
                                  $"\n\tEntry: {record.pName}" +
                                  $"\n[!] Matched on: {string.Join(", ", matches.ToArray())}\n");
                return $"\t[-] {record.pName} : {string.Join(", ", matches.ToArray())}\n";
            }
            return "";
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct DNS_RECORD
        {
            public IntPtr pNext;
            public string pName;
            public ushort wType;
            public ushort wDataLength;
            public uint flags;
            public uint dwTtl;
            public uint dwReserved;
            // Data follows here, but we only need the name
        }
    }
}
