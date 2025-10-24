using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpEDRChecker
{
    internal class NetworkChecker : IChecker
    {
        public string Name => "network";
        // Based on https://stackoverflow.com/a/536553
        private const int AF_INET = 2;

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, TCP_TABLE_CLASS tableClass, uint reserved = 0);

        public string Check()
        {
            var summaryBuilder = new StringBuilder();
            try
            {
                Console.WriteLine("##################################################");
                Console.WriteLine("[!][!][!] Checking Network Connections [!][!][!]");
                Console.WriteLine("##################################################\n");

                int bufferSize = 0;
                // Get the required buffer size
                GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);

                IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);

                try
                {
                    if (GetExtendedTcpTable(tcpTablePtr, ref bufferSize, true, AF_INET, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL) == 0)
                    {
                        var table = (MIB_TCPTABLE_OWNER_PID)Marshal.PtrToStructure(tcpTablePtr, typeof(MIB_TCPTABLE_OWNER_PID));
                        IntPtr rowPtr = (IntPtr)((long)tcpTablePtr + Marshal.SizeOf(table.dwNumEntries));

                        for (int i = 0; i < table.dwNumEntries; i++)
                        {
                            var row = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));
                            summaryBuilder.Append(CheckConnection(row));
                            rowPtr = (IntPtr)((long)rowPtr + Marshal.SizeOf(row));
                        }
                    }
                    else
                    {
                        Console.WriteLine("[-] Failed to retrieve TCP table.");
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(tcpTablePtr);
                }

                var summary = summaryBuilder.ToString();
                if (string.IsNullOrEmpty(summary))
                {
                    Console.WriteLine("[+] No suspicious network connections found\n");
                    return "\n[+] No suspicious network connections found\n";
                }
                return $"\n[!] Network Connection Summary: \n{summary}\n";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking network connections: {e.Message}\n{e.StackTrace}");
                return "\n[-] Errored on checking network connections\n";
            }
        }

        private string CheckConnection(MIB_TCPROW_OWNER_PID connection)
        {
            string processName = "N/A";
            string processPath = "N/A";
            string metadata = "";
            string allattribs = "";

            try
            {
                Process p = Process.GetProcessById((int)connection.owningPid);
                processName = p.ProcessName;
                if (p.MainModule != null)
                {
                    processPath = p.MainModule.FileName;
                    metadata = FileChecker.GetFileInfo(processPath);
                }
            }
            catch (ArgumentException)
            {
                // Can fail if process exits or access is denied
            }

            allattribs = $"{processName} - {processPath} - {metadata}";
            var matches = EDRMatcher.GetMatches(allattribs);

            if (matches.Count > 0)
            {
                Console.WriteLine($"[-] Suspicious network connection found:" +
                            $"\n\tProcess: {processName} (PID: {connection.owningPid})" +
                            $"\n\tBinary: {processPath}" +
                            $"\n\tLocal: {connection.LocalAddress}:{connection.LocalPort}" +
                            $"\n\tRemote: {connection.RemoteAddress}:{connection.RemotePort}" +
                            $"\n\tState: {connection.State}" +
                            $"\n\tFile Metadata: {metadata}" +
                            $"\n[!] Matched on: {string.Join(", ", matches.ToArray())}\n");
                return $"\t[-] {processName} : {string.Join(", ", matches.ToArray())}\n";
            }
            return "";
        }

        #region PInvoke Structures
        private enum TCP_TABLE_CLASS
        {
            TCP_TABLE_BASIC_LISTENER,
            TCP_TABLE_BASIC_CONNECTIONS,
            TCP_TABLE_BASIC_ALL,
            TCP_TABLE_OWNER_PID_LISTENER,
            TCP_TABLE_OWNER_PID_CONNECTIONS,
            TCP_TABLE_OWNER_PID_ALL,
            TCP_TABLE_OWNER_MODULE_LISTENER,
            TCP_TABLE_OWNER_MODULE_CONNECTIONS,
            TCP_TABLE_OWNER_MODULE_ALL
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPTABLE_OWNER_PID
        {
            public uint dwNumEntries;
            private readonly MIB_TCPROW_OWNER_PID table;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public MibTcpState State;
            public readonly uint localAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            private readonly byte[] localPort;
            public readonly uint remoteAddr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            private readonly byte[] remotePort;
            public readonly uint owningPid;

            public IPAddress LocalAddress => new IPAddress(localAddr);
            public ushort LocalPort => BitConverter.ToUInt16(new byte[2] { localPort[1], localPort[0] }, 0);
            public IPAddress RemoteAddress => new IPAddress(remoteAddr);
            public ushort RemotePort => BitConverter.ToUInt16(new byte[2] { remotePort[1], remotePort[0] }, 0);
        }

        private enum MibTcpState
        {
            CLOSED = 1,
            LISTEN = 2,
            SYN_SENT = 3,
            SYN_RCVD = 4,
            ESTAB = 5,
            FIN_WAIT1 = 6,
            FIN_WAIT2 = 7,
            CLOSE_WAIT = 8,
            CLOSING = 9,
            LAST_ACK = 10,
            TIME_WAIT = 11,
            DELETE_TCB = 12
        }
        #endregion
    }
}
