using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace SharpEDRChecker
{
    internal class AdsChecker : IChecker
    {
        public string Name => "ads";
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr FindFirstStreamW(string lpFileName, STREAM_INFO_LEVELS InfoLevel, out WIN32_FIND_STREAM_DATA lpFindStreamData, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool FindNextStreamW(IntPtr hFindFile, out WIN32_FIND_STREAM_DATA lpFindStreamData);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FindClose(IntPtr hFindFile);

        private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        private enum STREAM_INFO_LEVELS
        {
            FindStreamInfoStandard = 0
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WIN32_FIND_STREAM_DATA
        {
            public long StreamSize;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 296)]
            public string cStreamName;
        }

        public string Check()
        {
            var summaryBuilder = new StringBuilder();
            try
            {
                Console.WriteLine("###################################################");
                Console.WriteLine("[!][!][!] Checking for Alternate Data Streams [!][!][!]");
                Console.WriteLine("###################################################\n");

                var dirsToCheck = new List<string> {
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
                };

                foreach (var dir in dirsToCheck)
                {
                    try
                    {
                        var files = Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories);
                        foreach (var file in files)
                        {
                            summaryBuilder.Append(CheckFileForAds(file));
                        }
                    }
                    catch (UnauthorizedAccessException)
                    {
                        Console.WriteLine($"[-] Access denied to directory, cannot check for ADS: {dir}");
                    }
                }

                var summary = summaryBuilder.ToString();
                if (string.IsNullOrEmpty(summary))
                {
                    Console.WriteLine("[+] No suspicious Alternate Data Streams found\n");
                    return "\n[+] No suspicious Alternate Data Streams found\n";
                }
                return $"\n[!] Alternate Data Streams Summary: \n{summary}\n";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking for ADS: {e.Message}\n{e.StackTrace}");
                return "\n[-] Errored on checking for ADS\n";
            }
        }

        private string CheckFileForAds(string filePath)
        {
            var summaryBuilder = new StringBuilder();
            IntPtr hFind = FindFirstStreamW(filePath, STREAM_INFO_LEVELS.FindStreamInfoStandard, out var findStreamData, 0);

            if (hFind == INVALID_HANDLE_VALUE)
            {
                return "";
            }

            try
            {
                do
                {
                    // The default stream is ::$DATA, we want to check others
                    if (findStreamData.cStreamName != "::$DATA")
                    {
                        var matches = EDRMatcher.GetMatches(findStreamData.cStreamName);
                        if (matches.Count > 0)
                        {
                            Console.WriteLine($"[-] Suspicious Alternate Data Stream found:" +
                                              $"\n\tFile: {filePath}" +
                                              $"\n\tStream Name: {findStreamData.cStreamName}" +
                                              $"\n[!] Matched on: {string.Join(", ", matches.ToArray())}\n");
                            summaryBuilder.Append($"\t[-] {filePath}{findStreamData.cStreamName} : {string.Join(", ", matches.ToArray())}\n");
                        }
                    }
                } while (FindNextStreamW(hFind, out findStreamData));
            }
            finally
            {
                FindClose(hFind);
            }
            return summaryBuilder.ToString();
        }
    }
}
