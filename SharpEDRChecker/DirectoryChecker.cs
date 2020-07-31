using System;
using System.Collections.Generic;
using System.IO;

namespace SharpEDRChecker
{
    internal class DirectoryChecker
    {
        internal static string CheckDirectories()
        {
            Console.WriteLine("[!] Checking Directories...");
            bool foundSuspiciousDirectory = false;
            string[] progdirs = {
                @"C:\Program Files",
                @"C:\Program Files (x86)",
                @"C:\ProgramData"};

            foreach (string dir in progdirs)
            {
                string[] subdirectories = Directory.GetDirectories(dir);
                foreach (var subdirectory in subdirectories)
                {
                    var matches = new List<string>();
                    foreach (var edrstring in EDRData.edrlist)
                    {
                        if (subdirectory.ToString().ToLower().Contains(edrstring.ToLower()))
                        {
                            matches.Add(edrstring);
                        }
                    }
                    if (matches.Count > 0)
                    {
                        Console.WriteLine($"[-] Suspicious directory found: {subdirectory}");
                        Console.WriteLine($"[!] Matched on: {string.Join(", ", matches)}\n");
                        foundSuspiciousDirectory = true;
                    }
                }
            }
            if (!foundSuspiciousDirectory)
            {
                Console.WriteLine("[+] No suspicious directories found\n");
            }
            return "<Directory summary>";
        }
    }
}