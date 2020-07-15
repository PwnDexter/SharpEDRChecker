using System;
using System.IO;

namespace SharpEDRChecker
{
    internal class DirectoryChecker
    {
        internal static void CheckDirectories()
        {
            Console.WriteLine("[!] Checking Directories...");
            bool foundSuspiciousDirectory = false;
            {
                string[] progdirs = {
                    @"C:\Program Files",
                    @"C:\Program Files (x86)",
                    @"C:\ProgramData"};

                foreach (string dir in progdirs)
                {
                    string[] subdirectories = Directory.GetDirectories(dir);
                    foreach (var subdirectory in subdirectories)
                    {
                        foreach (var edrstring in EDRData.edrlist)
                        {
                            if (subdirectory.ToString().ToLower().Contains(edrstring.ToLower()))
                            {
                                Console.WriteLine($"[-] Suspicious directory found: {subdirectory}");
                                Console.WriteLine($"[!] Matched on: {edrstring}\n");
                                foundSuspiciousDirectory = true;
                            }
                        }
                    }
                }
            }
            if (!foundSuspiciousDirectory)
            {
                Console.WriteLine("[+] No suspicious directories found\n");
            }
        }
    }
}