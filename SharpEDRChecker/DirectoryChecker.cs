using System;
using System.Collections.Generic;
using System.IO;

namespace SharpEDRChecker
{
    internal class DirectoryChecker
    {
        internal static string CheckDirectories()
        {
            try
            {
                Console.WriteLine("########################################");
                Console.WriteLine("[!][!][!] Checking Directories [!][!][!]");
                Console.WriteLine("########################################\n");
                string summary = "";
                string[] progdirs = {
                    @"C:\Program Files",
                    @"C:\Program Files (x86)",
                    @"C:\ProgramData"};

                foreach (string dir in progdirs)
                {
                    string[] subdirectories = Directory.GetDirectories(dir);
                    summary += CheckDirectory(subdirectories);
                }
                if (string.IsNullOrEmpty(summary))
                {
                    Console.WriteLine("[+] No suspicious directories found\n");
                    return "\n[+] No suspicious directories found\n";
                }
                return $"\n[!] Directory Summary: \n{summary}\n";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking directories: {e.Message}\n{e.StackTrace}");
                return "\n[-] Errored on checking directories\n";
            }
        }

        private static string CheckDirectory(string[] subdirectories)
        {
            var summary = "";
            foreach (var subdirectory in subdirectories)
            {
                summary += CheckSubDirectory(subdirectory);  
            }
            return summary;
        }

        private static string CheckSubDirectory(string subdirectory)
        {
            try
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
                    Console.WriteLine($"[!] Matched on: {string.Join(", ", matches.ToArray())}\n");
                    return $"\t[-] {subdirectory} : {string.Join(", ", matches.ToArray())}\n";
                }
                return "";
            } 
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking sub directory: {subdirectory}\n{e.Message}\n{e.StackTrace}");
                return $"\t[-] {subdirectory} : Failed to perform checks\n";
            }
        }
    }
}