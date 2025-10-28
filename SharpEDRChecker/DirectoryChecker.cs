﻿﻿﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SharpEDRChecker
{
    internal class DirectoryChecker : IChecker
    {
        public string Name => "directories";
        public string Check()
        {
            try
            {
                Console.WriteLine("########################################");
                Console.WriteLine("[!][!][!] Checking Directories [!][!][!]");
                Console.WriteLine("########################################\n");
                var summaryBuilder = new StringBuilder();
                var progdirs = new List<string> {
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData) };

                foreach (string dir in progdirs)
                {
                    try
                    {
                        string[] subdirectories = Directory.GetDirectories(dir);
                        summaryBuilder.Append(CheckDirectory(subdirectories));
                    }
                    catch (UnauthorizedAccessException)
                    {
                        Console.WriteLine($"[-] Access denied to directory, cannot list subdirectories: {dir}\n");
                    }
                }
                if (summaryBuilder.Length == 0)
                {
                    Console.WriteLine("[+] No suspicious directories found\n");
                    return "\n[+] No suspicious directories found\n";
                }
                return $"\n[!] Directory Summary: \n{summaryBuilder.ToString()}\n";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking directories: {e.Message}\n{e.StackTrace}");
                return "\n[-] Errored on checking directories\n";
            }
        }

        private string CheckDirectory(string[] subdirectories)
        {
            var summaryBuilder = new StringBuilder();
            foreach (string subdirectory in subdirectories)
            {
                summaryBuilder.Append(CheckSubDirectory(subdirectory));
            }
            return summaryBuilder.ToString();
        }

        private string CheckSubDirectory(string subdirectory)
        {
            try
            {
                var matches = EDRMatcher.GetMatches(subdirectory);
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
