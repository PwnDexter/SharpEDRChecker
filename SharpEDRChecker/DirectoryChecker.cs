using System;
using System.IO;

namespace SharpEDRChecker
{
    internal class DirectoryChecker
    {
        internal static void CheckDirectories()
        {
            Console.WriteLine("[!] Checking Directories");
            {
                string[] progdirs = {
                    @"C:\Program Files",
                    @"C:\Program Files (x86)",
                    @"C:\ProgramData"};

                foreach (string dir in progdirs)
                {
                    string[] subdirectories = Directory.GetDirectories(dir);
                    Console.WriteLine("Directories:");

                    foreach (var subdirectory in subdirectories)
                    {
                        Console.WriteLine(subdirectory);
                    }
                }
            }
        }
    }
}