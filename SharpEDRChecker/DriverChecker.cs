﻿using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SharpEDRChecker
{
    internal class DriverChecker : IChecker
    {
        [DllImport("psapi")]
        private static extern bool EnumDeviceDrivers(
            [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)][In][Out] UIntPtr[] ddAddresses,
            uint arraySizeBytes,
            [MarshalAs(UnmanagedType.U4)] out uint bytesNeeded);

        [DllImport("psapi")]
        private static extern int GetDeviceDriverBaseName(
            UIntPtr ddAddress,
            StringBuilder ddBaseName,
            int baseNameStringSizeChars);

        [DllImport("psapi")]
        private static extern int GetDeviceDriverFileName(
            UIntPtr ddAddress,
            StringBuilder ddBaseName,
            int baseNameStringSizeChars);

        public string Name => "drivers";
        public string Check()
        {
            try
            {
                Console.WriteLine("####################################");
                Console.WriteLine("[!][!][!] Checking drivers [!][!][!]");
                Console.WriteLine("####################################\n");
                uint numberOfDrivers;
                UIntPtr[] driverAddresses;

                uint sizeOfDriverArrayInBytes = GetSizeOfDriversArray();
                if (sizeOfDriverArrayInBytes == 0)
                {
                    Console.WriteLine("[-] Error getting driver array size");
                    return "\n[-] Driver checks errored\n";
                }

                uint sizeOfOneDriverAddress = (uint)UIntPtr.Size;
                numberOfDrivers = sizeOfDriverArrayInBytes / sizeOfOneDriverAddress;
                driverAddresses = new UIntPtr[numberOfDrivers];

                bool success = EnumDeviceDrivers(driverAddresses, sizeOfDriverArrayInBytes, out sizeOfDriverArrayInBytes);

                if (!success)
                {
                    Console.WriteLine("[-] Call to EnumDeviceDrivers failed!");
                    int error = Marshal.GetLastWin32Error();
                    Console.WriteLine("[-] The last Win32 Error was: " + error);
                    return "\n[-] Driver checks errored\n";
                }

                var summary = IterateOverDrivers(numberOfDrivers, driverAddresses);

                if (string.IsNullOrEmpty(summary))
                {
                    Console.WriteLine("[+] No suspicious drivers found\n");
                    return "\n[+] No suspicious drivers found\n";
                }
                return $"\n[!] Driver Summary: \n{summary}";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking drivers: {e.Message}\n{e.StackTrace}");
                return "\n[-] Driver checks errored\n";
            }
        }

        private string IterateOverDrivers(uint arraySize, UIntPtr[] ddAddresses)
        {
            var summaryBag = new ConcurrentBag<string>();
            Parallel.For(0, arraySize, i =>
            {
                var driverFileName = GetDriverFileName(ddAddresses[i]);
                var driverBaseName = GetDriverBaseName(ddAddresses[i]);
                summaryBag.Add(CheckDriver(driverFileName, driverBaseName));
            });
            return string.Join("", summaryBag);
        }

        private string CheckDriver(string driverFileName, string driverBaseName)
        {
            try
            {
                var expandedPath = Environment.ExpandEnvironmentVariables(driverFileName.Replace(@"\??\", ""));
                var metadata = $"{FileChecker.GetFileInfo(expandedPath)}";
                var allattribs = $"{driverBaseName} - {metadata}";

                var matches = EDRMatcher.GetMatches(allattribs);
                if (matches.Count > 0)
                {
                    Console.WriteLine("[-] Suspicious driver found:" +
                                $"\n\tSuspicious Module: {driverBaseName}" +
                                $"\n\tFile Metadata: {metadata}" +
                                $"\n[!] Matched on: {string.Join(", ", matches.ToArray())}\n");
                    return $"\t[-] {driverBaseName} : {string.Join(", ", matches.ToArray())}\n";
                }
                return "";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking driver {driverBaseName} : {driverFileName}\n{e.Message}\n{e.StackTrace}");
                return $"\t[-] {driverBaseName} : Failed to perform checks\n";
            }
        }

        private string GetDriverBaseName(UIntPtr driverAddress)
        {
            StringBuilder driverBaseNamesb = new StringBuilder(1000);
            int result = GetDeviceDriverBaseName(driverAddress, driverBaseNamesb, driverBaseNamesb.Capacity);

            if (result == 0)
            {
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] The last Win32 Error was: " + error);
            }
            return driverBaseNamesb.ToString();
        }

        private string GetDriverFileName(UIntPtr driverAddress)
        {
            StringBuilder driverFileNamesb = new StringBuilder(1000);
            int result = GetDeviceDriverFileName(driverAddress, driverFileNamesb, driverFileNamesb.Capacity);

            if (result == 0)
            {
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] The last Win32 Error was: " + error);
            }
            return driverFileNamesb.ToString();
        }

        private uint GetSizeOfDriversArray()
        {
            uint bytesNeeded;
            bool success = EnumDeviceDrivers(null, 0, out bytesNeeded);

            if (!success)
            {
                Console.WriteLine("[-] Call to EnumDeviceDrivers failed!");
                int error = Marshal.GetLastWin32Error();
                Console.WriteLine("[-] The last Win32 Error was: " + error);
                return 0;
            }
            return bytesNeeded;
        }
    }
}
