﻿using System;
using System.Collections.Generic;
using System.Management;
using System.Text;

namespace SharpEDRChecker
{
    internal class ServiceChecker : IChecker
    {
        public string Name => "services";
        public string Check()
        {
            Console.WriteLine("#####################################");
            Console.WriteLine("[!][!][!] Checking Services [!][!][!]");
            Console.WriteLine("#####################################\n");
            try
            {
                var wmiQuery = "Select Name, DisplayName, Description, Caption, PathName, State, ProcessId From Win32_Service";
                var serviceList = new ManagementObjectSearcher(wmiQuery).Get();
                var summaryBuilder = new StringBuilder();
                foreach (var service in serviceList)
                {
                    summaryBuilder.Append(CheckService(service));
                }
                if (summaryBuilder.Length == 0)
                {
                    Console.WriteLine("[+] No suspicious services found\n");
                    return "\n[+] No suspicious services found\n";
                }
                return $"\n[!] Service Summary: \n{summaryBuilder.ToString()}\n";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking services: {e.Message}\n{e.StackTrace}");
                return "\n[-] Errored on checking services\n";
            }
        }

        private string CheckService(ManagementBaseObject service)
        {
            try
            {
                var serviceName = service["Name"];
                var serviceDisplayName = service["DisplayName"];
                var serviceDescription = service["Description"];
                var serviceCaption = service["Caption"];
                var servicePathName = service["PathName"];
                var serviceState = service["State"];
                var servicePID = service["ProcessId"];
                var metadata = "";

                var allattribs = $"{serviceName} - " +
                    $"{serviceDisplayName} - " +
                    $"{serviceDescription} - " +
                    $"{serviceCaption} - " +
                    $"{servicePathName}";

                if (servicePathName != null)
                {
                    try
                    {
                        var indexOfExe = servicePathName.ToString().ToLower().IndexOf(".exe");
                        if (indexOfExe != -1)
                        {
                            var filePath = servicePathName.ToString().Substring(0, indexOfExe + ".exe".Length).Trim('"');
                            metadata = $"{FileChecker.GetFileInfo(filePath)}";
                            allattribs = $"{allattribs} - {metadata}";
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[-] Could not get file metadata for service binary: {servicePathName}\n[-] {e.Message}\n");
                    }
                }

                var matches = EDRMatcher.GetMatches(allattribs);
                if (matches.Count > 0)
                {
                    Console.WriteLine($"[-] Suspicious service found:" +
                           $"\n\tName: {serviceName}" +
                           $"\n\tDisplayName: {serviceDisplayName}" +
                           $"\n\tDescription: {serviceDescription}" +
                           $"\n\tCaption: {serviceCaption}" +
                           $"\n\tBinary: {servicePathName}" +
                           $"\n\tStatus: {serviceState}" +
                           $"\n\tProcess ID: {servicePID}" +
                           $"\n\tFile Metadata: {metadata}" +
                           $"\n[!] Matched on: {string.Join(", ", matches.ToArray())}\n");
                    return $"\t[-] {serviceName} : {string.Join(", ", matches.ToArray())}\n";
                }
                return "";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking individual service: {service["Name"]}\n{e.Message}\n{e.StackTrace}");
                return $"\t[-] {service["Name"]} : Failed to perform checks\n";
            }
        }
    }
}
