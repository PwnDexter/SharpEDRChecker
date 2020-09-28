using System;
using System.Collections.Generic;
using System.Management;

namespace SharpEDRChecker
{
    internal class ServiceChecker
    {
        internal static string CheckServices()
        {
            Console.WriteLine("#####################################");
            Console.WriteLine("[!][!][!] Checking Services [!][!][!]");
            Console.WriteLine("#####################################\n");
            try
            {
                var serviceList = new ManagementObjectSearcher("Select * From Win32_Service").Get();
                string summary = "";
                foreach (var service in serviceList)
                {
                    summary += CheckService(service);
                }
                if (string.IsNullOrEmpty(summary))
                {
                    Console.WriteLine("[+] No suspicious services found\n");
                    return "\n[+] No suspicious services found\n";
                }
                return $"\n[!] Service Summary: \n{summary}\n";
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on checking services: {e.Message}\n{e.StackTrace}");
                return "\n[-] Errored on checking services\n";
            }
        }

        private static string CheckService(ManagementBaseObject service)
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
                    var indexOfExe = servicePathName.ToString().ToLower().IndexOf(".exe");
                    var filePath = servicePathName.ToString().Substring(0, indexOfExe + ".exe".Length).Trim('"');
                    metadata = $"{FileChecker.GetFileInfo(filePath)}";
                    allattribs = $"{allattribs} - {metadata}";
                }

                var matches = new List<string>();
                foreach (var edrstring in EDRData.edrlist)
                {
                    if (allattribs.ToLower().Contains(edrstring.ToLower()))
                    {
                        matches.Add(edrstring);
                    }
                }
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