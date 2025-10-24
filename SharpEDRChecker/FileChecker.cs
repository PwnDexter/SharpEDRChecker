﻿using System;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace SharpEDRChecker
{
    class FileChecker
    {
        internal static string GetFileInfo(string filePath)
        {
            FileVersionInfo fileVersionInfo;
            try
            {
                fileVersionInfo = FileVersionInfo.GetVersionInfo(filePath);
                var sb = new StringBuilder();
                sb.AppendLine($"\n \t\t Product Name: {fileVersionInfo.ProductName}");
                sb.AppendLine($" \t\t Filename: {fileVersionInfo.FileName}");
                sb.AppendLine($" \t\t Original Filename: {fileVersionInfo.OriginalFilename}");
                sb.AppendLine($" \t\t Internal Name: {fileVersionInfo.InternalName}");
                sb.AppendLine($" \t\t Company Name: {fileVersionInfo.CompanyName}");
                sb.AppendLine($" \t\t File Description: {fileVersionInfo.FileDescription}");
                sb.AppendLine($" \t\t Product Version: {fileVersionInfo.ProductVersion}");
                sb.AppendLine($" \t\t Comments: {fileVersionInfo.Comments}");
                sb.AppendLine($" \t\t Legal Copyright: {fileVersionInfo.LegalCopyright}");
                sb.AppendLine($" \t\t Legal Trademarks: {fileVersionInfo.LegalTrademarks}");
                return sb.ToString();
            }
            catch (FileNotFoundException)
            {
                if (filePath.ToLower().StartsWith(@"c:\windows\system32\"))
                {
                    filePath = filePath.ToLower().Replace(@"c:\windows\system32\", @"c:\Windows\Sysnative\");
                    return GetFileInfo(filePath);
                }
                else
                {
                    Console.WriteLine($"[!] Could not get file info for: {filePath}\n");
                    return "";
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Errored on getting file info for: {filePath}\n{e.Message}\n{e.StackTrace}");
                return "";
            }
        }
    }
}
