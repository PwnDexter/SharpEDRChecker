using System.Security.Principal;

namespace SharpEDRChecker
{
    internal class PrivilegeChecker
    {
        internal static bool PrivCheck()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
    }
}