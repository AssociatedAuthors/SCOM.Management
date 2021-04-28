 

#=================================================================================
#  Script to Grant/Revoke/Enumerate Log on as a service user right 
#
#  Author: Kevin Holman
#  Update: ATr ( + RemovePrivilege part, + Action Args ) 
#  v1.2
#=================================================================================

# Let parameters options simplest to be used in PowerShellWriteAction
param(
    [string]$UserAccount="",    
    
	[ValidateSet("Grant","Revoke","Enumerate")]
    [string]$Action = "Enumerate"

)


# Manual Testing section - put stuff here for manually testing script - typically parameters:
#=================================================================================
#=================================================================================


# Constants section - modify stuff here:
#=================================================================================
# Assign script name variable for use in event logging.  
# ScriptName should be the same as the ID of the module that the script is contained in
$ScriptName = "SCOM.Management.UserRights.LogonAsService.WA.ps1"
$EventID = "7003"
#=================================================================================


# Starting Script section - All scripts get this
#=================================================================================
# Gather the start time of the script
$StartTime = Get-Date
#Set variable to be used in logging events
$whoami = whoami
# Load MOMScript API
$momapi = New-Object -comObject MOM.ScriptAPI
#Log script event that we are starting task
$momapi.LogScriptEvent($ScriptName,$EventID,0,"`n Script is starting. `n Running as ($whoami).")
#=================================================================================

# Begin MAIN script section
#=================================================================================

#Log the params to the script:
$momapi.LogScriptEvent($ScriptName,$EventID,0,"`n Params passed to script: `n UserAccount: ($UserAccount) `n Action: ($Action)")

Set-StrictMode -Version 2.0
#$ErrorActionPreference = "Stop"

Function Main 
{
    Add-PS_LSA

    If($Action -eq "Enumerate")
    {
        Write-Host "$Action the Log on as a service privilege : `n"
		
        try{
            $output = EnumerateAccountsWithUserRight("SeServiceLogonRight")
            Write-Output $output
        }       
        Catch{

            $_Error = $_.Exception.Message
            $Result = "Error attempting to $Action the Log on as a service privilege. `n Error is ($_Error)."
            $momapi.LogScriptEvent($ScriptName,$EventID,1,"`n$Result")
    
            Throw $Result # Throw to fail the SCOM task

        }

        
    }
    Else 
    {
        
        if ( $UserAccount -eq "" )
        { 
            Throw "UserAccount cannot be an empty string." 
        }

    
        $Error.Clear()
        $lsa = New-Object PS_LSA.LsaWrapper
    
        try{

            If($Action -eq "Grant" ) 
            {
                $lsa.AddPrivilege($UserAccount,"SeServiceLogonRight")
            }
            ElseIf($Action -eq "Revoke")
            {
                $lsa.RemovePrivilege($UserAccount,"SeServiceLogonRight")
            }
            Else{}

            $Result = "$Action the Log on as a service privilege for User ($UserAccount) Succeeded."
            $momapi.LogScriptEvent($ScriptName,$EventID,0,"`n$Result")
    
            Write-Host $Result

            Write-Host "`n"

            $output = EnumerateAccountsWithUserRight("SeServiceLogonRight")
            Write-Output $output

        }
        Catch{

            $_Error = $_.Exception.Message
            $Result = "Error attempting to $Action the Log on as a service privilege to account: ($UserAccount). `n Error is ($_Error)."
            $momapi.LogScriptEvent($ScriptName,$EventID,1,"`n$Result")
    
            Throw $Result # Throw to fail the SCOM task

        }


    }    

}

Function Add-PS_LSA 
{
    
# The following section is adapted from https://gallery.technet.microsoft.com/scriptcenter/Grant-Revoke-Query-user-26e259b0

Add-Type -TypeDefinition @'
using System;
namespace PS_LSA
{
    using System.ComponentModel;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Security.Principal;
    using LSA_HANDLE = IntPtr;

    public enum Rights
    {
        SeServiceLogonRight,   // Log on as a service
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES
    {
        internal int Length;
        internal IntPtr RootDirectory;
        internal IntPtr ObjectName;
        internal int Attributes;
        internal IntPtr SecurityDescriptor;
        internal IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LSA_UNICODE_STRING
    {
        internal ushort Length;
        internal ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_ENUMERATION_INFORMATION
    {
        internal IntPtr PSid;
    }

    internal sealed class Win32Sec
    {
        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaOpenPolicy(
            LSA_UNICODE_STRING[] SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            int AccessMask,
            out IntPtr PolicyHandle
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaAddAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaRemoveAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            bool AllRights,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaEnumerateAccountsWithUserRight(
            LSA_HANDLE PolicyHandle,
            LSA_UNICODE_STRING[] UserRights,
            out IntPtr EnumerationBuffer,
            out ulong CountReturned
        );

        [DllImport("advapi32")]
        internal static extern int LsaNtStatusToWinError(int NTSTATUS);

        [DllImport("advapi32")]
        internal static extern int LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32")]
        internal static extern int LsaFreeMemory(IntPtr Buffer);
    }

    internal sealed class Sid : IDisposable
    {
        public IntPtr pSid = IntPtr.Zero;
        public SecurityIdentifier sid = null;

        public Sid(string account)
        {
            try { sid = new SecurityIdentifier(account); }
            catch { sid = (SecurityIdentifier)(new NTAccount(account)).Translate(typeof(SecurityIdentifier)); }
            Byte[] buffer = new Byte[sid.BinaryLength];
            sid.GetBinaryForm(buffer, 0);

            pSid = Marshal.AllocHGlobal(sid.BinaryLength);
            Marshal.Copy(buffer, 0, pSid, sid.BinaryLength);
        }

        public void Dispose()
        {
            if (pSid != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pSid);
                pSid = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~Sid() { Dispose(); }
    }

    public sealed class LsaWrapper : IDisposable
    {
        enum Access : int
        {
            POLICY_READ = 0x20006,
            POLICY_ALL_ACCESS = 0x00F0FFF,
            POLICY_EXECUTE = 0X20801,
            POLICY_WRITE = 0X207F8
        }
        const uint STATUS_ACCESS_DENIED = 0xc0000022;
        const uint STATUS_INSUFFICIENT_RESOURCES = 0xc000009a;
        const uint STATUS_NO_MEMORY = 0xc0000017;
        const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xc0000034;
        const uint STATUS_NO_MORE_ENTRIES = 0x8000001a;

        IntPtr lsaHandle;

        public LsaWrapper() : this(null) { } // local system if systemName is null
        public LsaWrapper(string systemName)
        {
            LSA_OBJECT_ATTRIBUTES lsaAttr;
            lsaAttr.RootDirectory = IntPtr.Zero;
            lsaAttr.ObjectName = IntPtr.Zero;
            lsaAttr.Attributes = 0;
            lsaAttr.SecurityDescriptor = IntPtr.Zero;
            lsaAttr.SecurityQualityOfService = IntPtr.Zero;
            lsaAttr.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            lsaHandle = IntPtr.Zero;
            LSA_UNICODE_STRING[] system = null;
            if (systemName != null)
            {
                system = new LSA_UNICODE_STRING[1];
                system[0] = InitLsaString(systemName);
            }

            uint ret = Win32Sec.LsaOpenPolicy(system, ref lsaAttr, (int)Access.POLICY_ALL_ACCESS, out lsaHandle);
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void AddPrivilege(string account, Rights privilege)
        {
            uint ret = 0;
            using (Sid sid = new Sid(account))
            {
                LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
                privileges[0] = InitLsaString(privilege.ToString());
                ret = Win32Sec.LsaAddAccountRights(lsaHandle, sid.pSid, privileges, 1);
            }
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }
		
		public void RemovePrivilege(string account, Rights privilege)
        {
            uint ret = 0;
            using (Sid sid = new Sid(account))
            {
                LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
                privileges[0] = InitLsaString(privilege.ToString());
                ret = Win32Sec.LsaRemoveAccountRights(lsaHandle, sid.pSid, false, privileges, 1);
            }
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }


        public string[] EnumerateAccountsWithUserRight(Rights privilege, bool resolveSid = true)
        {
            uint ret = 0;
            ulong count = 0;
            LSA_UNICODE_STRING[] rights = new LSA_UNICODE_STRING[1];
            rights[0] = InitLsaString(privilege.ToString());
            IntPtr buffer = IntPtr.Zero;
            string[] accounts = null;

            ret = Win32Sec.LsaEnumerateAccountsWithUserRight(lsaHandle, rights, out buffer, out count);
            if (ret == 0)
            {
                accounts = new string[count];
                for (int i = 0; i < (int)count; i++)
                {
                    LSA_ENUMERATION_INFORMATION LsaInfo = (LSA_ENUMERATION_INFORMATION)Marshal.PtrToStructure(
                        IntPtr.Add(buffer, i * Marshal.SizeOf(typeof(LSA_ENUMERATION_INFORMATION))),
                        typeof(LSA_ENUMERATION_INFORMATION));

                        if (resolveSid) {
                            try {
                                accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).Translate(typeof(NTAccount)).ToString();
                            } catch (System.Security.Principal.IdentityNotMappedException) {
                                accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).ToString();
                            }
                        } else { accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).ToString(); }
                }
                Win32Sec.LsaFreeMemory(buffer);
                return accounts;
            }
            if (ret == STATUS_NO_MORE_ENTRIES) return null;  // No accounts assigned
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void Dispose()
        {
            if (lsaHandle != IntPtr.Zero)
            {
                Win32Sec.LsaClose(lsaHandle);
                lsaHandle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~LsaWrapper() { Dispose(); }

        // helper functions:
        static LSA_UNICODE_STRING InitLsaString(string s)
        {
            // Unicode strings max. 32KB
            if (s.Length > 0x7ffe) throw new ArgumentException("String too long");
            LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
            lus.Buffer = s;
            lus.Length = (ushort)(s.Length * sizeof(char));
            lus.MaximumLength = (ushort)(lus.Length + sizeof(char));
            return lus;
        }
    }
}
'@ 
}

Function EnumerateAccountsWithUserRight( $SeService )
{
    $UserAccountList = @()
    $Error.Clear()
    $lsa = New-Object PS_LSA.LsaWrapper
    $sids = $lsa.EnumerateAccountsWithUserRight( $SeService, $false)
    IF ($Error)
    {
        $Result = "Error attempting to enumerate accounts. `n Error is ($Error)"
        Write-Error $Result
    }
    ELSE
    {
        FOREACH ($sid in $sids) 
        {
            [string]$SidText = $sid
            TRY
            {
                $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid) 
                $objUser = $objSID.Translate([System.Security.Principal.NTAccount]) 
                $UserAccountName = $objUser.Value
            }
            CATCH
            {
                $UserAccountName = "Unresolved"
            }
            $UserAccountList += New-Object -Typename PSObject -Prop @{ 'Account'= $UserAccountName ; 'SID'= $SidText }

        }
        $UserAccountList
    }
}


Main

# End of script section
#=================================================================================
#Log an event for script ending and total execution time.
$EndTime = Get-Date
$ScriptTime = ($EndTime - $StartTime).TotalSeconds
$momapi.LogScriptEvent($ScriptName,$EventID,0,"`n Script Completed. `n Script Runtime: ($ScriptTime) seconds.")
#=================================================================================
# End of script

