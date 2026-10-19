$ErrorActionPreference = 'Stop'
try {
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class VpscWindowsFs {
 const uint READ=0x80000000, WRITE=0x40000000, ATTR=0x80, LIST=0x1, SHARE_READ=1;
 const uint OPEN_EXISTING=3, CREATE_NEW=1, OPEN_REPARSE=0x00200000, BACKUP=0x02000000;
 const uint MOVE_WRITE_THROUGH=0x8, REPARSE=0x400, DIRECTORY=0x10;
 [StructLayout(LayoutKind.Sequential)] struct TAG { public uint Attributes; public uint Value; }
 [StructLayout(LayoutKind.Sequential)] struct INFO {
  public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation;
  public System.Runtime.InteropServices.ComTypes.FILETIME Access;
  public System.Runtime.InteropServices.ComTypes.FILETIME Write;
  public uint Volume; public uint SizeHigh; public uint SizeLow; public uint Links;
  public uint IndexHigh; public uint IndexLow;
 }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
 static extern SafeFileHandle CreateFileW(string name,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandleEx(SafeFileHandle h,int kind,out TAG info,uint size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out INFO info);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle h,StringBuilder b,uint size,uint flags);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadFile(SafeFileHandle h,byte[] b,uint n,out uint read,IntPtr overlapped);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool WriteFile(SafeFileHandle h,byte[] b,uint n,out uint written,IntPtr overlapped);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool FlushFileBuffers(SafeFileHandle h);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool MoveFileExW(string a,string b,uint flags);
 static IOException Error(string code){return new IOException(code);}
 static string Final(SafeFileHandle h){var b=new StringBuilder(32768);uint n=GetFinalPathNameByHandleW(h,b,(uint)b.Capacity,0);if(n==0||n>=b.Capacity)throw Error("PATH");return b.ToString().TrimEnd('\\');}
 static SafeFileHandle Open(string p,uint access,bool isDir){
  var h=CreateFileW(p,access,SHARE_READ,IntPtr.Zero,OPEN_EXISTING,OPEN_REPARSE|BACKUP,IntPtr.Zero);
  if(h.IsInvalid)throw Error("PATH");TAG t;
  if(!GetFileInformationByHandleEx(h,9,out t,(uint)Marshal.SizeOf(typeof(TAG)))||(t.Attributes&REPARSE)!=0||((t.Attributes&DIRECTORY)!=0)!=isDir){h.Dispose();throw Error("REPARSE_OR_TYPE");}
  return h;
 }
 static bool Beneath(string root,string target){var prefix=root.EndsWith("\\",StringComparison.Ordinal)?root:root+"\\";return target.StartsWith(prefix,StringComparison.OrdinalIgnoreCase);}
 public static byte[] Read(string root,string target,int max){
  using(var r=Open(root,LIST|ATTR,true)) using(var f=Open(target,READ|ATTR,false)){
   string rf=Final(r),tf=Final(f);if(!Beneath(rf,tf))throw Error("OUTSIDE_ROOT");
   INFO before,after;if(!GetFileInformationByHandle(f,out before)||before.Links!=1)throw Error("FILE_INFO");
   long size=((long)before.SizeHigh<<32)|before.SizeLow;if(size<0||size>max)throw Error("FILE_LIMIT");
   using(var output=new MemoryStream((int)size)){
    var buffer=new byte[65536];uint n;
    while(ReadFile(f,buffer,(uint)buffer.Length,out n,IntPtr.Zero)&&n>0){if(output.Length+n>max)throw Error("FILE_LIMIT");output.Write(buffer,0,(int)n);}
    if(!GetFileInformationByHandle(f,out after)||before.Volume!=after.Volume||before.IndexHigh!=after.IndexHigh||before.IndexLow!=after.IndexLow||before.SizeHigh!=after.SizeHigh||before.SizeLow!=after.SizeLow||before.Write.dwHighDateTime!=after.Write.dwHighDateTime||before.Write.dwLowDateTime!=after.Write.dwLowDateTime||output.Length!=size)throw Error("FILE_CHANGED");
    return output.ToArray();
   }
  }
 }
 static SafeFileHandle OpenRoot(string p){return Open(p,LIST|ATTR,true);}
 static void AddEntries(string root,string target,string relative,int depth,int depthMax,int limit,List<Dictionary<string,string>> entries,ref bool truncated){
  using(var r=OpenRoot(root))using(var d=Open(target,LIST|ATTR,true)){
   string rf=Final(r),df=Final(d);if(!String.Equals(rf,df,StringComparison.OrdinalIgnoreCase)&&!Beneath(rf,df))throw Error("OUTSIDE_ROOT");
   foreach(var item in Directory.GetFileSystemEntries(df)){
    if(entries.Count>=limit){truncated=true;break;}string name=Path.GetFileName(item);string rel=relative.Length==0?name:Path.Combine(relative,name);uint attrs=0;try{attrs=(uint)File.GetAttributes(item);}catch{}
    string type=(attrs&REPARSE)!=0?"reparse":(attrs&DIRECTORY)!=0?"directory":"file";entries.Add(new Dictionary<string,string>{{"name",name},{"path",rel},{"type",type}});
    if(type=="directory"&&depth<depthMax&&!truncated)AddEntries(root,item,rel,depth+1,depthMax,limit,entries,ref truncated);
   }
  }
 }
 public static Dictionary<string,object> List(string root,string target,int depth,int limit){var entries=new List<Dictionary<string,string>>();bool truncated=false;AddEntries(root,target,"",0,depth,limit,entries,ref truncated);return new Dictionary<string,object>{{"entries",entries.ToArray()},{"truncated",truncated}};}
 public static int Create(string root,string target,string b64){
  string parent=Path.GetDirectoryName(target),name=Path.GetFileName(target);if(String.IsNullOrEmpty(name)||name=="."||name=="..")throw Error("INVALID_NAME");
  using(var r=Open(root,LIST|ATTR,true))using(var d=Open(parent,LIST|ATTR,true)){
   string rf=Final(r),pf=Final(d);if(!String.Equals(rf,pf,StringComparison.OrdinalIgnoreCase)&&!Beneath(rf,pf))throw Error("OUTSIDE_ROOT");
   string dest=Path.Combine(pf,name);using(var f=CreateFileW(dest,WRITE|ATTR,0,IntPtr.Zero,CREATE_NEW,OPEN_REPARSE,IntPtr.Zero)){
    if(f.IsInvalid){int e=Marshal.GetLastWin32Error();throw Error(e==80||e==183?"ALREADY_EXISTS":"WRITE_FAILED");}
    TAG t;if(!GetFileInformationByHandleEx(f,9,out t,(uint)Marshal.SizeOf(typeof(TAG)))||(t.Attributes&REPARSE)!=0||!Beneath(rf,Final(f)))throw Error("REPARSE_OR_TYPE");
    byte[] bytes=Convert.FromBase64String(b64);uint written;if(!WriteFile(f,bytes,(uint)bytes.Length,out written,IntPtr.Zero)||written!=(uint)bytes.Length||!FlushFileBuffers(f))throw Error("WRITE_FAILED");return bytes.Length;
   }
  }
 }
 public static void MoveWriteThrough(string src,string dest,bool replace){if(!MoveFileExW(src,dest,MOVE_WRITE_THROUGH|(replace?1u:0u)))throw Error("MOVE_FAILED");}
}
public static class VpscWindowsLock {
 const uint READ=0x80000000,WRITE=0x40000000,DELETE=0x00010000,SHARE_READ=1,OPEN_EXISTING=3,OPEN_ALWAYS=4,OPEN_REPARSE=0x00200000;
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFileW(string p,uint a,uint s,IntPtr sec,uint c,uint f,IntPtr t);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetFileInformationByHandleEx(SafeFileHandle h,int k,out TAG_INFO t,uint n);
 [StructLayout(LayoutKind.Sequential)]struct TAG_INFO{public uint Attributes;public uint Tag;}
 [DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetProcessTimes(IntPtr h,out long creation,out long exit,out long kernel,out long user);
 [DllImport("kernel32.dll",SetLastError=true)]static extern uint WaitForSingleObject(IntPtr h,uint ms);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetFileInformationByHandle(SafeFileHandle h,out FILE_INFO i);
 [StructLayout(LayoutKind.Sequential)]struct DISPOSITION_INFO{[MarshalAs(UnmanagedType.Bool)]public bool DeleteFile;}
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool SetFileInformationByHandle(SafeFileHandle h,int kind,ref DISPOSITION_INFO info,uint size);
 [StructLayout(LayoutKind.Sequential)]struct FILE_INFO{public uint Attributes;public long A;public long B;public long C;public uint Volume;public uint High;public uint Low;public uint Links;public uint IHigh;public uint ILow;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern uint GetFinalPathNameByHandleW(SafeFileHandle h,StringBuilder b,uint n,uint f);
 static string Final(SafeFileHandle h){var b=new StringBuilder(32768);uint n=GetFinalPathNameByHandleW(h,b,(uint)b.Capacity,0);if(n==0||n>=b.Capacity)throw new IOException("PATH");return b.ToString();}
 static void NoReparse(SafeFileHandle h){TAG_INFO t;if(!GetFileInformationByHandleEx(h,9,out t,8)||(t.Attributes&0x400)!=0||(t.Attributes&0x10)!=0)throw new IOException("REPARSE");}
 public static int Hold(string p,string ownerJson,int parentPid){
  using(var h=CreateFileW(p,READ|WRITE,0,IntPtr.Zero,OPEN_ALWAYS,OPEN_REPARSE,IntPtr.Zero)){
   if(h.IsInvalid){int e=Marshal.GetLastWin32Error();Console.WriteLine(e==32||e==33?"BUSY":"ERROR_OPEN:"+e.ToString());Console.Out.Flush();return 1;}NoReparse(h);
   using(var fs=new FileStream(h,FileAccess.ReadWrite,4096,false)){
    if(fs.Length>0){Console.WriteLine("STALE");Console.Out.Flush();return 2;}
    IntPtr parent=OpenProcess(0x00100000|0x1000,false,(uint)parentPid);if(parent==IntPtr.Zero){Console.WriteLine("ERROR_PARENT");Console.Out.Flush();return 1;}
    long c,e,k,u;if(!GetProcessTimes(parent,out c,out e,out k,out u)){CloseHandle(parent);Console.WriteLine("ERROR_PARENT");Console.Out.Flush();return 1;}
    string json=ownerJson.Replace("\"startTicks\":\"pending\"","\"startTicks\":\""+c.ToString()+"\"");byte[] bytes=Encoding.UTF8.GetBytes(json+"\n");fs.Write(bytes,0,bytes.Length);fs.Flush(true);
    Console.WriteLine("READY:"+c.ToString());Console.Out.Flush();WaitForSingleObject(parent,0xFFFFFFFF);CloseHandle(parent);return 0;
   }
  }
 }
 public static string Inspect(string p){
  using(var h=CreateFileW(p,READ,SHARE_READ,IntPtr.Zero,OPEN_EXISTING,OPEN_REPARSE,IntPtr.Zero)){
   if(h.IsInvalid){int e=Marshal.GetLastWin32Error();if(e==2||e==3)return "ABSENT";if(e==32||e==33)return "ACTIVE";return "UNKNOWN";}NoReparse(h);
   using(var fs=new FileStream(h,FileAccess.Read,1024,false)){if(fs.Length==0)return "ABSENT";if(fs.Length>4096)return "UNKNOWN";byte[] b=new byte[(int)fs.Length];int n=fs.Read(b,0,b.Length);if(n!=b.Length)return "UNKNOWN";return "DATA:"+Convert.ToBase64String(b);}
  }
 }
 public static string Status(int pid,string start){IntPtr h=OpenProcess(0x00100000|0x1000,false,(uint)pid);if(h==IntPtr.Zero){int e=Marshal.GetLastWin32Error();return e==87||e==1168?"dead":"unknown";}try{uint w=WaitForSingleObject(h,0);if(w==0)return "dead";long c,e,k,u;if(!GetProcessTimes(h,out c,out e,out k,out u))return "unknown";return c.ToString()==start?"active":"dead";}finally{CloseHandle(h);}}
 public static string StartTicks(int pid){IntPtr h=OpenProcess(0x00100000|0x1000,false,(uint)pid);if(h==IntPtr.Zero)throw new IOException("PROCESS");try{long c,e,k,u;if(!GetProcessTimes(h,out c,out e,out k,out u))throw new IOException("PROCESS");return c.ToString();}finally{CloseHandle(h);}}
 public static bool Clear(string p,string expectedB64,int pid,string start,bool allowActive){
  using(var h=CreateFileW(p,READ|WRITE|DELETE,0,IntPtr.Zero,OPEN_EXISTING,OPEN_REPARSE,IntPtr.Zero)){
   if(h.IsInvalid)return false;NoReparse(h);using(var fs=new FileStream(h,FileAccess.ReadWrite,1024,false)){
    if(fs.Length>4096)return false;byte[] current=new byte[(int)fs.Length];fs.Position=0;if(fs.Read(current,0,current.Length)!=current.Length)return false;
    byte[] expected=Convert.FromBase64String(expectedB64);if(current.Length!=expected.Length)return false;for(int i=0;i<current.Length;i++)if(current[i]!=expected[i])return false;
    string state=Status(pid,start);if(allowActive?state!="active":state!="dead")return false;
    fs.Flush(true);var disposition=new DISPOSITION_INFO{DeleteFile=true};return SetFileInformationByHandle(h,4,ref disposition,(uint)Marshal.SizeOf(typeof(DISPOSITION_INFO)));
   }
  }
 }
}
'@
$raw=[Console]::In.ReadToEnd()
$r=ConvertFrom-Json -InputObject $raw
function Full([string]$p){return [IO.Path]::GetFullPath($p)}
function NoReparse([string]$p){
 $full=Full $p;$root=[IO.Path]::GetPathRoot($full);$cursor=$root;$tail=$full.Substring($root.Length)
 foreach($part in $tail.Split([IO.Path]::DirectorySeparatorChar,[StringSplitOptions]::RemoveEmptyEntries)){$cursor=[IO.Path]::Combine($cursor,$part);if(Test-Path -LiteralPath $cursor){if(([IO.File]::GetAttributes($cursor)-band [IO.FileAttributes]::ReparsePoint)-ne 0){throw 'REPARSE'}}};return $full
}
function ApplyAcl([string]$p,[bool]$directory,[bool]$set){
 $full=NoReparse $p;if(!(Test-Path -LiteralPath $full)){throw 'MISSING'};$attrs=[IO.File]::GetAttributes($full)
 if($directory-ne(($attrs-band [IO.FileAttributes]::Directory)-ne 0)){throw 'TYPE'}
 $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User;$system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
 if($directory){$acl=[IO.Directory]::GetAccessControl($full)}else{$acl=[IO.File]::GetAccessControl($full)}
 if($set){$acl.SetAccessRuleProtection($true,$false);foreach($rule in @($acl.Access)){[void]$acl.RemoveAccessRuleSpecific($rule)};$inherit=[Security.AccessControl.InheritanceFlags]::None;if($directory){$inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit-bor [Security.AccessControl.InheritanceFlags]::ObjectInherit};$acl.SetOwner($sid);$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,[Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)));$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system,[Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)));if($directory){[IO.Directory]::SetAccessControl($full,$acl);$acl=[IO.Directory]::GetAccessControl($full)}else{[IO.File]::SetAccessControl($full,$acl);$acl=[IO.File]::GetAccessControl($full)}}
 if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value -or !$acl.AreAccessRulesProtected -or $acl.Access.Count -ne 2){throw 'ACL'};foreach($rule in $acl.Access){$ruleSid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value;if($rule.IsInherited -or $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or !($ruleSid -eq $sid.Value -or $ruleSid -eq $system.Value)){throw 'ACL'}};return $full
}
switch ($r.op) {
 'secure-directory' { $v=ApplyAcl $r.path $true $true; $o=@{ok=$true;path=$v} }
 'secure-file' { $v=ApplyAcl $r.path $false $true; $o=@{ok=$true;path=$v} }
 'verify-private-directory' { $v=ApplyAcl $r.path $true $false; $o=@{ok=$true;path=$v} }
 'verify-private-file' { $v=ApplyAcl $r.path $false $false; $o=@{ok=$true;path=$v} }
 'operation-root' {
   $v=NoReparse $r.path
   if (!(Test-Path -LiteralPath $v -PathType Container)) { throw 'TYPE' }
   $acl=[IO.Directory]::GetAccessControl($v); $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
   if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid) { throw 'OWNER' }
   $known=@($sid,'S-1-5-18','S-1-5-32-544')
   $mask=[int]([Security.AccessControl.FileSystemRights]::Write -bor
     [Security.AccessControl.FileSystemRights]::AppendData -bor
     [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
     [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
     [Security.AccessControl.FileSystemRights]::Delete -bor
     [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
     [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
     [Security.AccessControl.FileSystemRights]::TakeOwnership -bor
     [Security.AccessControl.FileSystemRights]::FullControl)
   foreach ($rule in $acl.Access) {
     $rs=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
     if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
         $rs -notin $known -and (([int]$rule.FileSystemRights -band $mask) -ne 0)) { throw 'ACL' }
   }
   $o=@{ok=$true;path=$v}
 }
 'elevated' { $p=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); $o=@{ok=$true;elevated=$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)} }
 'read' { $b=[VpscWindowsFs]::Read($r.root,$r.path,[int]$r.maxBytes); $o=@{ok=$true;bytes=[Convert]::ToBase64String($b)} }
 'list' { $v=[VpscWindowsFs]::List($r.root,$r.path,[int]$r.depth,[int]$r.limit); $o=@{ok=$true;value=$v} }
 'create' { $n=[VpscWindowsFs]::Create($r.root,$r.path,$r.bytes); $o=@{ok=$true;bytes=$n} }
 'move-write-through' { [VpscWindowsFs]::MoveWriteThrough((NoReparse $r.source),(NoReparse $r.destination),[bool]$r.replace); $o=@{ok=$true} }
 'lock-inspect' {
   $s=[VpscWindowsLock]::Inspect($r.path)
   if ($s.StartsWith('DATA:')) {
     $b=[Convert]::FromBase64String($s.Substring(5)); $v=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString($b))
     $status=[VpscWindowsLock]::Status([int]$v.pid,[string]$v.startTicks)
     $o=@{ok=$true;status=$status;bytes=$s.Substring(5)}
   } else { $o=@{ok=$true;status=$s.ToLowerInvariant()} }
 }
 'process-start' { $o=@{ok=$true;startTicks=[VpscWindowsLock]::StartTicks([int]$r.pid)} }
 'lock-clear' { $ok=[VpscWindowsLock]::Clear($r.path,$r.expectedBytes,[int]$r.pid,[string]$r.startTicks,[bool]$r.allowActive); $o=@{ok=$ok;cleared=$ok} }
 'lock-hold' { $v=ConvertFrom-Json $r.ownerJson; [VpscWindowsLock]::Hold($r.path,$r.ownerJson,[int]$v.pid)|Out-Null; exit 0 }
 default { throw 'OP' }
}
[Console]::Out.Write((ConvertTo-Json -InputObject $o -Compress -Depth 8))
} catch {
 $e=$_.Exception; while($e.InnerException){$e=$e.InnerException}
 $code=[string]$e.Message
 if($code -notmatch '^(ALREADY_EXISTS|OUTSIDE_ROOT|REPARSE_OR_TYPE|INVALID_NAME|WRITE_FAILED|PATH|FILE_INFO|FILE_LIMIT|FILE_CHANGED|LOCK_UNAVAILABLE|LOCK_OWNER_UNVERIFIED|LOCK_PARENT_UNVERIFIED|LOCK_BUSY|LOCK_STALE)$'){$code='WINDOWS_SECURITY'}
 [Console]::Out.Write((ConvertTo-Json -InputObject @{ok=$false;error=$code} -Compress)); exit 1
}
