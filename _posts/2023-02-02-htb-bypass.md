---
layout: post
title: "Bypass (HTB rev)"
subtitle: "a Skater-obfuscated .NET crackme whose login can never pass, so I decrypted its string table and read the flag out"
date: 2023-02-02
tags: [htb, ctf, reversing, dotnet, crackme]
category: writeups
kind: challenge
os: Windows
tldr: "A .NET console crackme obfuscated with RustemSoft Skater. Its login always returns false, so the real key check is unreachable and the program loops on the prompt forever, but every string including the flag is AES-CBC decrypted at startup from an embedded resource whose 32-byte key and 16-byte IV sit in front of the ciphertext. I pulled the resource out of the PE, decrypted it, read the flag directly, then confirmed it by patching the login and entering the recovered key."
---

## the binary

I got a single file, `Bypass.exe`, and `file` gave away the runtime straight off:

```text
$ file Bypass.exe
Bypass.exe: PE32 executable for MS Windows 4.00 (console), Intel i386 Mono/.Net assembly, 3 sections
```

A managed .NET assembly, not a native binary, so there is no disassembly slog. It carries IL that reads back close to source. `strings` confirmed the stack and turned up the crypto it uses:

```text
$ strings -n6 Bypass.exe | grep -iE 'mscoree|_CorExeMain|mscorlib|Rijndael|v4\.0\.30319'
v4.0.30319
mscorlib
RijndaelManaged
_CorExeMain
mscoree.dll
```

`RijndaelManaged` in the import side told me the program does its own AES somewhere, which for a crackme usually means the interesting strings are encrypted and built at runtime.

## reading it back

No dnSpy on this box, so I dumped the IL with `monodis` (ships with mono):

```text
$ monodis Bypass.exe > bypass.il
```

The assembly has been run through the RustemSoft Skater .NET Obfuscator, demo edition. Its tell is twofold: every class and method is renamed to a bare number (`0`, `1`, `2`, `5`, `6`, `7`), and the string literals are gone from the IL entirely, replaced by loads from static fields that get populated at startup. I will refer to the classes by those numbers below, since that is how they read in the dump.

Class `0` holds the program logic. Its entry point is method `0::0`:

```text
IL_0001:  call      bool class 0::1()      // the login
IL_0006:  stloc.0
IL_000a:  brfalse.s IL_0016                // login failed -> fall through to the loop
IL_000d:  call      void class 0::2()      // login passed -> the real check
IL_0014:  br.s      IL_0029
IL_0017:  ldsfld    string 5::0            // "Wrong username and/or password"
IL_001c:  call      void Console::WriteLine(string)
IL_0022:  call      void class 0::0()      // recurse, i.e. prompt again
IL_0029:  ret
```

So `0::2`, the part that matters, only runs if `0::1` returns true. Everything hinges on that login.

## the login that never passes

Method `0::1` reads a username and a password, then returns a bool:

```text
IL_0001:  ldsfld  string 5::1             // "Enter a username: "
IL_0006:  call    void Console::Write(string)
IL_000c:  call    string Console::ReadLine()
IL_0011:  stloc.0                         // username
IL_0012:  ldsfld  string 5::2             // "Enter a password: "
IL_0017:  call    void Console::Write(string)
IL_001d:  call    string Console::ReadLine()
IL_0022:  stloc.1                         // password
IL_0023:  ldc.i4.0                        // push 0 (false)
IL_0024:  stloc.2
IL_0027:  ldloc.2
IL_0028:  ret                             // return false, unconditionally
```

It never compares the two inputs against anything. It pushes `0` and returns it. The username and password prompts are a stage set. No credential can make this return true, which means `0::2` is dead code from the prompt's point of view and the program loops on the login forever.

Running it under mono shows exactly that. Any input comes back rejected and the prompt repeats:

```text
$ printf 'admin\npassword\nfoo\nbar\n' | mono Bypass.exe
Enter a username: Enter a password: Wrong username and/or password
Enter a username: Enter a password: Wrong username and/or password
Enter a username: Enter a password: Wrong username and/or password
...
```

That is the negative control for the whole challenge. The login is not guessable because it is not a comparison. The name "Bypass" is the instruction: the check has to be gone around, not solved.

## the real check, and where the strings come from

Method `0::2` is the gate that prints the flag. It loads a secret into a local, prompts for input, and compares the two with `string::op_Equality`:

```text
IL_0001:  ldsfld  string 5::3             // the expected secret key
IL_0006:  stloc.0
IL_0007:  ldsfld  string 5::4             // "Please Enter the secret Key: "
IL_000c:  call    void Console::Write(string)
IL_0012:  call    string Console::ReadLine()
IL_0017:  stloc.1
IL_0018:  ldloc.0
IL_0019:  ldloc.1
IL_001a:  call    bool string::op_Equality(string, string)
IL_0021:  brfalse.s IL_0041
IL_0024:  ldsfld  string 5::5             // flag prefix
IL_0029:  ldsfld  string 0::2            // flag middle
IL_002e:  ldsfld  string 5::6             // flag suffix
IL_0033:  call    string string::Concat(string, string, string)
IL_0038:  call    void Console::Write(string)
```

Every `ldsfld string 5::N` is loading one of thirteen static fields on class `5`. Those fields start empty. They are filled by `5::0`, which runs once and builds the whole table:

```text
IL_0000:  call    Assembly::GetExecutingAssembly()
IL_0005:  ldstr   "0"
IL_000a:  callvirt Assembly::GetManifestResourceStream(string)   // embedded resource "0"
IL_000f:  call    uint8[] class 7::3(Stream)                      // read + decrypt
IL_0014:  newobj  class 6::.ctor(uint8[])                         // BinaryReader wrapper
// then 13x: call 6::6() (BinaryReader.ReadString) -> stsfld 5::N
```

So the string table is an embedded resource named `0`, decrypted, then read back as thirteen length-prefixed Unicode strings. The decryptor is class `7` method `2`, and it has one detail worth stopping on:

```text
IL_0000:  newobj   RijndaelManaged::.ctor()
IL_000c:  callvirt set_BlockSize(int32)            // 128
IL_0013:  callvirt set_Mode(CipherMode)            // 1 = CBC
IL_0019:  callvirt GenerateKey()                   // random key
IL_001f:  callvirt GenerateIV()                    // random IV
IL_0025:  newobj   MemoryStream(inputBytes)
...
IL_004d:  callvirt Stream::Read(key, 0, key.Length)   // overwrite key from the front of the stream
IL_0059:  callvirt Stream::Read(iv,  0, iv.Length)    // then the IV
IL_0062:  callvirt CreateDecryptor(key, iv)
// decrypt the remainder
```

`GenerateKey` and `GenerateIV` look like they randomize the cipher, but their only real job here is to allocate `key` and `iv` at the right lengths. The code immediately reads over both arrays from the start of the resource stream. A 256-bit Rijndael key is 32 bytes and a 128-bit block IV is 16 bytes, so the resource is laid out as:

```text
[ 32-byte AES key ][ 16-byte IV ][ AES-CBC ciphertext ]
```

The key travels with the ciphertext. I did not need to run the program to decrypt it.

## recovering the table offline

The resource is not in the Win32 `.rsrc` section. It lives in the CLR data the COM descriptor directory points at, so I parsed the Cor20 header with `pefile`, followed its Resources RVA, and took the 4-byte length prefix off the first entry:

```python
import pefile, struct
pe = pefile.PE("Bypass.exe")
com = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]          # COM descriptor
cor20 = pe.get_data(com.VirtualAddress, com.Size)
res_rva, res_size = struct.unpack_from("<II", cor20, 24)
res = pe.get_data(res_rva, res_size)
rlen = struct.unpack_from("<I", res, 0)[0]
data = res[4:4+rlen]                                  # 1616 bytes
```

Then split off the key and IV and run AES-CBC over the rest. A .NET `BinaryReader` over a Unicode stream reads each string as a 7-bit-encoded byte length followed by UTF-16LE, so I walked the plaintext the same way:

```python
from Crypto.Cipher import AES
key, iv, ct = data[:32], data[32:48], data[48:]
pt = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)        # strip PKCS7 trailer

def read7(b, o):
    r = s = 0
    while True:
        x = b[o]; o += 1
        r |= (x & 0x7f) << s
        if not x & 0x80: return r, o
        s += 7

o, strings = 0, []
while o < len(pt) and len(strings) < 13:
    n, o = read7(pt, o)
    strings.append(pt[o:o+n].decode("utf-16-le")); o += n
```

That gave all thirteen strings (`[10]` through `[12]` just repeat `[9]`):

```text
[0]  'Wrong username and/or password'
[1]  'Enter a username: '
[2]  'Enter a password: '
[3]  'ThisIsAReallyReallySecureKeyButYouCanReadItFromSourceSoItSucks'
[4]  'Please Enter the secret Key: '
[5]  'Nice here is the Flag:HTB{'
[6]  '}'
[7]  'Wrong Key'
[8]  'SuP3rC00lFL4g'
[9]  'This executable has been obfuscated by using RustemSoft Skater .NET Obfuscator Demo version. Please visit RustemSoft.com for more information.'
```

Field `5::3`, the secret the check wants, is the key `ThisIsAReallyReallySecureKeyButYouCanReadItFromSourceSoItSucks`, which names its own weakness. The flag was already in the table in three pieces: the congrats branch concatenates `5::5` + `0::2` + `5::6`, and `0::2` is just field `5::8` copied across in a static constructor. Joined, that is `Nice here is the Flag:HTB{` + `SuP3rC00lFL4g` + `}`.

## the bypass and the flag

Decrypting the table already hands over the flag, but the challenge is named for the login, so it is worth closing the loop. The login returns `false` from a single `ldc.i4.0` (opcode `0x16`) at IL offset `0x23`. Flipping that one byte to `ldc.i4.1` (`0x17`) makes it return true, and the entry point then falls into the real check:

```python
import pefile
pe = pefile.PE("Bypass.exe")
foff = pe.get_offset_from_rva(0x2090)      # method 0::1
b = bytearray(open("Bypass.exe","rb").read())
il = foff + 12                             # fat header (method has locals)
assert b[il+0x23] == 0x16                   # ldc.i4.0
b[il+0x23] = 0x17                           # ldc.i4.1
open("Bypass_patched.exe","wb").write(b)
```

Run the patched binary, let the login pass, and feed it the recovered key:

```text
$ printf 'u\np\nThisIsAReallyReallySecureKeyButYouCanReadItFromSourceSoItSucks\n' | mono Bypass_patched.exe
Enter a username: Enter a password: Please Enter the secret Key: Nice here is the Flag:HTB{SuP3rC00lFL4g}
```

The flag:

```text
HTB{SuP3rC00lFL4g}
```

The whole box is one idea dressed up twice. A login that cannot be passed because it is not a check, and a string table encrypted with a key stored right next to the ciphertext. Obfuscating the names and hiding the strings behind AES buys nothing once the key rides along in the same resource, which the author spelled out in the key itself.