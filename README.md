# Dota2Dumper

Dumps Dota's netvars, interfaces, gamesystems and classes. Inject via LoadLibrary.

Generates a PudgeDumper folder in your Documents folder with the following info:

- Interfaces.txt
- GameSystems.txt
- Netvars.h for Dota2Cheat
- Folders with every class of every Schema scope

Happy updating!

# D2SigVerifier

A tool that verifies signatures and VMT indices provided via JSON.

## Running

Build, place the JSON files beside the .exe then run via console, providing the path to `steamapps/common/dota 2 beta`

Example:

```
D2SigVerifier.exe "H:\SteamLibrary\steamapps\common\dota 2 beta"
```

## Where to get data

`vmt_signatures.json` and `signatures.json` files can be found in [`Dota2Cheat/Data`](https://github.com/ExistedGit/Dota2Cheat/blob/main/Dota2Cheat/Data).

The resulting `vmt.json` is also supposed to go into Data.

## VMT indices

Signatures for virtual methods are provided via `vmt_signatures.json` in the same folder

Structured like this:

```
  "\\game\\bin\\win64\\": {     // subfolder of steamapps\common\dota 2 beta
    "particles.dll": {          // dll name
      "CParticleCollection": {  // class name
        "methods": {            // key = func name, value = pattern
          "SetRenderingEnabled": "4C 8B DC 55 56 41 54",
          "SetControlPoint": "4D 8B C8 44 8B C2 48 C7 C2"
        }
      }
    },
  }
```

Class entries may have an optional `mappedName` attribute, which is needed when the names in code and in DLL are different. For example,
since `C_BaseEntity` is written as `CBaseEntity` in code, it will have `"mappedName": "CBaseEntity"`. Refer to [Dota2Cheat](https://github.com/ExistedGit/Dota2Cheat/blob/main/Dota2Cheat/SDK/VMI.h) for in-code names.

## Signatures

Provided via `signatures.json` in the same folder. For structure refer to [Dota2Cheat](https://github.com/ExistedGit/Dota2Cheat/wiki/Interacting-with-Dota2Cheat#signatures--vtable-indices).

The program will check if the signatures are intact.
