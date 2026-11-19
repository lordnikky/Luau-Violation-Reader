# dm_arbiter

it's just a datamodel, find it on https://offsets.imtheo.lol/offsets.hpp

# arbiter_to_dm 

string `FLog::LuaAppExperienceController] LuaAppExperienceController: EnableLuaAppScriptError`

<img width="970" height="266" alt="image" src="https://github.com/user-attachments/assets/990b63de-7e5b-403f-ae51-b4780f286384" />

that 0x1F0 (or wtv value it will be) is the arbiter

# global_state, actor_state, l_global, registry_free

`FrameRateManager` last actual xref, not rdata, scroll to the bottom and look for `0.0000009536743f`

<img width="652" height="241" alt="image" src="https://github.com/user-attachments/assets/118e2258-9546-46d6-be2b-6d14a6cd4d01" />

double click that, press tab 

<img width="756" height="567" alt="image" src="https://github.com/user-attachments/assets/f85f215d-4011-4947-90a5-471036ae88fe" />

0x210 - global_state, 0x520 - actor_state, 0x50 - l_global, 0x640 - registry_free 

All of these can be found in Thorium's dumps, their names are

global_State* global - l_global

SC2LS - global_state

SC2LSA - actor_state

registryfree - registry_free

# script_context_vtable

press g and search for RBX::ScriptContext::`vftable', second one will be it 

<img width="815" height="116" alt="image" src="https://github.com/user-attachments/assets/b38383a4-3c5b-4589-80bd-6e71ea6ea9a1" />
