# dm_arbiter

it's just a datamodel, find it on https://offsets.imtheo.lol/offsets.hpp

# arbiter_to_dm 

string `FLog::LuaAppExperienceController] LuaAppExperienceController: EnableLuaAppScriptError`

<img width="970" height="266" alt="image" src="https://github.com/user-attachments/assets/990b63de-7e5b-403f-ae51-b4780f286384" />

that 0x1F0 (or wtv value it will be) is the arbiter

# facets and facets_end

string `GenericChallengeService`, first xref, decompile and go to xrefs of the function

<img width="892" height="629" alt="image" src="https://github.com/user-attachments/assets/24b681e0-760f-44ee-988b-ab41f0aed78a" />

choose the 2 ones on 21-22, well one just do 21, then at the very top you'll find this 

<img width="630" height="275" alt="image" src="https://github.com/user-attachments/assets/6baf453d-6f91-409b-a3e5-583dc8a884ca" />

double click the sub_28D3370 or wtv it'll be, in that function when you're in it press tab

<img width="889" height="350" alt="image" src="https://github.com/user-attachments/assets/9a94bef6-ad84-43e2-9d6b-e222446652ea" />

and there you have it, 0xA0 - facets_end 0x98 - facets.

# global_state, actor_state, l_global, registry_free

`FrameRateManager` last actual xref, not rdata, scroll to the bottom and look for `0.0000009536743f`

<img width="652" height="241" alt="image" src="https://github.com/user-attachments/assets/118e2258-9546-46d6-be2b-6d14a6cd4d01" />

double click that, press tab 

<img width="756" height="567" alt="image" src="https://github.com/user-attachments/assets/f85f215d-4011-4947-90a5-471036ae88fe" />

0x210 - global_state, 0x520 - actor_state, 0x50 - l_global, 0x640 - registry_free 
