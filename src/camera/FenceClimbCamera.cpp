#include "FenceClimbCamera.h"
#include "Config.h"
#include <safetyhook.hpp>
#include <Hooking.Patterns.h>

namespace Camera {

	namespace CIntermezzoEventVaultWall
	{
	    SafetyHookInline shDetectTrigger = {};
	    bool __fastcall DetectTrigger(void* _this, void* edx)
	    {
	        static bool FenceCam = Config::cfg.fenceClimb;
	        if (!FenceCam)
	        {
	            return false;
	        }

	        return shDetectTrigger.unsafe_fastcall<bool>(_this, edx);
	    }
	}

	void InstallFenceClimb(){
		auto pattern = hook::pattern("55 8B EC 83 E4 ? 83 EC ? 56 57 8B F9 E8 ? ? ? ? 84 C0 0F 85 ? ? ? ? E8 ? ? ? ? 8B F0 85 F6 0F 84 ? ? ? ? F7 46");
    	CIntermezzoEventVaultWall::shDetectTrigger = safetyhook::create_inline(pattern.get_first(0), CIntermezzoEventVaultWall::DetectTrigger);
	}

}
