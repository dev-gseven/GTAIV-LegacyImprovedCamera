#include "VehicleTurnSpeed.h"
#include "Config.h"
#include <Windows.h>
#include <cstring>
#include <safetyhook.hpp>
#include <Hooking.Patterns.h>

namespace Camera
{
    namespace
    {
        safetyhook::MidHook vehicleXHook;
        safetyhook::MidHook vehicleYHook;
    }

    void InstallVehicleTurnSpeed()
    {
        DWORD oldProtect = 0;

        // Axis X // 1.0.4.0
        auto axisXPattern = hook::pattern("F3 0F 5E C1 F3 0F 11 44 24 60 0F 84");
        if(!axisXPattern.empty()){
            auto axisXAddress = axisXPattern.get_first();
            VirtualProtect(axisXAddress, 10, PAGE_EXECUTE_READWRITE, &oldProtect);
            memset(axisXAddress, 0x90, 10);
            VirtualProtect(axisXAddress, 10, oldProtect, &oldProtect);
            vehicleXHook = safetyhook::create_mid(axisXAddress, [](SafetyHookContext &reg)
            {
                const int8_t turn = Config::cfg.vehKbXTurn;
                const float adjustedTurnSpeed = reg.xmm0.f32[0] / (reg.xmm1.f32[0] * (1.0f - turn * 0.1f));
                float &turnSpeed = *(float*)(reg.esp + 0x60);
                turnSpeed = adjustedTurnSpeed;
            });
        }
        // Axis X // 1.0.7.0, 1.0.8.0
        else {
            auto axisXPattern = hook::pattern("F3 0F 5E C1 F3 0F 11 44 24 ? 0F 84");
            auto axisXAddress = axisXPattern.get_first();
            static uint8_t axisXStackOffset = *axisXPattern.get_first<uint8_t>(9);
            VirtualProtect(axisXAddress, 10, PAGE_EXECUTE_READWRITE, &oldProtect);
            memset(axisXAddress, 0x90, 10);
            VirtualProtect(axisXAddress, 10, oldProtect, &oldProtect);

            vehicleXHook = safetyhook::create_mid(axisXAddress,[](SafetyHookContext& regs)
                {
                    const int8_t turn = Config::cfg.vehKbXTurn;
                    const float adjustedTurnSpeed = regs.xmm0.f32[0] / (regs.xmm1.f32[0] * (1.0f - turn * 0.1f));
                    float& turnSpeed = *reinterpret_cast<float*>(regs.esp + axisXStackOffset);
                    turnSpeed = adjustedTurnSpeed;
                }
            );
        }

        // Axis Y // 1.0.4.0
        auto axisYPattern = hook::pattern("F3 0F 5E C2 F3 0F 11 44 24 70 F3 0F");
        if (!axisYPattern.empty()){
            auto axisYAddress = axisYPattern.get_first();
            VirtualProtect(axisYAddress, 10, PAGE_EXECUTE_READWRITE, &oldProtect);
            memset(axisYAddress, 0x90, 10);
            VirtualProtect(axisYAddress, 10, oldProtect, &oldProtect);
            vehicleYHook = safetyhook::create_mid(axisYAddress, [](SafetyHookContext &reg)
            {
                const int8_t turn = Config::cfg.vehKbYTurn;
                const float adjustedTurnSpeed = reg.xmm0.f32[0] / (reg.xmm2.f32[0] * (1.0f - turn * 0.1f));
                float &turnSpeed = *(float*)(reg.esp + 0x70);
                turnSpeed = adjustedTurnSpeed;
            });
        }
        // Axis Y // 1.0.7.0, 1.0.8.0
        else {
            axisYPattern = hook::pattern("F3 0F 5E C2 F3 0F 11 84 24 ? ? ? ? F3 0F 10 43");
            auto axisYAddress = axisYPattern.get_first();
            VirtualProtect(axisYAddress, 13, PAGE_EXECUTE_READWRITE, &oldProtect);
            memset(axisYAddress, 0x90, 13);
            VirtualProtect(axisYAddress, 13, oldProtect, &oldProtect);
            vehicleYHook = safetyhook::create_mid(axisYAddress, [](SafetyHookContext& regs)
            {
                const int8_t turn = Config::cfg.vehKbYTurn;
                const float adjustedTurnSpeed = regs.xmm0.f32[0] / (regs.xmm2.f32[0] * (1.0f - turn * 0.1f));
                float &turnSpeed = *(float*)(regs.esp + 0x100 - 0x44);
                turnSpeed = adjustedTurnSpeed;
            });
        }
    }
}