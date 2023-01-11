#pragma once
#include "vmintrin.h"

#ifdef WINVM
#include "ShotHv/HvPch.h"
#else
#endif


BOOLEAN DbgInit();
BOOLEAN UnHookFuncs();