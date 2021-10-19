from binaryninja import Architecture, Platform

from .deus_arch import DeusArchitecture
from .deus_view import DeusView
from .deus_call import DeusCallingConvention

DeusArchitecture.register()

deus_arch = Architecture["deus"]
standalone = deus_arch.standalone_platform

class DeusPlatform(Platform):
    name = "deus"

deus_platform = DeusPlatform(deus_arch)
deus_platform.register("deus")


DeusView.register()
Architecture['deus'].register_calling_convention(DeusCallingConvention(Architecture['deus'], 'deus-abi'))
