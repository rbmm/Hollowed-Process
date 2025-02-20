.686

.model flat

public _codesec_exe_begin, _codesec_exe_end

.const

_codesec_exe_begin LABEL BYTE
INCLUDE <exe.x86.asm>
_codesec_exe_end LABEL BYTE

end