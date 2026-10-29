# Verify this parses syntactically against dnfile 0.18.0 (no DLL needed to syntax-check)
import dnfile, sys

def find_psc(dll_path):
    pe = dnfile.dnPE(dll_path)
    pe.parse_data_directories()
    tdefs = pe.net.mdtables.TypeDef
    mdefs = pe.net.mdtables.MethodDef
    for ti, t in enumerate(tdefs.rows, start=1):
        if t.TypeName != "CompiledScriptBlockData":
            continue
        start = t.MethodList[0].row_index
        # next type's MethodList sets the exclusive upper bound; last type runs to end
        if ti < len(tdefs.rows):
            end = tdefs.rows[ti].MethodList[0].row_index
        else:
            end = len(mdefs.rows) + 1
        for mi in range(start, end):
            m = mdefs.rows[mi - 1]
            if m.Name == "PerformSecurityChecks":
                token = 0x06000000 | mi
                print(f"token=0x{token:08x}  rva=0x{m.Rva:x}  name={m.Name}")

if __name__ == "__main__":
    find_psc(sys.argv[1])
