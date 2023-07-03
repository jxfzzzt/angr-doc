import angr
import claripy

def getFuncAddr(cfg, func_name, plt=None):
    found = [addr for addr, func in cfg.kb.functions.items()
             if func.name == func_name and (plt is None or plt == func.is_plt)]

    if len(found) > 0:
        print("Found " + func_name + "'s address at " + str([hex(i) for i in found]) + "!")
        return found[0]
    else:
        raise Exception('Func Address not Found!')


def solve():
    proj = angr.Project('./strcpy_test', load_options={'auto_load_libs': False})
    cfg = proj.analyses.CFG(fail_fast=True)

    strcpy_addr = getFuncAddr(cfg, 'strcpy', True)
    avoid_addr = getFuncAddr(cfg, 'func3')
    print('strcpy_addr: ', hex(strcpy_addr))
    print('func3_addr: ', hex(avoid_addr))

    c = cfg.kb.functions.function(name='func3')
    assert strcpy_addr == cfg.kb.functions.function(name='strcpy').addr
    assert avoid_addr == cfg.kb.functions.function(name='func3').addr

    argv = [proj.filename]

    arg_size = 40
    passwd = claripy.BVS('passwd', arg_size * 8)
    argv.append(passwd)
    argv.append('HAHAHAHA')

    entry_state = proj.factory.entry_state(args=argv)

    sm = proj.factory.simulation_manager(entry_state)

    def checkStrcpy(state):
        if (state.ip.args[0] == strcpy_addr):
            BV_strcpy_content = state.memory.load(state.regs.rsi, len(argv[2]))
            strcpy_content = state.solver.eval(BV_strcpy_content, cast_to=bytes)
            return True if argv[2].encode() in strcpy_content else False

        else:
            return False

    sm.explore(find=checkStrcpy, avoid=(avoid_addr, ))

    if sm.found:
        found_state = sm.found[0]
        result = found_state.solver.eval(argv[1], cast_to=bytes)
        answer = result[:result.find(b'\0')]
        print('answer: ', answer)
        with open('input', 'wb') as f:
            f.write(answer + b" " + b"HAHAHAHA")


if __name__ == '__main__':
    solve()