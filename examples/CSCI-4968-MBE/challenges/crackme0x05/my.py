import angr

def solve():
    proj = angr.Project('./crackme0x05', load_options={'auto_load_libs': False})
    entry_state = proj.factory.entry_state()
    sm = proj.factory.simulation_manager(entry_state)

    def find_func(state):
        return b'Password OK!' in state.posix.dumps(1)

    def avoid_func(state):
        return b'Password Incorrect!' in state.posix.dumps(1)

    sm.explore(find=find_func, avoid=avoid_func)

    if sm.found:
        found_state = sm.found[0]
        answer = found_state.posix.dumps(0)
        print('answer: ', answer)
        with open('input', 'wb') as fp:
            fp.write(answer)

if __name__ == '__main__':
    solve()