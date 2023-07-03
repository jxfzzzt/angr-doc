import angr

def solve():
    find_addr = 0x08048533
    avoid_addr = 0x08048554
    proj = angr.Project('./crackme0x00a', load_options={'auto_load_libs': False})
    entry_state = proj.factory.entry_state()
    sm = proj.factory.simulation_manager(entry_state)
    sm.explore(find=find_addr, avoid=avoid_addr)

    if sm.found:
        found_state = sm.found[0]
        stdin = found_state.posix.dumps(0)
        answer = stdin[:stdin.find(b'\0')]
        print('answer: ', answer)

if __name__ == '__main__':
    solve()