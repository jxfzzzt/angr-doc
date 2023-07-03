import angr

def solve():
    proj = angr.Project('./crackme0x03')
    entry_state = proj.factory.entry_state()
    sm = proj.factory.simulation_manager(entry_state)

    find_addr = 0x0804848A
    avoid_addr = 0x0804847C

    sm.explore(find=find_addr, avoid=avoid_addr)
    if sm.found:
        found_state = sm.found[0]
        answer = int(found_state.posix.dumps(0))
        print('answer: ', answer)

if __name__ == '__main__':
    solve()