import angr

def solve():
    proj = angr.Project('./crackme0x04', load_options={'auto_load_libs': False})
    entry_state = proj.factory.entry_state()
    sm = proj.factory.simulation_manager(entry_state)

    find_addr = 0x080484DC
    avoid_addr = 0x080484FB
    sm.explore(find=find_addr, avoid=avoid_addr)
    if sm.found:
        found_state = sm.found[0]
        answer = found_state.posix.dumps(0)
        print('answer: ', answer)
        with open('input', 'wb') as f:
            f.write(answer)

if __name__ == '__main__':
    solve()