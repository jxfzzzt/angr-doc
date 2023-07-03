import angr

def main():
    proj = angr.Project('./src/step0.bin')

    addr_main = 0x4004a6
    first_jmp = 0x4004b9
    endpoint = 0x4004d6
    first_branch_left = 0x4004bb
    first_branch_right = 0x4004c2
    second_branch_left = 0x4004ca
    second_branch_right = 0x4004d1

    main_state = proj.factory.blank_state(addr=addr_main)
    sm = proj.factory.simulation_manager(main_state)
    assert sm.active[0].addr == addr_main

    sm.step(lambda pg: pg.active[0].addr >= first_jmp)
    print(sm)

    for i, s in enumerate(sm.active):
        

if __name__ == '__main__':
    main()