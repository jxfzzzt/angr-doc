import angr

def main():
    proj = angr.Project('fauxware')
    init_state = proj.factory.entry_state(stdin=angr.SimFile)

    while True:
        succ = init_state.step()
        if len(succ.successors) == 2:
            break
        init_state = succ.successors[0]

    state1, state2 = succ.successors
    print('state1 = ', state1)
    print('state2 = ', state2)

def test():
    proj = angr.Project('fauxware')
    state = proj.factory.entry_state()

    while True:
        print(state)
        succ = state.step()
        if len(succ.successors) == 2:
            break
        state = succ.successors[0]


if __name__ == '__main__':
    test()

