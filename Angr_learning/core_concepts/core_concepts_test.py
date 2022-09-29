import angr
import monkeyhex
from loguru import logger


def ret_angr_project(path):
    return angr.Project(path)


def basic_properities(proj: angr.Project):
    logger.info("this is the basic properities print!")
    logger.info(proj.arch)
    logger.info(proj.entry)
    logger.info(proj.filename)

def loader(proj:angr.Project):
    logger.info("\n")
    logger.info("this is the loader print!")
    logger.info(proj.loader)
    logger.info(proj.loader.shared_objects)
    logger.info(proj.loader.min_addr)
    logger.info(proj.loader.max_addr)
    logger.info(proj.loader.main_object)
    logger.info(proj.loader.main_object.execstack)
    logger.info(proj.loader.main_object.pic)

def block(proj:angr.Project):
    logger.info("\n")
    logger.info("this is the block print!")
    block = proj.factory.block(proj.entry)
    logger.info(block)
    logger.info(block.pp())
    logger.info(block.instructions)
    logger.info(block.instruction_addrs)
    logger.info(block.serialize())
    logger.info(block.vex)
    logger.info(block.capstone)

# states中访问寄存器官方文档中有些问题，可能需要去看看angr_ctf_master
def states(proj:angr.Project):
    state = proj.factory.entry_state()
    logger.info(state)
    logger.info(state.mem[proj.entry].int.resolved)
    '''
        上面这种做法，可以在state.mem[addr]访问一个内存地址
        然后将其解析为指定类型，上方的语句是解析成int
        然后有三种操作方法：
        1.向其中store一个bitvector或者python相对应的类型
        2.使用resolved获取一个值，类型为bitvector
        3.使用concrete获取一个值，类型为python int
    '''
    return state

def bitvectors_transfer(proj:angr.Project):
    state = proj.factory.entry_state()
    bv = state.solver.BVV(0x1234,32)
    logger.info(bv)
    logger.info(state.solver.eval(bv))
    state.mem[0x1000].long = 4
    logger.info(state.mem[0x1000].long.resolved)
    # state.regs.eax = state.solver.BVV(3,32)
    # logger.info(state.regs.eax)

def simulation(proj:angr.Project):
    simgr = proj.factory.simulation_manager(proj.factory.entry_state())
    logger.info(simgr)
    logger.info(simgr.active)
    simgr.step()
    logger.info(simgr.active)


path = "F:\\binary\\bin\\busybox"
proj = ret_angr_project(path)
basic_properities(proj)
# loader(proj)
# block(proj)
# states(proj)
# bitvectors_transfer(proj)
# logger.info(type(proj.arch))
# logger.info(proj.arch.register_list)
simulation(proj)