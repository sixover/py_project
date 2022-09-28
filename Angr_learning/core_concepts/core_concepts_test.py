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

def states(proj:angr.Project):
    state = proj.factory.entry_state()
    logger.info(state)
    # logger.info(state.regs.init_state())
    # logger.info(state.regs.STRONGREF_STATE)
    logger.info(state.mem[proj.entry].int.resolved)

def bitvectors_transfer(proj:angr.Project):
    pass

path = "F:\\py_project\\Angr_learning\\bin\\busybox"
proj = ret_angr_project(path)
# basic_properities(proj)
# loader(proj)
# block(proj)
states(proj)