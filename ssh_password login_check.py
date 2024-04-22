import pexpect

def load_ips(filename):
    """
    从指定的文件中读取IP地址。
    """
    with open(filename, 'r') as file:
        return [line.strip() for line in file if line.strip()]

def ssh_check_password_auth(ip, username='root'):
    """
    使用pexpect启动SSH进程，自动回答首次连接的确认问题，并分析输出以判断是否允许密码登录。
    """
    command = f"ssh {username}@{ip}"
    try:
        # 启动SSH命令
        child = pexpect.spawn(command, timeout=10)
        
        # 处理首次连接的主机密钥确认问题
        index = child.expect(['Are you sure you want to continue connecting (yes/no/[fingerprint])?', pexpect.EOF, pexpect.TIMEOUT])
        
        if index == 0:
            child.sendline('yes')  # 自动回答 'yes'
            # 继续等待下一步可能的输出
            child.expect([pexpect.EOF, pexpect.TIMEOUT, 'password:'])
            output = child.before.decode('utf-8')
        else:
            output = child.before.decode('utf-8')

        # 分析输出信息判断是否允许密码登录
        if ('Permission denied (publickey,gssapi-keyex,gssapi-with-mic)' in output or 
            'Permission denied (publickey)' in output or 
            'Permission denied (keyboard-interactive)' in output or 
            'No supported authentication methods available' in output):
            print(f"Password authentication NOT allowed for {ip}.")
        elif 'Permission denied, please try again.' in output:
            print(f"Multiple failed password attempts for {ip}. Check manually.")
        elif 'Connection closed by remote host' in output:
            print(f"Connection was closed by {ip}, possibly due to too many failed login attempts.")
        elif 'Permission denied (password)' in output:
            print(f"Password provided is incorrect for {ip}.")
        else:
            print(f"Password authentication may be allowed for {ip}, or check manually.")
    
    except Exception as e:
        print(f"An error occurred while connecting to {ip}: {str(e)}")

def main():
    ips_file = 'ips.txt'  # IP地址文件
    ips = load_ips(ips_file)  # 从文件加载IP地址列表
    for ip in ips:
        ssh_check_password_auth(ip)

if __name__ == '__main__':
    main()