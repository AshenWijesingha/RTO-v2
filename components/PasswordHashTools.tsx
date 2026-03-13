'use client'

import React, { useState } from 'react'
import { copyToClipboard } from '@/lib/utils'

// ── MD5 Implementation ────────────────────────────────────────────────
function md5(input: string): string {
  function safeAdd(x: number, y: number) {
    const lsw = (x & 0xffff) + (y & 0xffff)
    return (((x >> 16) + (y >> 16) + (lsw >> 16)) << 16) | (lsw & 0xffff)
  }
  function bitRotateLeft(num: number, cnt: number) {
    return (num << cnt) | (num >>> (32 - cnt))
  }
  function md5cmn(q: number, a: number, b: number, x: number, s: number, t: number) {
    return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b)
  }
  function md5ff(a: number, b: number, c: number, d: number, x: number, s: number, t: number) {
    return md5cmn((b & c) | (~b & d), a, b, x, s, t)
  }
  function md5gg(a: number, b: number, c: number, d: number, x: number, s: number, t: number) {
    return md5cmn((b & d) | (c & ~d), a, b, x, s, t)
  }
  function md5hh(a: number, b: number, c: number, d: number, x: number, s: number, t: number) {
    return md5cmn(b ^ c ^ d, a, b, x, s, t)
  }
  function md5ii(a: number, b: number, c: number, d: number, x: number, s: number, t: number) {
    return md5cmn(c ^ (b | ~d), a, b, x, s, t)
  }

  function binlMD5(x: number[], len: number): number[] {
    x[len >> 5] |= 0x80 << (len % 32)
    x[(((len + 64) >>> 9) << 4) + 14] = len
    let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878
    for (let i = 0; i < x.length; i += 16) {
      const oa = a, ob = b, oc = c, od = d
      a = md5ff(a, b, c, d, x[i] || 0, 7, -680876936)
      d = md5ff(d, a, b, c, x[i + 1] || 0, 12, -389564586)
      c = md5ff(c, d, a, b, x[i + 2] || 0, 17, 606105819)
      b = md5ff(b, c, d, a, x[i + 3] || 0, 22, -1044525330)
      a = md5ff(a, b, c, d, x[i + 4] || 0, 7, -176418897)
      d = md5ff(d, a, b, c, x[i + 5] || 0, 12, 1200080426)
      c = md5ff(c, d, a, b, x[i + 6] || 0, 17, -1473231341)
      b = md5ff(b, c, d, a, x[i + 7] || 0, 22, -45705983)
      a = md5ff(a, b, c, d, x[i + 8] || 0, 7, 1770035416)
      d = md5ff(d, a, b, c, x[i + 9] || 0, 12, -1958414417)
      c = md5ff(c, d, a, b, x[i + 10] || 0, 17, -42063)
      b = md5ff(b, c, d, a, x[i + 11] || 0, 22, -1990404162)
      a = md5ff(a, b, c, d, x[i + 12] || 0, 7, 1804603682)
      d = md5ff(d, a, b, c, x[i + 13] || 0, 12, -40341101)
      c = md5ff(c, d, a, b, x[i + 14] || 0, 17, -1502002290)
      b = md5ff(b, c, d, a, x[i + 15] || 0, 22, 1236535329)

      a = md5gg(a, b, c, d, x[i + 1] || 0, 5, -165796510)
      d = md5gg(d, a, b, c, x[i + 6] || 0, 9, -1069501632)
      c = md5gg(c, d, a, b, x[i + 11] || 0, 14, 643717713)
      b = md5gg(b, c, d, a, x[i] || 0, 20, -373897302)
      a = md5gg(a, b, c, d, x[i + 5] || 0, 5, -701558691)
      d = md5gg(d, a, b, c, x[i + 10] || 0, 9, 38016083)
      c = md5gg(c, d, a, b, x[i + 15] || 0, 14, -660478335)
      b = md5gg(b, c, d, a, x[i + 4] || 0, 20, -405537848)
      a = md5gg(a, b, c, d, x[i + 9] || 0, 5, 568446438)
      d = md5gg(d, a, b, c, x[i + 14] || 0, 9, -1019803690)
      c = md5gg(c, d, a, b, x[i + 3] || 0, 14, -187363961)
      b = md5gg(b, c, d, a, x[i + 8] || 0, 20, 1163531501)
      a = md5gg(a, b, c, d, x[i + 13] || 0, 5, -1444681467)
      d = md5gg(d, a, b, c, x[i + 2] || 0, 9, -51403784)
      c = md5gg(c, d, a, b, x[i + 7] || 0, 14, 1735328473)
      b = md5gg(b, c, d, a, x[i + 12] || 0, 20, -1926607734)

      a = md5hh(a, b, c, d, x[i + 5] || 0, 4, -378558)
      d = md5hh(d, a, b, c, x[i + 8] || 0, 11, -2022574463)
      c = md5hh(c, d, a, b, x[i + 11] || 0, 16, 1839030562)
      b = md5hh(b, c, d, a, x[i + 14] || 0, 23, -35309556)
      a = md5hh(a, b, c, d, x[i + 1] || 0, 4, -1530992060)
      d = md5hh(d, a, b, c, x[i + 4] || 0, 11, 1272893353)
      c = md5hh(c, d, a, b, x[i + 7] || 0, 16, -155497632)
      b = md5hh(b, c, d, a, x[i + 10] || 0, 23, -1094730640)
      a = md5hh(a, b, c, d, x[i + 13] || 0, 4, 681279174)
      d = md5hh(d, a, b, c, x[i] || 0, 11, -358537222)
      c = md5hh(c, d, a, b, x[i + 3] || 0, 16, -722521979)
      b = md5hh(b, c, d, a, x[i + 6] || 0, 23, 76029189)
      a = md5hh(a, b, c, d, x[i + 9] || 0, 4, -640364487)
      d = md5hh(d, a, b, c, x[i + 12] || 0, 11, -421815835)
      c = md5hh(c, d, a, b, x[i + 15] || 0, 16, 530742520)
      b = md5hh(b, c, d, a, x[i + 2] || 0, 23, -995338651)

      a = md5ii(a, b, c, d, x[i] || 0, 6, -198630844)
      d = md5ii(d, a, b, c, x[i + 7] || 0, 10, 1126891415)
      c = md5ii(c, d, a, b, x[i + 14] || 0, 15, -1416354905)
      b = md5ii(b, c, d, a, x[i + 5] || 0, 21, -57434055)
      a = md5ii(a, b, c, d, x[i + 12] || 0, 6, 1700485571)
      d = md5ii(d, a, b, c, x[i + 3] || 0, 10, -1894986606)
      c = md5ii(c, d, a, b, x[i + 10] || 0, 15, -1051523)
      b = md5ii(b, c, d, a, x[i + 1] || 0, 21, -2054922799)
      a = md5ii(a, b, c, d, x[i + 8] || 0, 6, 1873313359)
      d = md5ii(d, a, b, c, x[i + 15] || 0, 10, -30611744)
      c = md5ii(c, d, a, b, x[i + 6] || 0, 15, -1560198380)
      b = md5ii(b, c, d, a, x[i + 13] || 0, 21, 1309151649)
      a = md5ii(a, b, c, d, x[i + 4] || 0, 6, -145523070)
      d = md5ii(d, a, b, c, x[i + 11] || 0, 10, -1120210379)
      c = md5ii(c, d, a, b, x[i + 2] || 0, 15, 718787259)
      b = md5ii(b, c, d, a, x[i + 9] || 0, 21, -343485551)

      a = safeAdd(a, oa); b = safeAdd(b, ob); c = safeAdd(c, oc); d = safeAdd(d, od)
    }
    return [a, b, c, d]
  }

  function str2binl(str: string): number[] {
    const bin: number[] = []
    const mask = (1 << 8) - 1
    for (let i = 0; i < str.length * 8; i += 8) {
      bin[i >> 5] |= (str.charCodeAt(i / 8) & mask) << (i % 32)
    }
    return bin
  }

  function binl2hex(binarray: number[]): string {
    const hexTab = '0123456789abcdef'
    let str = ''
    for (let i = 0; i < binarray.length * 4; i++) {
      str += hexTab.charAt((binarray[i >> 2] >> ((i % 4) * 8 + 4)) & 0xf) +
             hexTab.charAt((binarray[i >> 2] >> ((i % 4) * 8)) & 0xf)
    }
    return str
  }

  // Convert UTF-8 string to byte string
  const utf8Bytes = new TextEncoder().encode(input)
  const utf8Str = Array.from(utf8Bytes).map(b => String.fromCharCode(b)).join('')
  return binl2hex(binlMD5(str2binl(utf8Str), utf8Str.length * 8))
}

// ── Web Crypto Hash ───────────────────────────────────────────────────
async function hashWithCrypto(algo: string, text: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(text)
  const hashBuffer = await crypto.subtle.digest(algo, data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}

async function hashHexWithCrypto(algo: string, hex: string): Promise<string> {
  const bytes = new Uint8Array(hex.match(/.{1,2}/g)?.map(b => parseInt(b, 16)) || [])
  const hashBuffer = await crypto.subtle.digest(algo, bytes)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}

function md5Hex(hex: string): string {
  const bytes = hex.match(/.{1,2}/g)?.map(b => parseInt(b, 16)) || []
  const str = bytes.map(b => String.fromCharCode(b)).join('')
  return md5(str)
}

// ── Static Data ───────────────────────────────────────────────────────
const HASHCAT_MODES = [
  { type: 'MD5', mode: '0', example: '8743b52063cd84097a65d1633f5c74f5', john: 'Raw-MD5' },
  { type: 'SHA-1', mode: '100', example: 'b89eaac7e61417341b710b727768294d0e6a277b', john: 'Raw-SHA1' },
  { type: 'SHA-256', mode: '1400', example: '127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935', john: 'Raw-SHA256' },
  { type: 'SHA-512', mode: '1700', example: '82a9dda829eb7f8ffe9fbe49e45d47d2...', john: 'Raw-SHA512' },
  { type: 'NTLM', mode: '1000', example: 'b4b9b02e6f09a9bd760f388b67351e2b', john: 'NT' },
  { type: 'NTLMv2', mode: '5600', example: 'admin::N46iSNekpT:08ca45b7d7ea58ee...', john: 'netntlmv2' },
  { type: 'Net-NTLMv1', mode: '5500', example: 'u4-netntlm::kNS:338d08f8e26de93300...', john: 'netntlm' },
  { type: 'bcrypt', mode: '3200', example: '$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6', john: 'bcrypt' },
  { type: 'WPA2', mode: '22000', example: 'WPA*02*025c9e2d...', john: 'wpapsk' },
  { type: 'Kerberos TGS (RC4)', mode: '13100', example: '$krb5tgs$23$*user$realm$spn*$...', john: 'krb5tgs' },
  { type: 'Kerberos AS-REP', mode: '18200', example: '$krb5asrep$23$user@domain:...', john: 'krb5asrep' },
  { type: 'MySQL 4.1+', mode: '300', example: '6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9', john: 'mysql-sha1' },
  { type: 'MSSQL (2012+)', mode: '1731', example: '0x02000102030...', john: 'mssql12' },
]

const WORDLISTS = [
  { name: 'rockyou.txt', path: '/usr/share/wordlists/rockyou.txt', desc: 'Classic 14M password list from RockYou breach' },
  { name: 'SecLists - Common', path: '/usr/share/seclists/Passwords/Common-Credentials/', desc: 'Curated common credentials (top 100, 1000, 10000)' },
  { name: 'SecLists - Default', path: '/usr/share/seclists/Passwords/Default-Credentials/', desc: 'Default credentials for services and devices' },
  { name: 'SecLists - Leaked DBs', path: '/usr/share/seclists/Passwords/Leaked-Databases/', desc: 'Passwords from various breaches' },
  { name: 'CeWL (Custom)', path: 'cewl https://target.com -d 3 -m 5 -w custom.txt', desc: 'Generate wordlist by spidering a target website' },
  { name: 'Crunch (Generated)', path: 'crunch 8 12 -o custom.txt', desc: 'Generate wordlist with specific patterns/lengths' },
]

const ATTACK_MODES = [
  { id: 'dictionary', label: 'Dictionary (0)', mode: '0', desc: 'Straight wordlist attack' },
  { id: 'combinator', label: 'Combinator (1)', mode: '1', desc: 'Combine two wordlists' },
  { id: 'bruteforce', label: 'Brute-force (3)', mode: '3', desc: 'Mask-based brute force' },
  { id: 'rulebased', label: 'Rule-based (0+rules)', mode: '0', desc: 'Dictionary with mutation rules' },
]

const COMMON_RULES = [
  { name: 'best64.rule', path: '/usr/share/hashcat/rules/best64.rule' },
  { name: 'rockyou-30000.rule', path: '/usr/share/hashcat/rules/rockyou-30000.rule' },
  { name: 'dive.rule', path: '/usr/share/hashcat/rules/dive.rule' },
  { name: 'OneRuleToRuleThemAll', path: '/usr/share/hashcat/rules/OneRuleToRuleThemAll.rule' },
]

const DEFAULT_CREDENTIALS = [
  { service: 'SSH', username: 'root', password: 'toor', notes: 'Kali Linux default' },
  { service: 'SSH', username: 'admin', password: 'admin', notes: 'Common IoT/router' },
  { service: 'MySQL', username: 'root', password: '(empty)', notes: 'Default install' },
  { service: 'MySQL', username: 'root', password: 'root', notes: 'Common setup' },
  { service: 'PostgreSQL', username: 'postgres', password: 'postgres', notes: 'Default install' },
  { service: 'MongoDB', username: '(no auth)', password: '(no auth)', notes: 'Auth disabled by default' },
  { service: 'Redis', username: '(no auth)', password: '(no auth)', notes: 'No auth by default' },
  { service: 'Tomcat', username: 'tomcat', password: 'tomcat', notes: 'Manager app' },
  { service: 'Tomcat', username: 'admin', password: 'admin', notes: 'Alternate default' },
  { service: 'Jenkins', username: 'admin', password: 'admin', notes: 'Initial setup' },
  { service: 'WordPress', username: 'admin', password: 'admin', notes: 'Common setup' },
  { service: 'phpMyAdmin', username: 'root', password: '(empty)', notes: 'MySQL root passthrough' },
  { service: 'SNMP', username: 'public', password: 'private', notes: 'Community strings (read/write)' },
  { service: 'VNC', username: '(none)', password: 'password', notes: 'Common weak password' },
  { service: 'Cisco IOS', username: 'cisco', password: 'cisco', notes: 'Legacy default' },
  { service: 'Cisco IOS', username: 'admin', password: 'admin', notes: 'Alternate default' },
]

const KEYBOARD_PATTERNS = ['qwerty', 'qwertz', 'azerty', 'asdf', 'asdfgh', 'zxcv', 'zxcvbn', '1234', '12345', '123456', '1234567', '12345678', '123456789', 'qazwsx', '!@#$', '!@#$%']
const COMMON_WORDS = ['password', 'admin', 'letmein', 'welcome', 'monkey', 'dragon', 'master', 'login', 'princess', 'football', 'shadow', 'sunshine', 'trustno1', 'iloveyou', 'batman', 'access', 'hello', 'charlie', 'donald', 'passw0rd', 'qwerty']

// ── Component ─────────────────────────────────────────────────────────
type TabKey = 'hash-gen' | 'pwd-strength' | 'hash-ref' | 'cred-patterns'

export default function PasswordHashTools() {
  const [activeTab, setActiveTab] = useState<TabKey>('hash-gen')
  const [copied, setCopied] = useState('')

  // Hash Generator state
  const [hashInput, setHashInput] = useState('')
  const [hexMode, setHexMode] = useState(false)
  const [hashes, setHashes] = useState<Record<string, string>>({})
  const [hashing, setHashing] = useState(false)

  // Password Strength state
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)

  // Hash Ref / Cracking state
  const [hcHashType, setHcHashType] = useState('0')
  const [hcHashFile, setHcHashFile] = useState('hashes.txt')
  const [hcWordlist, setHcWordlist] = useState('/usr/share/wordlists/rockyou.txt')
  const [hcAttackMode, setHcAttackMode] = useState('dictionary')
  const [hcMask, setHcMask] = useState('?a?a?a?a?a?a?a?a')
  const [hcRule, setHcRule] = useState('/usr/share/hashcat/rules/best64.rule')
  const [hcSecondWordlist, setHcSecondWordlist] = useState('wordlist2.txt')
  const [johnHashFile, setJohnHashFile] = useState('hashes.txt')
  const [johnFormat, setJohnFormat] = useState('Raw-MD5')
  const [johnWordlist, setJohnWordlist] = useState('/usr/share/wordlists/rockyou.txt')

  // Credential Patterns state
  const [policyMinLen, setPolicyMinLen] = useState(8)
  const [policyUpper, setPolicyUpper] = useState(true)
  const [policyLower, setPolicyLower] = useState(true)
  const [policyDigit, setPolicyDigit] = useState(true)
  const [policySpecial, setPolicySpecial] = useState(true)
  const [policyTestPwd, setPolicyTestPwd] = useState('')

  const copy = async (text: string, key: string) => {
    await copyToClipboard(text)
    setCopied(key)
    setTimeout(() => setCopied(''), 1500)
  }

  // ── Hash Generator Logic ──────────────────────────────────────────
  const generateHashes = async () => {
    if (!hashInput.trim()) return
    setHashing(true)
    try {
      const results: Record<string, string> = {}
      if (hexMode) {
        const cleanHex = hashInput.replace(/\s/g, '')
        if (!/^[0-9a-fA-F]*$/.test(cleanHex) || cleanHex.length % 2 !== 0) {
          setHashes({ error: 'Invalid hex input. Must be even-length hex string.' })
          setHashing(false)
          return
        }
        results['MD5'] = md5Hex(cleanHex)
        results['SHA-1'] = await hashHexWithCrypto('SHA-1', cleanHex)
        results['SHA-256'] = await hashHexWithCrypto('SHA-256', cleanHex)
        results['SHA-384'] = await hashHexWithCrypto('SHA-384', cleanHex)
        results['SHA-512'] = await hashHexWithCrypto('SHA-512', cleanHex)
      } else {
        results['MD5'] = md5(hashInput)
        results['SHA-1'] = await hashWithCrypto('SHA-1', hashInput)
        results['SHA-256'] = await hashWithCrypto('SHA-256', hashInput)
        results['SHA-384'] = await hashWithCrypto('SHA-384', hashInput)
        results['SHA-512'] = await hashWithCrypto('SHA-512', hashInput)
      }
      setHashes(results)
    } catch {
      setHashes({ error: 'Hashing failed' })
    }
    setHashing(false)
  }

  // ── Password Strength Logic ───────────────────────────────────────
  const analyzePassword = (pwd: string) => {
    if (!pwd) return null

    const hasUpper = /[A-Z]/.test(pwd)
    const hasLower = /[a-z]/.test(pwd)
    const hasDigit = /[0-9]/.test(pwd)
    const hasSpecial = /[^A-Za-z0-9]/.test(pwd)
    const length = pwd.length

    // Charset size for entropy
    let charsetSize = 0
    if (hasLower) charsetSize += 26
    if (hasUpper) charsetSize += 26
    if (hasDigit) charsetSize += 10
    if (hasSpecial) charsetSize += 33
    if (charsetSize === 0) charsetSize = 1

    const entropy = length * Math.log2(charsetSize)

    // Crack time estimates (seconds)
    const crackTimes = {
      'Online (1K/sec)': Math.pow(2, entropy) / 1000,
      'Offline slow (10K/sec)': Math.pow(2, entropy) / 10000,
      'Offline fast GPU (10B/sec)': Math.pow(2, entropy) / 10000000000,
    }

    // Pattern detection
    const warnings: string[] = []
    const lowerPwd = pwd.toLowerCase()

    for (const p of KEYBOARD_PATTERNS) {
      if (lowerPwd.includes(p)) warnings.push(`Keyboard pattern: "${p}"`)
    }
    for (const w of COMMON_WORDS) {
      if (lowerPwd.includes(w)) warnings.push(`Common word: "${w}"`)
    }
    const yearMatch = pwd.match(/(\d{4})/)
    if (yearMatch) {
      const year = parseInt(yearMatch[1])
      if (year >= 1950 && year <= 2030) warnings.push(`Date pattern: "${yearMatch[1]}"`)
    }
    if (/(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])/.test(pwd)) {
      warnings.push('Date pattern detected (YYMMDD)')
    }
    if (/(.)\1{2,}/.test(pwd)) warnings.push('Repeated characters detected')
    if (/(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i.test(pwd)) {
      warnings.push('Sequential letter pattern detected')
    }
    if (/(?:012|123|234|345|456|567|678|789)/.test(pwd)) {
      warnings.push('Sequential number pattern detected')
    }

    // Score calculation (0-100)
    let score = 0
    score += Math.min(25, length * 2) // Length: up to 25
    score += (hasUpper ? 10 : 0) + (hasLower ? 10 : 0) + (hasDigit ? 10 : 0) + (hasSpecial ? 15 : 0) // Char types: up to 45
    score += Math.min(30, entropy / 3) // Entropy: up to 30
    score -= warnings.length * 10 // Penalties
    score = Math.max(0, Math.min(100, Math.round(score)))

    // Recommendations
    const recommendations: string[] = []
    if (length < 12) recommendations.push('Increase length to at least 12 characters')
    if (length < 16) recommendations.push('Consider 16+ characters for sensitive accounts')
    if (!hasUpper) recommendations.push('Add uppercase letters')
    if (!hasLower) recommendations.push('Add lowercase letters')
    if (!hasDigit) recommendations.push('Add numbers')
    if (!hasSpecial) recommendations.push('Add special characters (!@#$%^&*)')
    if (warnings.length > 0) recommendations.push('Avoid common patterns, words, and sequences')
    if (entropy < 60) recommendations.push('Use a passphrase or password manager for stronger entropy')

    return { length, hasUpper, hasLower, hasDigit, hasSpecial, charsetSize, entropy, crackTimes, warnings, score, recommendations }
  }

  const formatCrackTime = (seconds: number): string => {
    if (seconds < 0.001) return 'Instant'
    if (seconds < 1) return `${(seconds * 1000).toFixed(0)} ms`
    if (seconds < 60) return `${seconds.toFixed(1)} seconds`
    if (seconds < 3600) return `${(seconds / 60).toFixed(1)} minutes`
    if (seconds < 86400) return `${(seconds / 3600).toFixed(1)} hours`
    if (seconds < 86400 * 365) return `${(seconds / 86400).toFixed(1)} days`
    if (seconds < 86400 * 365 * 1000) return `${(seconds / (86400 * 365)).toFixed(1)} years`
    if (seconds < 86400 * 365 * 1e6) return `${(seconds / (86400 * 365 * 1000)).toFixed(1)}K years`
    if (seconds < 86400 * 365 * 1e9) return `${(seconds / (86400 * 365 * 1e6)).toFixed(1)}M years`
    return `${(seconds / (86400 * 365 * 1e9)).toFixed(1)}B+ years`
  }

  // ── Command Generators ────────────────────────────────────────────
  const generateHashcatCmd = (): string => {
    const attack = ATTACK_MODES.find(a => a.id === hcAttackMode)
    let cmd = `hashcat -m ${hcHashType} -a ${attack?.mode || '0'}`

    if (hcAttackMode === 'bruteforce') {
      cmd += ` ${hcHashFile} ${hcMask}`
    } else if (hcAttackMode === 'combinator') {
      cmd += ` ${hcHashFile} ${hcWordlist} ${hcSecondWordlist}`
    } else if (hcAttackMode === 'rulebased') {
      cmd += ` ${hcHashFile} ${hcWordlist} -r ${hcRule}`
    } else {
      cmd += ` ${hcHashFile} ${hcWordlist}`
    }

    cmd += ' --force -O'
    return cmd
  }

  const generateJohnCmd = (): string => {
    return `john --format=${johnFormat} --wordlist=${johnWordlist} ${johnHashFile}`
  }

  // ── Policy Check ──────────────────────────────────────────────────
  const checkPolicy = (pwd: string) => {
    if (!pwd) return null
    const checks = [
      { label: `Minimum length (${policyMinLen})`, pass: pwd.length >= policyMinLen },
      ...(policyUpper ? [{ label: 'Contains uppercase', pass: /[A-Z]/.test(pwd) }] : []),
      ...(policyLower ? [{ label: 'Contains lowercase', pass: /[a-z]/.test(pwd) }] : []),
      ...(policyDigit ? [{ label: 'Contains digit', pass: /[0-9]/.test(pwd) }] : []),
      ...(policySpecial ? [{ label: 'Contains special character', pass: /[^A-Za-z0-9]/.test(pwd) }] : []),
    ]
    return checks
  }

  const analysis = analyzePassword(password)
  const policyResults = checkPolicy(policyTestPwd)

  // ── Score color ───────────────────────────────────────────────────
  const scoreColor = (score: number) => {
    if (score < 30) return '#ff4444'
    if (score < 60) return '#ffaa00'
    if (score < 80) return '#44aaff'
    return '#44ff44'
  }

  const TABS: { id: TabKey; label: string }[] = [
    { id: 'hash-gen', label: '🔐 Hash Generator' },
    { id: 'pwd-strength', label: '🛡️ Password Analyzer' },
    { id: 'hash-ref', label: '⚡ Cracking Reference' },
    { id: 'cred-patterns', label: '🔑 Credential Patterns' },
  ]

  return (
    <div className="space-y-6">
      <div>
        <h1 className="section-heading">Password &amp; Hash Tools</h1>
        <p className="section-subheading">Hash generation, password analysis, cracking references, and credential patterns</p>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 flex-wrap">
        {TABS.map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)} className={`tab-btn ${activeTab === t.id ? 'active' : ''}`}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */}
      {/* TAB 1: Hash Generator */}
      {/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */}
      {activeTab === 'hash-gen' && (
        <div className="space-y-4">
          <div className="card">
            <div className="card-header">
              <span className="card-title">Hash Generator</span>
              <span className="badge badge-warning">Blue + Red</span>
            </div>

            <div className="space-y-3">
              <div className="flex items-center gap-3 mb-2">
                <label className="text-xs text-gray-400 flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={hexMode}
                    onChange={e => setHexMode(e.target.checked)}
                    className="rounded"
                  />
                  Hex input mode (hash raw bytes)
                </label>
              </div>

              <textarea
                className="cyber-textarea w-full h-24"
                value={hashInput}
                onChange={e => setHashInput(e.target.value)}
                placeholder={hexMode ? 'Enter hex string (e.g., 48656c6c6f)...' : 'Enter text to hash...'}
              />

              <button
                onClick={generateHashes}
                disabled={!hashInput.trim() || hashing}
                className="btn-primary disabled:opacity-50"
              >
                {hashing ? 'Hashing...' : 'Generate Hashes'}
              </button>
            </div>
          </div>

          {Object.keys(hashes).length > 0 && (
            <div className="card">
              <div className="card-header">
                <span className="card-title">Hash Results</span>
              </div>

              {hashes.error ? (
                <div className="text-red-400 text-sm">{hashes.error}</div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="cyber-table">
                    <thead>
                      <tr>
                        <th>Algorithm</th>
                        <th>Hash</th>
                        <th>Copy</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(hashes).map(([algo, hash]) => (
                        <tr key={algo}>
                          <td className="font-semibold text-blue-400 whitespace-nowrap">{algo}</td>
                          <td>
                            <code className="text-xs font-mono text-green-400 break-all">{hash}</code>
                          </td>
                          <td>
                            <button onClick={() => copy(hash, `hash-${algo}`)} className="text-xs text-blue-400 hover:underline">
                              {copied === `hash-${algo}` ? '✓' : '⧉'}
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */}
      {/* TAB 2: Password Strength Analyzer */}
      {/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */}
      {activeTab === 'pwd-strength' && (
        <div className="space-y-4">
          <div className="card">
            <div className="card-header">
              <span className="card-title">Password Strength Analyzer</span>
              <span className="badge badge-success">Blue Team</span>
            </div>

            <div className="flex gap-2 items-center">
              <div className="relative flex-1">
                <input
                  className="cyber-input w-full pr-16"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  placeholder="Enter password to analyze..."
                />
                <button
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-xs text-gray-400 hover:text-white"
                >
                  {showPassword ? '🙈 Hide' : '👁️ Show'}
                </button>
              </div>
            </div>
          </div>

          {analysis && (
            <>
              {/* Score Bar */}
              <div className="card">
                <div className="card-header">
                  <span className="card-title">Overall Score</span>
                  <span className="text-2xl font-bold" style={{ color: scoreColor(analysis.score) }}>
                    {analysis.score}/100
                  </span>
                </div>
                <div className="w-full h-4 rounded-full overflow-hidden" style={{ background: 'rgba(255,255,255,0.1)' }}>
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${analysis.score}%`,
                      background: `linear-gradient(90deg, #ff4444, #ffaa00, #44ff44)`,
                      backgroundSize: '300% 100%',
                      backgroundPosition: `${100 - analysis.score}% 0`,
                    }}
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Length & Character Types */}
                <div className="card">
                  <div className="card-header">
                    <span className="card-title">Character Analysis</span>
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between items-center p-2 rounded" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                      <span className="text-sm text-gray-300">Length</span>
                      <span className={`font-bold ${analysis.length < 8 ? 'text-red-400' : analysis.length < 12 ? 'text-yellow-400' : 'text-green-400'}`}>
                        {analysis.length} chars
                      </span>
                    </div>
                    {[
                      { label: 'Uppercase (A-Z)', has: analysis.hasUpper },
                      { label: 'Lowercase (a-z)', has: analysis.hasLower },
                      { label: 'Digits (0-9)', has: analysis.hasDigit },
                      { label: 'Special (!@#$...)', has: analysis.hasSpecial },
                    ].map(item => (
                      <div key={item.label} className="flex justify-between items-center p-2 rounded" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                        <span className="text-sm text-gray-300">{item.label}</span>
                        <span className={item.has ? 'text-green-400' : 'text-red-400'}>
                          {item.has ? '✓' : '✗'}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Entropy & Crack Time */}
                <div className="card">
                  <div className="card-header">
                    <span className="card-title">Entropy &amp; Crack Time</span>
                  </div>
                  <div className="space-y-2">
                    <div className="flex justify-between items-center p-2 rounded" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                      <span className="text-sm text-gray-300">Charset size</span>
                      <span className="text-blue-400 font-mono">{analysis.charsetSize}</span>
                    </div>
                    <div className="flex justify-between items-center p-2 rounded" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                      <span className="text-sm text-gray-300">Entropy</span>
                      <span className={`font-mono font-bold ${analysis.entropy < 40 ? 'text-red-400' : analysis.entropy < 60 ? 'text-yellow-400' : 'text-green-400'}`}>
                        {analysis.entropy.toFixed(1)} bits
                      </span>
                    </div>
                    {Object.entries(analysis.crackTimes).map(([scenario, time]) => (
                      <div key={scenario} className="flex justify-between items-center p-2 rounded" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                        <span className="text-xs text-gray-400">{scenario}</span>
                        <span className="text-sm font-mono text-orange-400">{formatCrackTime(time)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Warnings */}
              {analysis.warnings.length > 0 && (
                <div className="card">
                  <div className="card-header">
                    <span className="card-title">⚠️ Pattern Warnings</span>
                    <span className="badge badge-critical">{analysis.warnings.length}</span>
                  </div>
                  <div className="space-y-1">
                    {analysis.warnings.map((w, i) => (
                      <div key={i} className="flex items-center gap-2 p-2 rounded text-sm text-yellow-400" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                        <span>⚠️</span> {w}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommendations */}
              {analysis.recommendations.length > 0 && (
                <div className="card">
                  <div className="card-header">
                    <span className="card-title">💡 Recommendations</span>
                  </div>
                  <div className="space-y-1">
                    {analysis.recommendations.map((r, i) => (
                      <div key={i} className="flex items-center gap-2 p-2 rounded text-sm text-gray-300" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                        <span className="text-blue-400">→</span> {r}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */}
      {/* TAB 3: Hash Lookup / Cracking Reference */}
      {/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */}
      {activeTab === 'hash-ref' && (
        <div className="space-y-4">
          {/* Hashcat Mode Reference */}
          <div className="card overflow-x-auto">
            <div className="card-header">
              <span className="card-title">Hashcat Mode Reference</span>
              <span className="badge badge-critical">Red Team</span>
            </div>
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>Hash Type</th>
                  <th>Hashcat Mode</th>
                  <th>Example Hash</th>
                  <th>John Format</th>
                </tr>
              </thead>
              <tbody>
                {HASHCAT_MODES.map(h => (
                  <tr key={h.type}>
                    <td className="font-semibold text-blue-400 whitespace-nowrap">{h.type}</td>
                    <td><code className="text-green-400 font-mono">{h.mode}</code></td>
                    <td>
                      <code className="text-xs font-mono text-gray-400 break-all">{h.example.length > 50 ? h.example.substring(0, 50) + '...' : h.example}</code>
                    </td>
                    <td className="text-xs text-orange-400">{h.john}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Common Wordlists */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Common Wordlists &amp; Tools</span>
            </div>
            <div className="space-y-2">
              {WORDLISTS.map(wl => (
                <div key={wl.name} className="flex items-center gap-3 p-2 rounded" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                  <div className="flex-1">
                    <div className="text-sm font-semibold text-blue-400">{wl.name}</div>
                    <code className="text-xs font-mono text-gray-500">{wl.path}</code>
                    <div className="text-xs text-gray-400 mt-0.5">{wl.desc}</div>
                  </div>
                  <button onClick={() => copy(wl.path, `wl-${wl.name}`)} className="text-xs text-blue-400 hover:underline">
                    {copied === `wl-${wl.name}` ? '✓' : '⧉'}
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Hashcat Command Generator */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Hashcat Command Generator</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-4">
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Hash Type</label>
                <select
                  className="cyber-input w-full"
                  value={hcHashType}
                  onChange={e => setHcHashType(e.target.value)}
                >
                  {HASHCAT_MODES.map(h => (
                    <option key={h.mode} value={h.mode}>{h.type} (-m {h.mode})</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-xs text-gray-400 mb-1 block">Attack Mode</label>
                <select
                  className="cyber-input w-full"
                  value={hcAttackMode}
                  onChange={e => setHcAttackMode(e.target.value)}
                >
                  {ATTACK_MODES.map(a => (
                    <option key={a.id} value={a.id}>{a.label} — {a.desc}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-xs text-gray-400 mb-1 block">Hash File</label>
                <input
                  className="cyber-input w-full"
                  value={hcHashFile}
                  onChange={e => setHcHashFile(e.target.value)}
                  placeholder="hashes.txt"
                />
              </div>

              {hcAttackMode !== 'bruteforce' && (
                <div>
                  <label className="text-xs text-gray-400 mb-1 block">Wordlist</label>
                  <input
                    className="cyber-input w-full"
                    value={hcWordlist}
                    onChange={e => setHcWordlist(e.target.value)}
                    placeholder="/usr/share/wordlists/rockyou.txt"
                  />
                </div>
              )}

              {hcAttackMode === 'bruteforce' && (
                <div>
                  <label className="text-xs text-gray-400 mb-1 block">Mask (?a=all, ?l=lower, ?u=upper, ?d=digit, ?s=special)</label>
                  <input
                    className="cyber-input w-full"
                    value={hcMask}
                    onChange={e => setHcMask(e.target.value)}
                    placeholder="?a?a?a?a?a?a?a?a"
                  />
                </div>
              )}

              {hcAttackMode === 'combinator' && (
                <div>
                  <label className="text-xs text-gray-400 mb-1 block">Second Wordlist</label>
                  <input
                    className="cyber-input w-full"
                    value={hcSecondWordlist}
                    onChange={e => setHcSecondWordlist(e.target.value)}
                    placeholder="wordlist2.txt"
                  />
                </div>
              )}

              {hcAttackMode === 'rulebased' && (
                <div>
                  <label className="text-xs text-gray-400 mb-1 block">Rule File</label>
                  <select
                    className="cyber-input w-full"
                    value={hcRule}
                    onChange={e => setHcRule(e.target.value)}
                  >
                    {COMMON_RULES.map(r => (
                      <option key={r.name} value={r.path}>{r.name}</option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-gray-400">Generated Command</span>
                <button onClick={() => copy(generateHashcatCmd(), 'hc-cmd')} className="btn-primary text-xs py-1">
                  {copied === 'hc-cmd' ? '✓ Copied' : 'Copy'}
                </button>
              </div>
              <pre className="code-block text-xs overflow-x-auto whitespace-pre-wrap" style={{ color: '#39ff14' }}>
                {generateHashcatCmd()}
              </pre>
            </div>
          </div>

          {/* John the Ripper Command Generator */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">John the Ripper Command Generator</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-4">
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Format</label>
                <select
                  className="cyber-input w-full"
                  value={johnFormat}
                  onChange={e => setJohnFormat(e.target.value)}
                >
                  {HASHCAT_MODES.map(h => (
                    <option key={h.john} value={h.john}>{h.john} ({h.type})</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-xs text-gray-400 mb-1 block">Hash File</label>
                <input
                  className="cyber-input w-full"
                  value={johnHashFile}
                  onChange={e => setJohnHashFile(e.target.value)}
                  placeholder="hashes.txt"
                />
              </div>

              <div>
                <label className="text-xs text-gray-400 mb-1 block">Wordlist</label>
                <input
                  className="cyber-input w-full"
                  value={johnWordlist}
                  onChange={e => setJohnWordlist(e.target.value)}
                  placeholder="/usr/share/wordlists/rockyou.txt"
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-gray-400">Generated Command</span>
                <button onClick={() => copy(generateJohnCmd(), 'john-cmd')} className="btn-primary text-xs py-1">
                  {copied === 'john-cmd' ? '✓ Copied' : 'Copy'}
                </button>
              </div>
              <pre className="code-block text-xs overflow-x-auto whitespace-pre-wrap" style={{ color: '#39ff14' }}>
                {generateJohnCmd()}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */}
      {/* TAB 4: Credential Patterns */}
      {/* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ */}
      {activeTab === 'cred-patterns' && (
        <div className="space-y-4">
          {/* Default Credentials Table */}
          <div className="card overflow-x-auto">
            <div className="card-header">
              <span className="card-title">Default Credentials Reference</span>
              <span className="badge badge-critical">Red Team</span>
            </div>
            <table className="cyber-table">
              <thead>
                <tr>
                  <th>Service</th>
                  <th>Username</th>
                  <th>Password</th>
                  <th>Notes</th>
                  <th>Copy</th>
                </tr>
              </thead>
              <tbody>
                {DEFAULT_CREDENTIALS.map((cred, i) => (
                  <tr key={i}>
                    <td className="font-semibold text-blue-400 whitespace-nowrap">{cred.service}</td>
                    <td><code className="text-sm font-mono text-green-400">{cred.username}</code></td>
                    <td><code className="text-sm font-mono text-orange-400">{cred.password}</code></td>
                    <td className="text-xs text-gray-400">{cred.notes}</td>
                    <td>
                      <button
                        onClick={() => copy(`${cred.username}:${cred.password}`, `cred-${i}`)}
                        className="text-xs text-blue-400 hover:underline"
                      >
                        {copied === `cred-${i}` ? '✓' : '⧉'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Password Policy Check */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Password Policy Checker</span>
              <span className="badge badge-success">Blue Team</span>
            </div>

            <div className="space-y-4">
              {/* Policy Configuration */}
              <div>
                <h3 className="text-sm font-semibold text-gray-300 mb-2">Define Policy</h3>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                  <div>
                    <label className="text-xs text-gray-400 mb-1 block">Min Length</label>
                    <input
                      className="cyber-input w-full"
                      type="number"
                      min={1}
                      max={128}
                      value={policyMinLen}
                      onChange={e => setPolicyMinLen(parseInt(e.target.value) || 1)}
                    />
                  </div>
                  {[
                    { label: 'Uppercase', val: policyUpper, set: setPolicyUpper },
                    { label: 'Lowercase', val: policyLower, set: setPolicyLower },
                    { label: 'Digits', val: policyDigit, set: setPolicyDigit },
                    { label: 'Special', val: policySpecial, set: setPolicySpecial },
                  ].map(p => (
                    <label key={p.label} className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer pt-5">
                      <input type="checkbox" checked={p.val} onChange={e => p.set(e.target.checked)} className="rounded" />
                      {p.label}
                    </label>
                  ))}
                </div>
              </div>

              {/* Test Password */}
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Test Password Against Policy</label>
                <input
                  className="cyber-input w-full"
                  type="text"
                  value={policyTestPwd}
                  onChange={e => setPolicyTestPwd(e.target.value)}
                  placeholder="Enter password to test against policy..."
                />
              </div>

              {/* Policy Results */}
              {policyResults && (
                <div className="space-y-1">
                  {policyResults.map((check, i) => (
                    <div key={i} className="flex items-center gap-2 p-2 rounded" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                      <span className={check.pass ? 'text-green-400' : 'text-red-400'}>
                        {check.pass ? '✓' : '✗'}
                      </span>
                      <span className="text-sm text-gray-300">{check.label}</span>
                      <span className={`badge ${check.pass ? 'badge-success' : 'badge-critical'} ml-auto`}>
                        {check.pass ? 'PASS' : 'FAIL'}
                      </span>
                    </div>
                  ))}
                  <div className="mt-2 p-2 rounded" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                    <span className="text-sm font-semibold">
                      Overall:{' '}
                      {policyResults.every(c => c.pass) ? (
                        <span className="text-green-400">✓ Meets policy requirements</span>
                      ) : (
                        <span className="text-red-400">✗ Does not meet policy requirements</span>
                      )}
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
