import { describe, expect, test } from 'bun:test'
import { parseDocument } from 'yaml'
import { listMihomoProxies, listMihomoTakenNames, proxyItemName, replaceMihomoProxy, withProxyName } from '../src/lib/mihomoReplace'

const ITEM_A = "  - name: 'A'\n    type: vless\n    server: a.example.com\n    port: 443\n"
const ITEM_EMOJI = "  - name: 'DE 🇩🇪 node'\n    type: vless\n    server: de.example.com\n    port: 443\n"
const ITEM_NUMERIC_NAME = "  - name: '123'\n    type: vless\n    server: a.example.com\n    port: 443\n"
const ITEM_NESTED = "  - name: 'A'\n    type: vless\n    ws-opts:\n      path: /ws\n      headers:\n        Host: a.example.com\n    alpn:\n      - h2\n"

const expectParses = (t: string) => expect(parseDocument(t).errors).toEqual([])

describe('proxyItemName', () => {
  test('extracts name from generated item', () => {
    expect(proxyItemName(ITEM_A)).toBe('A')
  })

  test('extracts name with emoji', () => {
    expect(proxyItemName(ITEM_EMOJI)).toBe('DE 🇩🇪 node')
  })

  test('returns null on unparsable input', () => {
    expect(proxyItemName('not: [valid: yaml')).toBeNull()
  })
})

describe('withProxyName', () => {
  test('replaces name, keeps rest byte-identical', () => {
    const result = withProxyName(ITEM_A, 'B')
    expect(result).toBe("  - name: 'B'\n    type: vless\n    server: a.example.com\n    port: 443\n")
  })

  test('escapes single quotes in new name', () => {
    const result = withProxyName(ITEM_A, "it's B")
    expect(result).toBe("  - name: 'it''s B'\n    type: vless\n    server: a.example.com\n    port: 443\n")
  })

  test('keeps emoji item body untouched', () => {
    const result = withProxyName(ITEM_EMOJI, 'X')
    expect(result).toBe("  - name: 'X'\n    type: vless\n    server: de.example.com\n    port: 443\n")
  })
})

describe('listMihomoProxies', () => {
  test('lists names in order', () => {
    const text = "proxies:\n  - name: 'a'\n    type: vless\n  - name: 'b'\n    type: vless\n"
    expect(listMihomoProxies(text)).toEqual(['a', 'b'])
  })

  test('returns [] on parse error', () => {
    expect(listMihomoProxies('not: [valid: yaml')).toEqual([])
  })

  test('returns [] when proxies section missing', () => {
    expect(listMihomoProxies('mode: rule\n')).toEqual([])
  })
})

describe('listMihomoTakenNames', () => {
  test('collects proxies[].name, proxy-groups[].name and builtins', () => {
    const text = "proxies:\n  - name: 'hk'\n    type: vless\nproxy-groups:\n  - name: auto\n    proxies:\n      - hk\n"
    const names = listMihomoTakenNames(text)
    expect(names).toContain('hk')
    expect(names).toContain('auto')
    expect(names).toContain('DIRECT')
    expect(names).toContain('REJECT')
  })

  test('substring name like "hk-2" does not falsely collide with "hk"', () => {
    const text = "proxies:\n  - name: 'hk'\n    type: vless\n  - name: 'hk-2'\n    type: vless\n"
    const names = listMihomoTakenNames(text)
    expect(names.includes('hk')).toBe(true)
    expect(names.includes('hk-2')).toBe(true)
    // exact match only: excluding 'hk' must not affect 'hk-2'
    const withoutHk = names.filter((n) => n !== 'hk')
    expect(withoutHk.includes('hk-2')).toBe(true)
    expect(withoutHk.includes('hk')).toBe(false)
  })

  test('never throws on unparsable input, returns builtins', () => {
    expect(listMihomoTakenNames('not: [valid: yaml')).toEqual(expect.arrayContaining(['DIRECT', 'REJECT']))
  })
})

describe('replaceMihomoProxy: basic replace', () => {
  test('renameRefs=false keeps old name, dash indent col 2', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\n    port: 443\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: false })
    expect(res.name).toBe('old')
    expect(res.refs).toBe(0)
    expect(res.line).toBe(2)
    expect(res.text).toBe("proxies:\n  - name: 'old'\n    type: vless\n    server: a.example.com\n    port: 443\n")
  })

  test('renameRefs=true uses generated name', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\n    port: 443\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    expect(res.name).toBe('A')
    expect(res.text).toBe("proxies:\n  - name: 'A'\n    type: vless\n    server: a.example.com\n    port: 443\n")
  })

  test('dash at column 0 is preserved (deindented block)', () => {
    const text = "proxies:\n- name: old\n  type: vless\n  port: 443\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: false })
    expect(res.text).toBe("proxies:\n- name: 'old'\n  type: vless\n  server: a.example.com\n  port: 443\n")
  })

  test('name unchanged (generated name === oldName) yields refs 0', () => {
    const text = "proxies:\n  - name: 'A'\n    type: vless\n"
    const res = replaceMihomoProxy(text, 'A', ITEM_A, { renameRefs: true })
    expect(res.name).toBe('A')
    expect(res.refs).toBe(0)
  })
})

describe('replaceMihomoProxy: item position & EOF', () => {
  test('replaces first item, keeps others intact', () => {
    const text = "proxies:\n  - name: 'a'\n    type: vless\n  - name: 'b'\n    type: vless\n"
    const res = replaceMihomoProxy(text, 'a', ITEM_A, { renameRefs: false })
    expect(res.text).toBe(
      "proxies:\n  - name: 'a'\n    type: vless\n    server: a.example.com\n    port: 443\n  - name: 'b'\n    type: vless\n"
    )
  })

  test('replaces middle item', () => {
    const text = "proxies:\n  - name: 'a'\n    type: vless\n  - name: 'b'\n    type: vless\n  - name: 'c'\n    type: vless\n"
    const res = replaceMihomoProxy(text, 'b', ITEM_A, { renameRefs: false })
    expect(res.text).toBe(
      "proxies:\n  - name: 'a'\n    type: vless\n  - name: 'b'\n    type: vless\n    server: a.example.com\n    port: 443\n  - name: 'c'\n    type: vless\n"
    )
  })

  test('replaces last item at EOF without trailing newline', () => {
    const text = "proxies:\n  - name: 'a'\n    type: vless\n  - name: 'b'\n    type: vless"
    const res = replaceMihomoProxy(text, 'b', ITEM_A, { renameRefs: false })
    expect(res.text).toBe("proxies:\n  - name: 'a'\n    type: vless\n  - name: 'b'\n    type: vless\n    server: a.example.com\n    port: 443\n")
  })
})

describe('replaceMihomoProxy: comments preserved', () => {
  test('comment between items preserved when replacing earlier item', () => {
    const text = "proxies:\n  - name: 'a'\n    type: vless\n  # keep me\n  - name: 'b'\n    type: vless\n"
    const res = replaceMihomoProxy(text, 'a', ITEM_A, { renameRefs: false })
    expect(res.text).toBe(
      "proxies:\n  - name: 'a'\n    type: vless\n    server: a.example.com\n    port: 443\n  # keep me\n  - name: 'b'\n    type: vless\n"
    )
  })

  test('inline comment on neighbour item preserved', () => {
    const text = "proxies:\n  - name: 'a'\n    type: vless\n  - name: 'b' # keep\n    type: vless\n"
    const res = replaceMihomoProxy(text, 'a', ITEM_A, { renameRefs: false })
    expect(res.text).toBe(
      "proxies:\n  - name: 'a'\n    type: vless\n    server: a.example.com\n    port: 443\n  - name: 'b' # keep\n    type: vless\n"
    )
  })

  test('comments elsewhere in the document preserved', () => {
    const text = "# top comment\nproxies:\n  - name: 'a'\n    type: vless\nmode: rule # trailing\n"
    const res = replaceMihomoProxy(text, 'a', ITEM_A, { renameRefs: false })
    expect(res.text).toBe("# top comment\nproxies:\n  - name: 'a'\n    type: vless\n    server: a.example.com\n    port: 443\nmode: rule # trailing\n")
  })
})

describe('replaceMihomoProxy: name quoting styles in config', () => {
  test('double-quoted old name', () => {
    const text = 'proxies:\n  - name: "old"\n    type: vless\n'
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: false })
    expect(res.name).toBe('old')
    expect(res.text).toContain("- name: 'old'\n    type: vless\n    server: a.example.com")
  })

  test('plain old name', () => {
    const text = 'proxies:\n  - name: old\n    type: vless\n'
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: false })
    expect(res.name).toBe('old')
  })

  test('plain name with emoji flag', () => {
    const text = "proxies:\n  - name: 🇩🇪 DE\n    type: vless\n"
    const res = replaceMihomoProxy(text, '🇩🇪 DE', ITEM_A, { renameRefs: false })
    expect(res.name).toBe('🇩🇪 DE')
    expectParses(res.text)
  })
})

describe('replaceMihomoProxy: proxy-groups references', () => {
  test('renames block-form proxy-groups[].proxies[]', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\nproxy-groups:\n  - name: auto\n    proxies:\n      - old\n      - DIRECT\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(1)
    expect(res.text).toBe(
      "proxies:\n  - name: 'A'\n    type: vless\n    server: a.example.com\n    port: 443\nproxy-groups:\n  - name: auto\n    proxies:\n      - A\n      - DIRECT\n"
    )
  })

  test('renames flow-form proxy-groups[].proxies[]', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\nproxy-groups:\n  - name: auto\n    proxies: [DIRECT, old]\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(1)
    expect(res.text).toContain('proxies: [DIRECT, A]')
    expectParses(res.text)
  })

  test('group name equal to old proxy name is not itself renamed', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\nproxy-groups:\n  - name: old\n    proxies:\n      - old\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    // group's own name key stays 'old' (unquoted), only the proxies[] reference is renamed to A
    expect(res.text).toContain('  - name: old\n    proxies:\n      - A\n')
  })

  test('renaming to a name equal to an existing group name throws', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\nproxy-groups:\n  - name: A\n    proxies:\n      - old\n"
    expect(() => replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })).toThrow('уже используется')
  })
})

describe('replaceMihomoProxy: dialer-proxy / providers / listeners / tunnels', () => {
  test('dialer-proxy in another proxy is renamed', () => {
    const text =
      "proxies:\n  - name: 'old'\n    type: vless\n  - name: 'chain'\n    type: vless\n    dialer-proxy: old\nproxy-groups:\n  - name: g\n    proxies:\n      - chain\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(1)
    expect(res.text).toContain('dialer-proxy: A')
  })

  test('proxy-providers.*.proxy and override.dialer-proxy renamed', () => {
    const text =
      "proxies:\n  - name: 'old'\n    type: vless\nproxy-providers:\n  p1:\n    type: http\n    url: https://example.com\n    proxy: old\n    override:\n      dialer-proxy: old\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(2)
    expect(res.text).toContain('proxy: A')
    expect(res.text).toContain('dialer-proxy: A')
  })

  test('rule-providers.*.proxy renamed', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\nrule-providers:\n  r1:\n    type: http\n    proxy: old\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(1)
    expect(res.text).toContain('proxy: A')
  })

  test('listeners[].proxy renamed', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\nlisteners:\n  - name: l1\n    type: tproxy\n    proxy: old\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(1)
    expect(res.text).toContain('proxy: A')
  })

  test('tunnels[] map form .proxy renamed', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\ntunnels:\n  - network: [tcp]\n    address: 0.0.0.0:53\n    proxy: old\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(1)
    expect(res.text).toContain('proxy: A')
  })

  test('tunnels[] string form 4th field renamed', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\ntunnels:\n  - tcp,0.0.0.0:53,8.8.8.8:53,old\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(1)
    expect(res.text).toContain('tcp,0.0.0.0:53,8.8.8.8:53,A')
  })

  test('ntp.dialer-proxy renamed', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\nntp:\n  enable: true\n  server: time.apple.com\n  dialer-proxy: old\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(1)
    expect(res.text).toContain('dialer-proxy: A')
  })
})

describe('replaceMihomoProxy: rules[] and sub-rules', () => {
  test('normal rule payload renamed', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\nrules:\n  - DOMAIN-SUFFIX,x.com,old\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(1)
    expect(res.text).toContain('DOMAIN-SUFFIX,x.com,A')
  })

  test('rule with no-resolve extra field renamed', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\nrules:\n  - IP-CIDR,1.2.3.0/24,old,no-resolve\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(1)
    expect(res.text).toContain('IP-CIDR,1.2.3.0/24,A,no-resolve')
  })

  test('AND logic rule with nested parens renamed', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\nrules:\n  - 'AND,((DOMAIN,x.com),(NETWORK,UDP)),old'\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(1)
    expect(res.text).toContain("AND,((DOMAIN,x.com),(NETWORK,UDP)),A")
    expectParses(res.text)
  })

  test('MATCH rule renamed', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\nrules:\n  - MATCH,old\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(1)
    expect(res.text).toContain('MATCH,A')
  })

  test('SUB-RULE payload is skipped', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\nrules:\n  - SUB-RULE,(NETWORK,UDP),old\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(0)
    expect(res.text).toContain('SUB-RULE,(NETWORK,UDP),old')
  })

  test('RULE-SET payload equal to oldName is not touched', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\nrules:\n  - RULE-SET,old,DIRECT\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(0)
    expect(res.text).toContain('RULE-SET,old,DIRECT')
  })

  test('sub-rules section entries renamed', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\nsub-rules:\n  sub1:\n    - DOMAIN-SUFFIX,x.com,old\n    - MATCH,old\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(2)
    expect(res.text).toContain('DOMAIN-SUFFIX,x.com,A')
    expect(res.text).toContain('MATCH,A')
  })
})

describe('replaceMihomoProxy: dns fragments', () => {
  test('#OLD fragment renamed', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\ndns:\n  nameserver:\n    - https://1.1.1.1/dns-query#old\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(1)
    expect(res.text).toContain('https://1.1.1.1/dns-query#A')
    expectParses(res.text)
  })

  test('#OLD&h3=true fragment renamed keeping options', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\ndns:\n  nameserver:\n    - https://1.1.1.1/dns-query#old&h3=true\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(1)
    expect(res.text).toContain('https://1.1.1.1/dns-query#A&h3=true')
  })

  test('nameserver-policy value renamed', () => {
    const text =
      "proxies:\n  - name: 'old'\n    type: vless\ndns:\n  nameserver-policy:\n    'geosite:cn': https://1.1.1.1/dns-query#old\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(1)
    expect(res.text).toContain('https://1.1.1.1/dns-query#A')
  })
})

describe('replaceMihomoProxy: invalid generated item (no silent fallback)', () => {
  const BROKEN_ITEM = "  - name: 'A'\n    type: ss\n    password: a: b\n    port: 443\n"

  test('renameRefs=true throws on unparsable item, text unchanged', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\n"
    expect(() => replaceMihomoProxy(text, 'old', BROKEN_ITEM, { renameRefs: true })).toThrow('корректным YAML')
    expect(text).toBe("proxies:\n  - name: 'old'\n    type: vless\n")
  })

  test('renameRefs=false throws on unparsable item, text unchanged', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\n"
    expect(() => replaceMihomoProxy(text, 'old', BROKEN_ITEM, { renameRefs: false })).toThrow('корректным YAML')
    expect(text).toBe("proxies:\n  - name: 'old'\n    type: vless\n")
  })
})

describe('replaceMihomoProxy: dash on its own line', () => {
  test('first item: dash-alone layout parses and neighbour intact', () => {
    const text = "proxies:\n  -\n    name: old\n    type: vless\n  - name: b\n    type: vless\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: false })
    expectParses(res.text)
    expect(res.text).toContain("- name: 'old'\n    type: vless\n    server: a.example.com\n    port: 443\n")
    expect(res.text).toContain("  - name: b\n    type: vless\n")
  })

  test('middle item: dash-alone layout parses and both neighbours intact', () => {
    const text =
      "proxies:\n  - name: a\n    type: vless\n  -\n    name: old\n    type: vless\n  - name: c\n    type: vless\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: false })
    expectParses(res.text)
    expect(res.text).toContain('- name: a\n    type: vless\n')
    expect(res.text).toContain('- name: c\n    type: vless\n')
    const doc = parseDocument(res.text)
    const proxies = doc.contents.get('proxies', true)
    expect(proxies.items.map((it: any) => it.get('name', true).value)).toEqual(['a', 'old', 'c'])
  })
})

describe('replaceMihomoProxy: anchors declared inside replaced item', () => {
  test('anchor used elsewhere in config throws', () => {
    const text =
      "proxies:\n  - name: 'old'\n    type: vless\n    server: &srv a.example.com\n  - name: 'b'\n    type: vless\n    server: *srv\n"
    expect(() => replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: false })).toThrow('якорь')
    expectParses(text)
  })

  test('anchor unused elsewhere is fine to drop', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\n    server: &srv a.example.com\n  - name: 'b'\n    type: vless\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: false })
    expectParses(res.text)
    expect(res.text).not.toContain('&srv')
  })
})

describe('replaceMihomoProxy: duplicate proxy names', () => {
  test('more than one proxy with oldName throws', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\n    port: 1\n  - name: 'old'\n    type: vless\n    port: 2\n"
    expect(() => replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: false })).toThrow('несколько прокси')
  })
})

describe('listMihomoProxies: uniqueness', () => {
  test('returns unique names in first-occurrence order', () => {
    const text = "proxies:\n  - name: 'a'\n    type: vless\n  - name: 'b'\n    type: vless\n  - name: 'a'\n    type: vless\n"
    expect(listMihomoProxies(text)).toEqual(['a', 'b'])
  })
})

describe('isPlainSafe: YAML 1.1 bool/null-like tokens are quoted', () => {
  const ITEM_NO = "  - name: 'no'\n    type: vless\n    server: a.example.com\n    port: 443\n"

  test('reference renamed to "no" is quoted, not left plain', () => {
    const text =
      "proxies:\n  - name: 'old'\n    type: vless\n  - name: 'chain'\n    type: vless\n    dialer-proxy: old\nproxy-groups:\n  - name: g\n    proxies:\n      - old\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_NO, { renameRefs: true })
    expect(res.text).toContain("dialer-proxy: 'no'")
    expect(res.text).toContain("- 'no'")
    expectParses(res.text)
  })

  test('reference renamed to "Yes" / "~" is quoted case-insensitively', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\nproxy-groups:\n  - name: auto\n    proxies: [DIRECT, old]\n"
    const itemYes = "  - name: 'Yes'\n    type: vless\n    server: a.example.com\n    port: 443\n"
    const resYes = replaceMihomoProxy(text, 'old', itemYes, { renameRefs: true })
    expect(resYes.text).toContain("proxies: [DIRECT, 'Yes']")
    expectParses(resYes.text)

    const itemTilde = "  - name: '~'\n    type: vless\n    server: a.example.com\n    port: 443\n"
    const resTilde = replaceMihomoProxy(text, 'old', itemTilde, { renameRefs: true })
    expect(resTilde.text).toContain("proxies: [DIRECT, '~']")
    expectParses(resTilde.text)
  })
})

describe('replaceMihomoProxy: negative / error cases', () => {
  test('collision throws when new name already used by another proxy', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\n  - name: 'A'\n    type: vless\n"
    expect(() => replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })).toThrow('уже используется')
  })

  test('collision with builtin target throws', () => {
    const item = "  - name: 'DIRECT'\n    type: vless\n    port: 443\n"
    const text = "proxies:\n  - name: 'old'\n    type: vless\n"
    expect(() => replaceMihomoProxy(text, 'old', item, { renameRefs: true })).toThrow('уже используется')
  })

  test('not found throws', () => {
    const text = "proxies:\n  - name: 'a'\n    type: vless\n"
    expect(() => replaceMihomoProxy(text, 'missing', ITEM_A, { renameRefs: false })).toThrow('не найден')
  })

  test('missing proxies section throws not-found', () => {
    const text = 'mode: rule\n'
    expect(() => replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: false })).toThrow('не найден')
  })

  test('YAML parse error throws', () => {
    const text = 'proxies:\n  - name: [unterminated\n'
    expect(() => replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: false })).toThrow('Не удалось разобрать')
  })

  test('flow-style proxies seq throws', () => {
    const text = "proxies: [{name: old, type: vless}]\n"
    expect(() => replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: false })).toThrow('flow-стиле')
  })

  test('flow-style item (block seq of flow maps) throws', () => {
    const text = "proxies:\n  - {name: old, type: vless}\n"
    expect(() => replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: false })).toThrow('flow-стиле')
  })
})

describe('replaceMihomoProxy: substring / unrelated scalars are not touched', () => {
  test('exact name match only: "hk" is renamed, "hk-2" is not', () => {
    const text =
      "proxies:\n  - name: 'hk'\n    type: vless\n  - name: 'hk-2'\n    type: vless\nproxy-groups:\n  - name: g\n    proxies:\n      - hk\n      - hk-2\n"
    const res = replaceMihomoProxy(text, 'hk', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(1)
    expect(res.text).toContain('- A\n      - hk-2\n')
  })

  test('unrelated scalar "mode: rule" is not touched when oldName is "rule"', () => {
    const text = "proxies:\n  - name: 'rule'\n    type: vless\nmode: rule\n"
    const res = replaceMihomoProxy(text, 'rule', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(0)
    expect(res.text).toContain('mode: rule\n')
  })

  test('unrelated scalar "type: vless" is not touched when oldName is "vless"', () => {
    const text = "proxies:\n  - name: 'vless'\n    type: vless\n  - name: 'other'\n    type: vless\n    dialer-proxy: vless\n"
    const res = replaceMihomoProxy(text, 'vless', ITEM_A, { renameRefs: true })
    // only the dialer-proxy reference (an actual reference context) is renamed, not every 'type: vless'
    expect(res.text).toContain('type: vless\n    dialer-proxy: A')
  })
})

describe('replaceMihomoProxy: plain-scalar safety for reference rewrites', () => {
  test('a new name that looks like a number is quoted, not left plain (would change YAML type)', () => {
    const text = "proxies:\n  - name: 'old'\n    type: vless\nproxy-groups:\n  - name: auto\n    proxies: [DIRECT, old]\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_NUMERIC_NAME, { renameRefs: true })
    expect(res.name).toBe('123')
    expect(res.text).toContain("proxies: [DIRECT, '123']")
    expectParses(res.text)
    const doc = parseDocument(res.text)
    const groups = doc.contents.get('proxy-groups', true)
    const arr = groups.items[0].get('proxies', true)
    expect(arr.items[1].value).toBe('123')
  })
})

describe('replaceMihomoProxy: nested item bodies and document ordering', () => {
  test('replacing an item with a nested map/seq body keeps neighbours byte-identical and parses', () => {
    const text =
      "proxies:\n  - name: 'old'\n    type: vless\n  - name: 'keep'\n    type: vless # keep me\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_NESTED, { renameRefs: false })
    expect(res.text).toBe(
      "proxies:\n  - name: 'old'\n    type: vless\n    ws-opts:\n      path: /ws\n      headers:\n        Host: a.example.com\n    alpn:\n      - h2\n  - name: 'keep'\n    type: vless # keep me\n"
    )
    expectParses(res.text)
  })

  test('reference section before proxies: still yields correct line number', () => {
    const text = "dns:\n  nameserver:\n    - https://1.1.1.1/dns-query#old\nproxies:\n  - name: 'old'\n    type: vless\n"
    const res = replaceMihomoProxy(text, 'old', ITEM_A, { renameRefs: true })
    expect(res.refs).toBe(1)
    expectParses(res.text)
    const lines = res.text.split('\n')
    expect(lines[res.line - 1].trim().startsWith('- name:')).toBe(true)
  })
})
