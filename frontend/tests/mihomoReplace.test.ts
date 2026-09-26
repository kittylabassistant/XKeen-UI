import { describe, expect, test } from 'bun:test'
import { parseDocument } from 'yaml'
import {
  listMihomoProviders,
  listMihomoProxies,
  listMihomoTakenNames,
  providerEntryName,
  proxyItemName,
  replaceMihomoProvider,
  replaceMihomoProxy,
  withProviderName,
  withProxyName,
} from '../src/lib/mihomoReplace'

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

// ---------------------------------------------------------------------------
// proxy-providers
// ---------------------------------------------------------------------------

const ENTRY_A =
  '  subscription_1:\n    type: http\n    url: https://example.com/sub\n    interval: 43200\n    override:\n      udp: true\n'

const ENTRY_NESTED =
  '  subscription_1:\n' +
  '    type: http\n' +
  '    url: https://example.com/sub\n' +
  '    interval: 43200\n' +
  '    override:\n' +
  '      udp: true\n' +
  '    health-check:\n' +
  '      enable: true\n' +
  '      url: https://www.gstatic.com/generate_204\n' +
  '      interval: 300\n' +
  '      expected-status: 204\n' +
  '    header:\n' +
  '      User-Agent: ["ClashMeta/1.19.30; mihomo/1.19.30"]\n' +
  '      x-hwid: ["A1B2C3D4E5F6"]\n'

describe('listMihomoProviders', () => {
  test('lists provider keys in order', () => {
    const text = 'proxy-providers:\n  p1:\n    type: http\n  p2:\n    type: http\n'
    expect(listMihomoProviders(text)).toEqual(['p1', 'p2'])
  })

  test('returns [] for empty flow map {}', () => {
    expect(listMihomoProviders('proxy-providers: {}\n')).toEqual([])
  })

  test('returns [] for null', () => {
    expect(listMihomoProviders('proxy-providers:\n')).toEqual([])
  })

  test('returns [] when section missing', () => {
    expect(listMihomoProviders('mode: rule\n')).toEqual([])
  })

  test('returns [] on parse error', () => {
    expect(listMihomoProviders('not: [valid: yaml')).toEqual([])
  })

  test('unique keys in first-occurrence order', () => {
    const text = 'proxy-providers:\n  a:\n    type: http\n  b:\n    type: http\n'
    expect(listMihomoProviders(text)).toEqual(['a', 'b'])
  })
})

describe('providerEntryName', () => {
  test('extracts key from generated entry', () => {
    expect(providerEntryName(ENTRY_A)).toBe('subscription_1')
  })

  test('extracts key from nested generated entry', () => {
    expect(providerEntryName(ENTRY_NESTED)).toBe('subscription_1')
  })

  test('returns null on unparsable input (nested mapping in compact form)', () => {
    expect(providerEntryName('  a: b:\n    type: http\n')).toBeNull()
  })

  test('returns null when entry has more than one top-level key', () => {
    expect(providerEntryName('  a:\n    type: http\n  b:\n    type: http\n')).toBeNull()
  })

  test('accepts scalar value entry', () => {
    expect(providerEntryName('  a: b\n')).toBe('a')
  })
})

describe('withProviderName', () => {
  test('replaces plain-safe key, keeps rest byte-identical', () => {
    const result = withProviderName(ENTRY_A, 'sub2')
    expect(result).toBe(
      '  sub2:\n    type: http\n    url: https://example.com/sub\n    interval: 43200\n    override:\n      udp: true\n'
    )
  })

  test('quotes key containing ": "', () => {
    const result = withProviderName(ENTRY_A, 'a: b')
    expect(result.startsWith("  'a: b':\n")).toBe(true)
  })

  test('quotes YAML 1.1 bool-like key "yes"', () => {
    const result = withProviderName(ENTRY_A, 'yes')
    expect(result.startsWith("  'yes':\n")).toBe(true)
  })

  test('quotes key starting with "#"', () => {
    const result = withProviderName(ENTRY_A, '#x')
    expect(result.startsWith("  '#x':\n")).toBe(true)
  })

  test('plain-safe key with apostrophe is left unquoted', () => {
    const result = withProviderName(ENTRY_A, "it's a")
    expect(result.startsWith("  it's a:\n")).toBe(true)
  })

  test('escapes single quotes in a key that needs quoting', () => {
    const result = withProviderName(ENTRY_A, "it's: a")
    expect(result.startsWith("  'it''s: a':\n")).toBe(true)
  })
})

describe('replaceMihomoProvider: basic replace', () => {
  test('renameRefs=false keeps old name', () => {
    const text = 'proxy-providers:\n  old:\n    type: http\n    url: https://a\n'
    const res = replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: false })
    expect(res.name).toBe('old')
    expect(res.refs).toBe(0)
    expect(res.line).toBe(2)
    expect(res.text).toBe(
      'proxy-providers:\n  old:\n    type: http\n    url: https://example.com/sub\n    interval: 43200\n    override:\n      udp: true\n'
    )
  })

  test('renameRefs=true uses generated name', () => {
    const text = 'proxy-providers:\n  old:\n    type: http\n    url: https://a\n'
    const res = replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: true })
    expect(res.name).toBe('subscription_1')
    expect(res.line).toBe(2)
    expect(res.text).toBe(
      'proxy-providers:\n  subscription_1:\n    type: http\n    url: https://example.com/sub\n    interval: 43200\n    override:\n      udp: true\n'
    )
  })

  test('name unchanged (generated name === oldName) yields refs 0', () => {
    const text = 'proxy-providers:\n  subscription_1:\n    type: http\n'
    const res = replaceMihomoProvider(text, 'subscription_1', ENTRY_A, { renameRefs: true })
    expect(res.name).toBe('subscription_1')
    expect(res.refs).toBe(0)
  })

  test('reference before provider section textually still yields correct line number', () => {
    const text = 'proxy-groups:\n  - name: auto\n    use:\n      - old\nproxy-providers:\n  old:\n    type: http\n'
    const res = replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: true })
    expect(res.refs).toBe(1)
    expect(res.name).toBe('subscription_1')
    expectParses(res.text)
    const lines = res.text.split('\n')
    expect(lines[res.line - 1].trim()).toBe('subscription_1:')
  })
})

describe('replaceMihomoProvider: entry key column alignment (does not assume column 2)', () => {
  // key at column 3, body nested 2 deeper (column 5)
  const ENTRY_KEYCOL3 = '   colent:\n     type: http\n     url: https://a\n'
  // key at column 4, body nested 2 deeper (column 6)
  const ENTRY_KEYCOL4 = '    colent:\n      type: http\n      url: https://a\n'

  test('entry key at column 3 into indent-2 config: key realigned to column 2, parses', () => {
    const text = 'proxy-providers:\n  old:\n    type: http\n'
    const res = replaceMihomoProvider(text, 'old', ENTRY_KEYCOL3, { renameRefs: false })
    expectParses(res.text)
    expect(res.text).toContain('  old:\n    type: http\n    url: https://a\n')
  })

  test('entry key at column 3 into indent-4 config: key realigned to column 4, parses', () => {
    const text = 'proxy-providers:\n    old:\n      type: http\n'
    const res = replaceMihomoProvider(text, 'old', ENTRY_KEYCOL3, { renameRefs: false })
    expectParses(res.text)
    expect(res.text).toContain('    old:\n      type: http\n      url: https://a\n')
  })

  test('entry key at column 4 into indent-2 config: key realigned to column 2, parses', () => {
    const text = 'proxy-providers:\n  old:\n    type: http\n'
    const res = replaceMihomoProvider(text, 'old', ENTRY_KEYCOL4, { renameRefs: false })
    expectParses(res.text)
    expect(res.text).toContain('  old:\n    type: http\n    url: https://a\n')
  })

  test('entry key at column 4 into indent-4 config: key realigned to column 4, parses', () => {
    const text = 'proxy-providers:\n    old:\n      type: http\n'
    const res = replaceMihomoProvider(text, 'old', ENTRY_KEYCOL4, { renameRefs: false })
    expectParses(res.text)
    expect(res.text).toContain('    old:\n      type: http\n      url: https://a\n')
  })
})

describe('replaceMihomoProvider: key quoting on renameRefs=true (matches withProviderName)', () => {
  const baseWithUse = (oldName: string) =>
    `proxy-providers:\n  ${oldName}:\n    type: http\nproxy-groups:\n  - name: g\n    use:\n      - ${oldName}\n`

  for (const name of ['yes', 'no', 'on', 'off']) {
    test(`plain YAML 1.1 bool-like name "${name}" is quoted in the inserted key`, () => {
      const entry = ENTRY_A.replace('subscription_1', name)
      const text = baseWithUse('old')
      const res = replaceMihomoProvider(text, 'old', entry, { renameRefs: true })
      expect(res.name).toBe(name)
      expect(res.text).toContain(`  '${name}':\n`)
      expect(res.text).toContain(`      - '${name}'\n`)
      expectParses(res.text)
    })
  }

  test('name needing quoting due to "#" is quoted consistently (built via withProviderName)', () => {
    const entry = withProviderName(ENTRY_A, 'a #b')
    const text = baseWithUse('old')
    const res = replaceMihomoProvider(text, 'old', entry, { renameRefs: true })
    expect(res.name).toBe('a #b')
    expect(res.text).toContain(`  'a #b':\n`)
    expect(res.text).toContain(`      - 'a #b'\n`)
    expectParses(res.text)
  })
})

describe('replaceMihomoProvider: key styles in config', () => {
  test('plain key', () => {
    const text = 'proxy-providers:\n  old:\n    type: http\n'
    const res = replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: false })
    expect(res.name).toBe('old')
  })

  test("single-quoted key 'my sub' in config, plain-safe name re-emitted unquoted", () => {
    const text = "proxy-providers:\n  'my sub':\n    type: http\n"
    const res = replaceMihomoProvider(text, 'my sub', ENTRY_A, { renameRefs: false })
    expect(res.name).toBe('my sub')
    expect(res.text).toContain('  my sub:\n    type: http\n    url:')
    expectParses(res.text)
  })

  test('double-quoted key "x"', () => {
    const text = 'proxy-providers:\n  "x":\n    type: http\n'
    const res = replaceMihomoProvider(text, 'x', ENTRY_A, { renameRefs: false })
    expect(res.name).toBe('x')
  })

  test('key with space and emoji', () => {
    const text = 'proxy-providers:\n  🇩🇪 DE sub:\n    type: http\n'
    const res = replaceMihomoProvider(text, '🇩🇪 DE sub', ENTRY_A, { renameRefs: false })
    expect(res.name).toBe('🇩🇪 DE sub')
    expectParses(res.text)
  })

  test('key indent 2', () => {
    const text = 'proxy-providers:\n  old:\n    type: http\n'
    const res = replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: false })
    expect(res.text).toContain('  old:\n    type: http\n    url:')
  })

  test('key indent 4', () => {
    const text = 'proxy-providers:\n    old:\n      type: http\n'
    const res = replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: false })
    expectParses(res.text)
    expect(res.text).toContain('    old:\n      type: http\n      url: https://example.com/sub\n      interval: 43200\n      override:\n        udp: true\n')
  })
})

describe('replaceMihomoProvider: use[] references', () => {
  test('renames block-form proxy-groups[].use[]', () => {
    const text =
      'proxy-providers:\n  old:\n    type: http\nproxy-groups:\n  - name: auto\n    use:\n      - old\n'
    const res = replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: true })
    expect(res.refs).toBe(1)
    expect(res.text).toContain('use:\n      - subscription_1\n')
  })

  test('renames flow-form proxy-groups[].use[]', () => {
    const text = 'proxy-providers:\n  old:\n    type: http\nproxy-groups:\n  - name: auto\n    use: [old]\n'
    const res = replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: true })
    expect(res.refs).toBe(1)
    expect(res.text).toContain('use: [subscription_1]')
    expectParses(res.text)
  })

  test('proxy-groups[].proxies[] entry equal to provider name is untouched', () => {
    const text =
      'proxy-providers:\n  old:\n    type: http\nproxy-groups:\n  - name: auto\n    proxies:\n      - old\n    use:\n      - old\n'
    const res = replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: true })
    expect(res.refs).toBe(1)
    expect(res.text).toContain('proxies:\n      - old\n')
    expect(res.text).toContain('use:\n      - subscription_1\n')
  })

  test('include-all-providers is untouched', () => {
    const text =
      'proxy-providers:\n  old:\n    type: http\nproxy-groups:\n  - name: auto\n    include-all-providers: true\n'
    const res = replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: true })
    expect(res.text).toContain('include-all-providers: true\n')
  })
})

describe('replaceMihomoProvider: position & neighbours', () => {
  test('replaces first provider, keeps others intact', () => {
    const text = 'proxy-providers:\n  a:\n    type: http\n  b:\n    type: http\n'
    const res = replaceMihomoProvider(text, 'a', ENTRY_A, { renameRefs: false })
    expect(res.text).toBe(
      'proxy-providers:\n  a:\n    type: http\n    url: https://example.com/sub\n    interval: 43200\n    override:\n      udp: true\n  b:\n    type: http\n'
    )
  })

  test('replaces middle provider', () => {
    const text = 'proxy-providers:\n  a:\n    type: http\n  b:\n    type: http\n  c:\n    type: http\n'
    const res = replaceMihomoProvider(text, 'b', ENTRY_A, { renameRefs: false })
    expect(res.text).toBe(
      'proxy-providers:\n  a:\n    type: http\n  b:\n    type: http\n    url: https://example.com/sub\n    interval: 43200\n    override:\n      udp: true\n  c:\n    type: http\n'
    )
  })

  test('replaces last provider at EOF without trailing newline', () => {
    const text = 'proxy-providers:\n  a:\n    type: http\n  b:\n    type: http'
    const res = replaceMihomoProvider(text, 'b', ENTRY_A, { renameRefs: false })
    expect(res.text).toBe(
      'proxy-providers:\n  a:\n    type: http\n  b:\n    type: http\n    url: https://example.com/sub\n    interval: 43200\n    override:\n      udp: true\n'
    )
  })

  test('proxy-providers as last section in document', () => {
    const text = 'mode: rule\nproxy-providers:\n  old:\n    type: http\n'
    const res = replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: false })
    expectParses(res.text)
    expect(res.text.startsWith('mode: rule\n')).toBe(true)
  })

  test('proxy-providers followed by proxy-groups', () => {
    const text = 'proxy-providers:\n  old:\n    type: http\nproxy-groups:\n  - name: g\n    proxies: [DIRECT]\n'
    const res = replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: false })
    expect(res.text).toContain('proxy-groups:\n  - name: g\n    proxies: [DIRECT]\n')
    expectParses(res.text)
  })

  test('neighbour provider with nested health-check/header preserved byte-for-byte', () => {
    const neighbourBlock = ENTRY_NESTED.replace('subscription_1', 'neighbour')
    const text = `proxy-providers:\n  old:\n    type: http\n${neighbourBlock}`
    const res = replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: false })
    expect(res.text).toContain(neighbourBlock)
    expectParses(res.text)
  })

  test('comment between pairs preserved', () => {
    const text = 'proxy-providers:\n  a:\n    type: http\n  # keep me\n  b:\n    type: http\n'
    const res = replaceMihomoProvider(text, 'a', ENTRY_A, { renameRefs: false })
    expect(res.text).toBe(
      'proxy-providers:\n  a:\n    type: http\n    url: https://example.com/sub\n    interval: 43200\n    override:\n      udp: true\n  # keep me\n  b:\n    type: http\n'
    )
  })
})

describe('replaceMihomoProvider: alias values', () => {
  test('replacing a provider whose value is an alias works', () => {
    const text = 'proxy-providers:\n  tpl: &tpl\n    type: http\n  old: *tpl\n'
    const res = replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: false })
    expect(res.text).toBe(
      'proxy-providers:\n  tpl: &tpl\n    type: http\n  old:\n    type: http\n    url: https://example.com/sub\n    interval: 43200\n    override:\n      udp: true\n'
    )
    expectParses(res.text)
  })

  test('target declaring an anchor used by another provider throws', () => {
    const text = 'proxy-providers:\n  old: &tpl\n    type: http\n  other: *tpl\n'
    expect(() => replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: false })).toThrow('якорь')
    expectParses(text)
  })

  test('anchor unused elsewhere is fine to drop', () => {
    const text = 'proxy-providers:\n  old: &tpl\n    type: http\n  other:\n    type: http\n'
    const res = replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: false })
    expectParses(res.text)
    expect(res.text).not.toContain('&tpl')
  })
})

describe('replaceMihomoProvider: collisions', () => {
  test('collision with another provider name throws', () => {
    const text = 'proxy-providers:\n  old:\n    type: http\n  subscription_1:\n    type: http\n'
    expect(() => replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: true })).toThrow('уже используется')
  })

  test('name equal to a proxy name is allowed (separate namespace)', () => {
    const text =
      "proxies:\n  - name: 'subscription_1'\n    type: vless\nproxy-providers:\n  old:\n    type: http\n"
    const res = replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: true })
    expect(res.name).toBe('subscription_1')
  })
})

describe('replaceMihomoProvider: negative / error cases', () => {
  test('not found throws', () => {
    const text = 'proxy-providers:\n  a:\n    type: http\n'
    expect(() => replaceMihomoProvider(text, 'missing', ENTRY_A, { renameRefs: false })).toThrow('не найден')
  })

  test('missing proxy-providers section throws not-found', () => {
    const text = 'mode: rule\n'
    expect(() => replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: false })).toThrow('не найден')
  })

  test('YAML parse error throws', () => {
    const text = 'proxy-providers:\n  old: [unterminated\n'
    expect(() => replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: false })).toThrow('Не удалось разобрать')
  })

  test('duplicate map keys (parse error) throws', () => {
    const text = 'proxy-providers:\n  a:\n    type: http\n  a:\n    type: http\n'
    expect(() => replaceMihomoProvider(text, 'a', ENTRY_A, { renameRefs: false })).toThrow('Не удалось разобрать')
  })

  test('flow-style proxy-providers map throws', () => {
    const text = 'proxy-providers: {old: {type: http}}\n'
    expect(() => replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: false })).toThrow('flow-стиле')
  })

  test('flow-style target value throws', () => {
    const text = 'proxy-providers:\n  old: {type: http}\n'
    expect(() => replaceMihomoProvider(text, 'old', ENTRY_A, { renameRefs: false })).toThrow('flow-стиле')
  })

  test('invalid entry with renameRefs=true throws, text unchanged', () => {
    const text = 'proxy-providers:\n  old:\n    type: http\n'
    const broken = '  a: b:\n    type: http\n'
    expect(() => replaceMihomoProvider(text, 'old', broken, { renameRefs: true })).toThrow('корректным YAML')
    expect(text).toBe('proxy-providers:\n  old:\n    type: http\n')
  })

  test('invalid entry with renameRefs=false throws, text unchanged', () => {
    const text = 'proxy-providers:\n  old:\n    type: http\n'
    const broken = '  a: b:\n    type: http\n'
    expect(() => replaceMihomoProvider(text, 'old', broken, { renameRefs: false })).toThrow('корректным YAML')
    expect(text).toBe('proxy-providers:\n  old:\n    type: http\n')
  })
})
