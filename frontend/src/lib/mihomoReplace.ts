import { isAlias, isMap, isScalar, isSeq, parseDocument, visit } from 'yaml'
import type { Document, Scalar, YAMLMap } from 'yaml'

/** Результат замены прокси в config.yaml */
export interface ReplaceProxyResult {
  text: string
  name: string
  line: number
  refs: number
}

const BUILTIN_TARGETS = ['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE', 'GLOBAL']

interface Edit {
  start: number
  end: number
  text: string
  isItem?: boolean
}

const quoteSingle = (value: string): string => `'${value.replace(/'/g, "''")}'`

/** Можно ли безопасно записать значение как plain-скаляр YAML в данном контексте */
function isPlainSafe(value: string, inFlow: boolean): boolean {
  if (value.length === 0) return false
  if (/^\s|\s$/.test(value)) return false
  if (/^[-?:,[\]{}#&*!|>'"%@`]/.test(value)) return false
  if (/:(\s|$)/.test(value)) return false
  if (/\s#/.test(value)) return false
  if (inFlow && /[,[\]{}]/.test(value)) return false
  // YAML 1.1 bool/null-подобные токены: некоторые парсеры (Go yaml.v3) распознают их как не-строки
  if (/^(y|yes|n|no|on|off|true|false)$/i.test(value)) return false
  if (/^(~|null)$/i.test(value)) return false
  try {
    const doc = parseDocument(value)
    if (doc.errors.length) return false
    const js = doc.toJS()
    if (typeof js !== 'string' || js !== value) return false
  } catch {
    return false
  }
  return true
}

/** Эмитит новое значение скаляра, сохраняя исходный стиль (PLAIN/QUOTE_SINGLE/QUOTE_DOUBLE) */
function emitLikeOriginal(node: Scalar, value: string, inFlow: boolean): string {
  if (node.type === 'QUOTE_DOUBLE') return JSON.stringify(value)
  if (node.type === 'QUOTE_SINGLE') return quoteSingle(value)
  return isPlainSafe(value, inFlow) ? value : quoteSingle(value)
}

/** Разбивает значение правила по запятым верхнего уровня, вне круглых скобок */
function splitTopLevelCommas(value: string): string[] {
  const parts: string[] = []
  let depth = 0
  let cur = ''
  for (const ch of value) {
    if (ch === '(') depth++
    else if (ch === ')') depth--
    if (ch === ',' && depth === 0) {
      parts.push(cur)
      cur = ''
    } else {
      cur += ch
    }
  }
  parts.push(cur)
  return parts
}

/** Заменяет значение CSV-поля, сохраняя окружающие пробелы */
function replaceFieldPreserveWs(field: string, newValue: string): string {
  const match = /^(\s*)([\s\S]*?)(\s*)$/.exec(field)
  if (!match) return newValue
  return `${match[1]}${newValue}${match[3]}`
}

/** Переименовывает ссылку на прокси в строке rules[] / sub-rules.*[] */
function renameInRuleString(value: string, oldName: string, newName: string): string | null {
  const parts = splitTopLevelCommas(value)
  if (parts.length === 0) return null
  const type = parts[0].trim().toUpperCase()
  if (type === 'SUB-RULE') return null
  const idx = type === 'MATCH' ? 1 : 2
  if (idx >= parts.length) return null
  if (parts[idx].trim() !== oldName) return null
  const next = [...parts]
  next[idx] = replaceFieldPreserveWs(parts[idx], newName)
  return next.join(',')
}

/** Переименовывает 4-е CSV-поле строковой формы tunnels[] */
function renameInTunnelString(value: string, oldName: string, newName: string): string | null {
  const parts = value.split(',')
  if (parts.length < 4) return null
  if (parts[3].trim() !== oldName) return null
  const next = [...parts]
  next[3] = replaceFieldPreserveWs(parts[3], newName)
  return next.join(',')
}

/** Переименовывает имя прокси во фрагменте (#name или #name&opt=val) строки под dns */
function renameDnsFragment(value: string, oldName: string, newName: string): string | null {
  const hashIdx = value.indexOf('#')
  if (hashIdx === -1) return null
  const prefix = value.slice(0, hashIdx)
  const fragParts = value.slice(hashIdx + 1).split('&')
  if (fragParts[0] !== oldName) return null
  fragParts[0] = newName
  return `${prefix}#${fragParts.join('&')}`
}

/** Рекурсивно обходит все строковые скаляры поддерева (используется для dns) */
function walkStringScalars(node: unknown, inFlow: boolean, cb: (node: Scalar, inFlow: boolean) => void): void {
  if (isSeq(node)) {
    const flow = inFlow || Boolean(node.flow)
    for (const item of node.items) walkStringScalars(item, flow, cb)
  } else if (isMap(node)) {
    const flow = inFlow || Boolean(node.flow)
    for (const pair of node.items) walkStringScalars(pair.value, flow, cb)
  } else if (isScalar(node) && typeof node.value === 'string') {
    cb(node, inFlow)
  }
}

function pushWholeValueEdit(edits: Edit[], node: unknown, oldName: string, newName: string, inFlow: boolean): void {
  if (isScalar(node) && node.value === oldName && node.range) {
    edits.push({ start: node.range[0], end: node.range[1], text: emitLikeOriginal(node, newName, inFlow) })
  }
}

/** Собирает правки переименования ссылок на прокси во всех поддерживаемых секциях конфига */
function collectReferenceEdits(root: YAMLMap, oldName: string, newName: string): Edit[] {
  const edits: Edit[] = []

  const proxiesSeq = root.get('proxies', true)
  if (isSeq(proxiesSeq)) {
    for (const it of proxiesSeq.items) {
      if (!isMap(it)) continue
      pushWholeValueEdit(edits, it.get('dialer-proxy', true), oldName, newName, Boolean(it.flow))
    }
  }

  const groups = root.get('proxy-groups', true)
  if (isSeq(groups)) {
    for (const g of groups.items) {
      if (!isMap(g)) continue
      const arr = g.get('proxies', true)
      if (isSeq(arr)) {
        for (const el of arr.items) pushWholeValueEdit(edits, el, oldName, newName, Boolean(arr.flow))
      }
    }
  }

  const providers = root.get('proxy-providers', true)
  if (isMap(providers)) {
    for (const pair of providers.items) {
      const p = pair.value
      if (!isMap(p)) continue
      pushWholeValueEdit(edits, p.get('proxy', true), oldName, newName, Boolean(p.flow))
      const override = p.get('override', true)
      if (isMap(override)) {
        pushWholeValueEdit(edits, override.get('dialer-proxy', true), oldName, newName, Boolean(override.flow))
      }
    }
  }

  const ruleProviders = root.get('rule-providers', true)
  if (isMap(ruleProviders)) {
    for (const pair of ruleProviders.items) {
      const p = pair.value
      if (!isMap(p)) continue
      pushWholeValueEdit(edits, p.get('proxy', true), oldName, newName, Boolean(p.flow))
    }
  }

  const listeners = root.get('listeners', true)
  if (isSeq(listeners)) {
    for (const l of listeners.items) {
      if (!isMap(l)) continue
      pushWholeValueEdit(edits, l.get('proxy', true), oldName, newName, Boolean(l.flow))
    }
  }

  const tunnels = root.get('tunnels', true)
  if (isSeq(tunnels)) {
    for (const t of tunnels.items) {
      if (isMap(t)) {
        pushWholeValueEdit(edits, t.get('proxy', true), oldName, newName, Boolean(t.flow))
      } else if (isScalar(t) && typeof t.value === 'string' && t.range) {
        const next = renameInTunnelString(t.value, oldName, newName)
        if (next !== null) edits.push({ start: t.range[0], end: t.range[1], text: emitLikeOriginal(t, next, Boolean(tunnels.flow)) })
      }
    }
  }

  const ntp = root.get('ntp', true)
  if (isMap(ntp)) {
    pushWholeValueEdit(edits, ntp.get('dialer-proxy', true), oldName, newName, Boolean(ntp.flow))
  }

  const rules = root.get('rules', true)
  if (isSeq(rules)) {
    for (const r of rules.items) {
      if (!isScalar(r) || typeof r.value !== 'string' || !r.range) continue
      const next = renameInRuleString(r.value, oldName, newName)
      if (next !== null) edits.push({ start: r.range[0], end: r.range[1], text: emitLikeOriginal(r, next, Boolean(rules.flow)) })
    }
  }

  const subRules = root.get('sub-rules', true)
  if (isMap(subRules)) {
    for (const pair of subRules.items) {
      const seq = pair.value
      if (!isSeq(seq)) continue
      for (const r of seq.items) {
        if (!isScalar(r) || typeof r.value !== 'string' || !r.range) continue
        const next = renameInRuleString(r.value, oldName, newName)
        if (next !== null) edits.push({ start: r.range[0], end: r.range[1], text: emitLikeOriginal(r, next, Boolean(seq.flow)) })
      }
    }
  }

  const dns = root.get('dns', true)
  if (dns !== undefined) {
    walkStringScalars(dns, false, (node, inFlow) => {
      if (!node.range) return
      const next = renameDnsFragment(node.value as string, oldName, newName)
      if (next !== null) edits.push({ start: node.range[0], end: node.range[1], text: emitLikeOriginal(node, next, inFlow) })
    })
  }

  return edits
}

function reindent(block: string, shift: number): string {
  if (shift === 0) return block
  return block
    .split('\n')
    .map((line) => {
      if (shift > 0) return ' '.repeat(shift) + line
      let removed = 0
      let idx = 0
      while (idx < line.length && line[idx] === ' ' && removed < -shift) {
        idx++
        removed++
      }
      return line.slice(idx)
    })
    .join('\n')
}

/** Имена прокси из top-level секции proxies, в порядке следования. Никогда не бросает исключений. */
export function listMihomoProxies(text: string): string[] {
  try {
    const doc = parseDocument(text)
    if (doc.errors.length) return []
    const root = doc.contents
    if (!isMap(root)) return []
    const proxies = root.get('proxies', true)
    if (!isSeq(proxies)) return []
    const names: string[] = []
    const seen = new Set<string>()
    for (const item of proxies.items) {
      if (!isMap(item)) continue
      const nameNode = item.get('name', true)
      if (isScalar(nameNode) && typeof nameNode.value === 'string' && !seen.has(nameNode.value)) {
        seen.add(nameNode.value)
        names.push(nameNode.value)
      }
    }
    return names
  } catch {
    return []
  }
}

/** Все занятые имена: proxies[].name, proxy-groups[].name и встроенные target-имена. Никогда не бросает исключений. */
export function listMihomoTakenNames(text: string): string[] {
  try {
    const doc = parseDocument(text)
    if (doc.errors.length) return [...BUILTIN_TARGETS]
    const root = doc.contents
    if (!isMap(root)) return [...BUILTIN_TARGETS]
    const names = new Set<string>(BUILTIN_TARGETS)
    const proxies = root.get('proxies', true)
    if (isSeq(proxies)) {
      for (const item of proxies.items) {
        if (!isMap(item)) continue
        const n = item.get('name', true)
        if (isScalar(n) && typeof n.value === 'string') names.add(n.value)
      }
    }
    const groups = root.get('proxy-groups', true)
    if (isSeq(groups)) {
      for (const g of groups.items) {
        if (!isMap(g)) continue
        const n = g.get('name', true)
        if (isScalar(n) && typeof n.value === 'string') names.add(n.value)
      }
    }
    return [...names]
  } catch {
    return [...BUILTIN_TARGETS]
  }
}

/** Имя прокси из сгенерированного блока YAML-элемента */
export function proxyItemName(item: string): string | null {
  try {
    const doc = parseDocument(item)
    if (doc.errors.length) return null
    const seq = doc.contents
    if (!isSeq(seq) || seq.items.length === 0) return null
    const map = seq.items[0]
    if (!isMap(map)) return null
    const nameNode = map.get('name', true)
    if (isScalar(nameNode) && typeof nameNode.value === 'string') return nameNode.value
    return null
  } catch {
    return null
  }
}

/** Возвращает сгенерированный блок с изменённым значением name (в одинарных кавычках); остальное побайтово идентично */
export function withProxyName(item: string, name: string): string {
  const doc = parseDocument(item)
  if (doc.errors.length) return item
  const seq = doc.contents
  if (!isSeq(seq) || seq.items.length === 0) return item
  const map = seq.items[0]
  if (!isMap(map)) return item
  const pair = map.items.find((p) => isScalar(p.key) && p.key.value === 'name')
  const nameNode = pair?.value
  if (!isScalar(nameNode) || !nameNode.range) return item
  const [start, end] = nameNode.range
  return item.slice(0, start) + quoteSingle(name) + item.slice(end)
}

/** Имена якорей (&x), объявленных в поддереве узла */
function collectAnchorNames(node: YAMLMap): Set<string> {
  const anchors = new Set<string>()
  visit(node, (_key, n) => {
    if (n && typeof n === 'object' && 'anchor' in n && typeof (n as { anchor?: unknown }).anchor === 'string') {
      const a = (n as { anchor: string }).anchor
      if (a) anchors.add(a)
    }
  })
  return anchors
}

/** Имена якорей, на которые ссылаются алиасы (*x) вне заданного диапазона */
function collectAliasSourcesOutside(doc: Document, range: readonly [number, number, ...number[]]): Set<string> {
  const sources = new Set<string>()
  visit(doc, (_key, n) => {
    if (isAlias(n)) {
      const r = n.range
      if (r && r[0] >= range[0] && r[1] <= range[1]) return
      sources.add(n.source)
    }
  })
  return sources
}

/** Заменяет прокси в config.yaml новым сгенерированным блоком, опционально переименовывая ссылки на него */
export function replaceMihomoProxy(text: string, oldName: string, item: string, opts: { renameRefs: boolean }): ReplaceProxyResult {
  const doc = parseDocument(text)
  if (doc.errors.length) {
    throw new Error(`Не удалось разобрать config.yaml: ${doc.errors[0].message}`)
  }

  const notFound = () => new Error(`Прокси «${oldName}» не найден в config.yaml`)
  const root = doc.contents
  if (!isMap(root)) throw notFound()
  const proxiesSeq = root.get('proxies', true)
  if (!isSeq(proxiesSeq)) throw notFound()

  let targetItem: YAMLMap | undefined
  let matchCount = 0
  for (const it of proxiesSeq.items) {
    if (!isMap(it)) continue
    const nameNode = it.get('name', true)
    if (isScalar(nameNode) && String(nameNode.value) === oldName) {
      matchCount++
      if (!targetItem) targetItem = it
    }
  }
  if (matchCount > 1) throw new Error(`В config.yaml несколько прокси с именем «${oldName}»`)
  if (!targetItem) throw notFound()
  const itemRange = targetItem.range
  if (!itemRange) throw notFound()

  if (proxiesSeq.flow || targetItem.flow) {
    throw new Error('Замена прокси в flow-стиле не поддерживается')
  }

  const declaredAnchors = collectAnchorNames(targetItem)
  if (declaredAnchors.size > 0) {
    const aliasesOutside = collectAliasSourcesOutside(doc, itemRange)
    for (const anchor of declaredAnchors) {
      if (aliasesOutside.has(anchor)) {
        throw new Error(`Прокси «${oldName}» объявляет якорь &${anchor}, который используется в другом месте конфига`)
      }
    }
  }

  const invalidItem = () => new Error('Сгенерированный прокси не является корректным YAML')
  const { renameRefs } = opts
  let name: string
  let block: string
  if (renameRefs) {
    const parsedName = proxyItemName(item)
    if (parsedName === null) throw invalidItem()
    name = parsedName
    block = item
  } else {
    name = oldName
    block = withProxyName(item, oldName)
    if (proxyItemName(block) !== oldName) throw invalidItem()
  }

  if (renameRefs && name !== oldName) {
    const otherNames = new Set<string>(BUILTIN_TARGETS)
    for (const it of proxiesSeq.items) {
      if (it === targetItem || !isMap(it)) continue
      const n = it.get('name', true)
      if (isScalar(n) && typeof n.value === 'string') otherNames.add(n.value)
    }
    const groups = root.get('proxy-groups', true)
    if (isSeq(groups)) {
      for (const g of groups.items) {
        if (!isMap(g)) continue
        const n = g.get('name', true)
        if (isScalar(n) && typeof n.value === 'string') otherNames.add(n.value)
      }
    }
    if (otherNames.has(name)) {
      throw new Error(`Имя «${name}» уже используется в конфиге`)
    }
  }

  const itemStart = itemRange[0]
  // itemRange[1] обычно уже включает собственный завершающий \n элемента (или доходит до EOF).
  // Если нет (например, значение заканчивается серединой строки) — дотягиваем до конца строки с \n.
  let regionEnd = itemRange[1]
  if (regionEnd < text.length && text[regionEnd - 1] !== '\n') {
    const nlAfter = text.indexOf('\n', regionEnd)
    regionEnd = nlAfter === -1 ? text.length : nlAfter + 1
  }
  let dashIdx = itemStart - 1
  while (dashIdx >= 0 && (text[dashIdx] === ' ' || text[dashIdx] === '\t' || text[dashIdx] === '\n' || text[dashIdx] === '\r')) dashIdx--
  if (dashIdx < 0 || text[dashIdx] !== '-') {
    throw new Error(`Не удалось найти начало элемента прокси «${oldName}» в config.yaml`)
  }
  const lineStart = text.lastIndexOf('\n', dashIdx) + 1
  const existingDashColumn = dashIdx - lineStart

  const shift = existingDashColumn - 2
  const raw = block.replace(/\n+$/, '')
  const insertion = `${reindent(raw, shift)}\n`

  const refEdits: Edit[] = []
  if (renameRefs && name !== oldName) {
    for (const edit of collectReferenceEdits(root, oldName, name)) {
      if (edit.start < regionEnd && edit.end > lineStart) continue
      refEdits.push(edit)
    }
  }

  const edits: Edit[] = [...refEdits, { start: lineStart, end: regionEnd, text: insertion, isItem: true }]
  edits.sort((a, b) => a.start - b.start)

  let result = ''
  let cursor = 0
  let itemFinalStart = -1
  for (const edit of edits) {
    result += text.slice(cursor, edit.start)
    if (edit.isItem) itemFinalStart = result.length
    result += edit.text
    cursor = edit.end
  }
  result += text.slice(cursor)

  const line = result.slice(0, itemFinalStart).split('\n').length

  return { text: result, name, line, refs: refEdits.length }
}
