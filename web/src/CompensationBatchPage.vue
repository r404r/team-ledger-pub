<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'

const emit = defineEmits<{ 'session-expired': [] }>()
type Session = { org_id: string; csrf_token: string; mfa_recent: boolean; mfa_valid_until: string; compensation_permissions: { capability: string; category: string }[] }
type Line = { employee_id: string; staff_code: string; currency: string; salary_before: string; increase_amount: string; salary_after: string; effective_date?: string; effective_month?: string; reason_code?: string; reason_text?: string; original_adjustment_event_id?: string; correction_members?: unknown[]; result: string; adjustment_counts: { current_year: number; previous_year: number } }
type Batch = { id: string; business_code: string; cycle_year: number; adjustment_type: 'normal' | 'special'; legal_entity_id: string; default_effective_date?: string; state: string; revision: string; manifest_digest?: string; lines: Line[]; increase_totals_by_currency: { currency: string; amount: string }[] }
type ImportCandidate = { id: string; batch_id: string; base_revision: string; state: string; line_count: number; lines: Line[]; errors: string[]; expires_at: string }
type SalaryRange = { id: string; legal_entity_id: string; location: string; job_family_id: string; career_level_id: string; currency: 'CNY' | 'JPY'; valid_from: string; valid_to?: string; revision: string; amounts: { minimum: string; midpoint: string; maximum: string } }
const batches = ref<Batch[]>([]), salaryRanges = ref<SalaryRange[]>([]), selected = ref<Batch | null>(null), candidate = ref<ImportCandidate | null>(null), busy = ref(false), error = ref(''), notice = ref(''), session = ref<Session | null>(null), confirmed = ref(false), file = ref<File | null>(null)
const create = reactive({ cycle_year: String(new Date().getUTCFullYear()), adjustment_type: 'normal', legal_entity_id: '', default_effective_date: '' })
const range = reactive({ legal_entity_id: '', location: 'Shanghai', job_family_id: '', career_level_id: '', currency: 'CNY', valid_from: '', minimum: '', midpoint: '', maximum: '' })
const rangeChange = reactive({ action: 'end', id: '', revision: '', legal_entity_id: '', location: '', job_family_id: '', career_level_id: '', currency: 'CNY', effective_to: '', minimum: '', midpoint: '', maximum: '' })
const correction = reactive({ reason: '', lines: '' })
let controller: AbortController | null = null
const canPropose = computed(() => session.value?.compensation_permissions.some(p => p.category === 'financial' && p.capability === 'compensation.propose') === true)
function orgID() { return /^\/orgs\/([0-9a-f-]+)\/compensation-adjustments\/?$/.exec(location.pathname)?.[1] ?? '' }
function clearSensitive() { selected.value = null; candidate.value = null; file.value = null; confirmed.value = false; correction.reason = ''; correction.lines = '' }
async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(`/api/v1${path}`, { ...init, signal: controller?.signal, credentials: 'same-origin', cache: 'no-store', headers: { Accept: 'application/json', 'X-Access-Purpose': 'compensation_management', ...(init.body && !(init.body instanceof Blob) ? { 'Content-Type': 'application/json' } : {}), ...(init.headers ?? {}), ...(session.value ? { 'X-CSRF-Token': session.value.csrf_token } : {}) } })
  if (response.status === 401) emit('session-expired')
  if (!response.ok) throw new Error(String(response.status))
  return response.json()
}
async function load() {
  controller?.abort(); controller = new AbortController(); busy.value = true; error.value = ''; clearSensitive()
  try {
    session.value = await request<Session>('/session')
    if (!session.value.mfa_recent || session.value.org_id !== orgID() || !canPropose.value) throw new Error('403')
    const reply = await request<{ batches: Batch[] }>(`/compensation-adjustment-batches?cycle_year=${encodeURIComponent(create.cycle_year)}`)
    batches.value = reply.batches
    salaryRanges.value = await request<SalaryRange[]>(`/orgs/${orgID()}/salary-ranges`)
  } catch (cause) { batches.value = []; clearSensitive(); error.value = `批次数据未释放（${cause instanceof Error ? cause.message : '503'}）。` } finally { busy.value = false }
}
async function createBatch() {
  if (busy.value || !canPropose.value || !/^\d{4}$/.test(create.cycle_year) || !create.legal_entity_id || create.adjustment_type === 'normal' && !/^\d{4}-\d{2}-\d{2}$/.test(create.default_effective_date)) { error.value = '请填写年度、法分公司及 Normal 默认生效日。'; return }
  busy.value = true; clearSensitive()
  try {
    const body = { cycle_year: Number(create.cycle_year), adjustment_type: create.adjustment_type, legal_entity_id: create.legal_entity_id, default_effective_date: create.adjustment_type === 'normal' ? create.default_effective_date : '' }
    const batch = await request<Batch>('/compensation-adjustment-batches', { method: 'POST', body: JSON.stringify(body), headers: { 'Idempotency-Key': crypto.randomUUID() } })
    notice.value = `已创建 ${batch.business_code}`; busy.value = false; await load(); await openBatch(batch.id)
  } catch (cause) { error.value = `创建失败（${cause instanceof Error ? cause.message : '503'}）。` } finally { busy.value = false }
}
async function addSalaryRange() {
  if (busy.value || !range.legal_entity_id || !range.job_family_id || !range.career_level_id || !/^\d{4}-\d{2}-\d{2}$/.test(range.valid_from) || ![range.minimum, range.midpoint, range.maximum].every(value => /^(0|[1-9]\d*)$/.test(value))) { error.value = '请完整填写 Salary Range，金额必须为非负整数。'; return }
  busy.value = true
  try {
    const body = { changes: [{ action: 'add', expected_revision: '0', legal_entity_id: range.legal_entity_id, location: range.location, job_family_id: range.job_family_id, career_level_id: range.career_level_id, currency: range.currency, valid_from: range.valid_from, amounts: { minimum: range.minimum, midpoint: range.midpoint, maximum: range.maximum } }] }
    salaryRanges.value = await request<SalaryRange[]>(`/orgs/${orgID()}/salary-range-changes`, { method: 'POST', body: JSON.stringify(body), headers: { 'Idempotency-Key': crypto.randomUUID() } })
    notice.value = 'Salary Range 已新增。'
  } catch (cause) { error.value = `Salary Range 新增失败（${cause instanceof Error ? cause.message : '503'}）。` } finally { busy.value = false }
}
function selectSalaryRange(item: SalaryRange) {
  Object.assign(rangeChange, { action: 'end', id: item.id, revision: item.revision, legal_entity_id: item.legal_entity_id, location: item.location, job_family_id: item.job_family_id, career_level_id: item.career_level_id, currency: item.currency, effective_to: '', minimum: item.amounts.minimum, midpoint: item.amounts.midpoint, maximum: item.amounts.maximum })
}
async function changeSalaryRange() {
  if (busy.value || !rangeChange.id || !/^\d{4}-\d{2}-\d{2}$/.test(rangeChange.effective_to)) { error.value = '请选择 Range 并填写结束/替换生效日。'; return }
  const change: Record<string, unknown> = { action: rangeChange.action, id: rangeChange.id, expected_revision: rangeChange.revision, effective_to: rangeChange.effective_to }
  if (rangeChange.action === 'replace') {
    if (![rangeChange.minimum, rangeChange.midpoint, rangeChange.maximum].every(value => /^(0|[1-9]\d*)$/.test(value))) { error.value = '替换金额必须为非负整数。'; return }
    Object.assign(change, { legal_entity_id: rangeChange.legal_entity_id, location: rangeChange.location, job_family_id: rangeChange.job_family_id, career_level_id: rangeChange.career_level_id, currency: rangeChange.currency, valid_from: rangeChange.effective_to, amounts: { minimum: rangeChange.minimum, midpoint: rangeChange.midpoint, maximum: rangeChange.maximum } })
  }
  busy.value = true
  try {
    salaryRanges.value = await request<SalaryRange[]>(`/orgs/${orgID()}/salary-range-changes`, { method: 'POST', body: JSON.stringify({ changes: [change] }), headers: { 'Idempotency-Key': crypto.randomUUID() } })
    notice.value = rangeChange.action === 'replace' ? 'Salary Range 已替换。' : 'Salary Range 已结束。'; rangeChange.id = ''
  } catch (cause) { error.value = `Salary Range 维护失败（${cause instanceof Error ? cause.message : '503'}）。` } finally { busy.value = false }
}
async function openBatch(id: string) {
  if (busy.value) return
  busy.value = true; clearSensitive()
  try { selected.value = await request<Batch>(`/compensation-adjustment-batches/${id}`) } catch (cause) { error.value = `批次读取失败（${cause instanceof Error ? cause.message : '503'}）。` } finally { busy.value = false }
}
function chooseFile(event: Event) { file.value = (event.target as HTMLInputElement).files?.[0] ?? null }
async function importWorkbook() {
  const batch = selected.value, workbook = file.value
  if (!batch || !workbook || busy.value || workbook.size > 10 * 1024 * 1024) { error.value = '请选择不超过 10 MiB 的 XLSX。'; return }
  busy.value = true; clearSensitive()
  try {
    candidate.value = await request<ImportCandidate>(`/compensation-adjustment-batches/${batch.id}/imports?revision=${encodeURIComponent(batch.revision)}`, { method: 'POST', body: workbook, headers: { 'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'Idempotency-Key': crypto.randomUUID() } })
    selected.value = await request<Batch>(`/compensation-adjustment-batches/${batch.id}`)
    notice.value = 'XLSX 已规范化为隔离候选；应用后才会替换草稿。'
  } catch (cause) { error.value = `导入失败（${cause instanceof Error ? cause.message : '503'}）。` } finally { busy.value = false }
}
async function applyCandidate() {
  const batch = selected.value, staged = candidate.value
  if (!batch || !staged || busy.value || staged.state !== 'valid' || staged.base_revision !== batch.revision) { error.value = '导入候选已过期或草稿版本已变化。'; return }
  busy.value = true
  try {
    selected.value = await request<Batch>(`/compensation-adjustment-batches/${batch.id}/draft`, { method: 'PATCH', body: JSON.stringify({ revision: batch.revision, candidate_id: staged.id }), headers: { 'Idempotency-Key': crypto.randomUUID() } })
    candidate.value = null; file.value = null; notice.value = '候选已应用；请核对逐人结果和币种合计。'
  } catch (cause) { error.value = `应用候选失败（${cause instanceof Error ? cause.message : '503'}）。` } finally { busy.value = false }
}
async function activate() {
  const batch = selected.value
  if (!batch || !confirmed.value || !['draft', 'activation_blocked'].includes(batch.state) || !batch.manifest_digest || busy.value) { error.value = '必须先核对非空冻结清单并明确确认。'; return }
  busy.value = true; const frozen = { id: batch.id, revision: batch.revision, manifest_digest: batch.manifest_digest }; clearSensitive()
  try {
    selected.value = await request<Batch>(`/compensation-adjustment-batches/${frozen.id}/transitions`, { method: 'POST', body: JSON.stringify({ action: 'submit', revision: frozen.revision, manifest_digest: frozen.manifest_digest }), headers: { 'Idempotency-Key': crypto.randomUUID() } })
    notice.value = '整批已原子生效。'
  } catch (cause) { error.value = `整批未确认生效（${cause instanceof Error ? cause.message : '503'}）；不会自动重试。` } finally { busy.value = false }
}
function generateCorrectionTemplate() {
  const lines = selected.value?.lines.filter(line => line.result === 'changed' && line.original_adjustment_event_id && line.correction_members?.length).map(line => ({
    employee_id: line.employee_id,
    members: JSON.parse(JSON.stringify(line.correction_members)),
  })) ?? []
  correction.lines = JSON.stringify(lines, null, 2)
}
async function correctBatch() {
  const batch = selected.value
  if (!batch || batch.state !== 'activated' || busy.value || !correction.reason.trim() || !correction.lines.trim()) { error.value = '请输入更正原因和更正成员 JSON。'; return }
  let lines: unknown
  try { lines = JSON.parse(correction.lines) } catch { error.value = '更正成员必须是合法 JSON。'; return }
  if (!Array.isArray(lines) || lines.length === 0) { error.value = '更正成员必须是非空数组。'; return }
  busy.value = true
  try {
    const result = await request<{ business_code: string }>(`/compensation-adjustment-batches/${batch.id}/corrections`, { method: 'POST', body: JSON.stringify({ reason: correction.reason.trim(), lines }), headers: { 'Idempotency-Key': crypto.randomUUID() } })
    notice.value = `更正 ${result.business_code} 已原子生效。`; correction.reason = ''; correction.lines = ''
  } catch (cause) { error.value = `更正未生效（${cause instanceof Error ? cause.message : '503'}）。` } finally { busy.value = false }
}
onMounted(load)
onBeforeUnmount(() => { controller?.abort(); clearSensitive(); batches.value = []; session.value = null })
</script>

<template>
  <main>
    <h1>薪资调整批次</h1>
    <p role="alert" v-if="error">{{ error }}</p><p role="status" v-if="notice">{{ notice }}</p>
    <form aria-label="创建薪资调整批次" @submit.prevent="createBatch">
      <label>年度 <input v-model="create.cycle_year" inputmode="numeric"></label>
      <label>类型 <select v-model="create.adjustment_type"><option value="normal">Normal</option><option value="special">Special</option></select></label>
      <label>法分公司 ID <input v-model.trim="create.legal_entity_id"></label>
      <label v-if="create.adjustment_type === 'normal'">默认生效日 <input v-model="create.default_effective_date" type="date"></label>
      <button :disabled="busy || !canPropose">创建批次</button><button type="button" :disabled="busy" @click="load">刷新</button>
    </form>
    <section aria-label="批次列表"><h2>批次</h2><ul><li v-for="batch in batches" :key="batch.id"><button :disabled="busy" @click="openBatch(batch.id)">{{ batch.business_code }} · {{ batch.adjustment_type }} · {{ batch.state }} · R{{ batch.revision }}</button></li></ul></section>
    <section aria-label="Salary Range 目录">
      <h2>Salary Range</h2>
      <form @submit.prevent="addSalaryRange">
        <label>法分公司 ID <input v-model.trim="range.legal_entity_id"></label><label>地点 <select v-model="range.location"><option>Shanghai</option><option>Wuxi</option><option>Tokyo</option></select></label>
        <label>Job Family ID <input v-model.trim="range.job_family_id"></label><label>Career Level ID <input v-model.trim="range.career_level_id"></label>
        <label>币种 <select v-model="range.currency"><option>CNY</option><option>JPY</option></select></label><label>生效日 <input v-model="range.valid_from" type="date"></label>
        <label>Minimum <input v-model.trim="range.minimum" inputmode="numeric"></label><label>Midpoint <input v-model.trim="range.midpoint" inputmode="numeric"></label><label>Maximum <input v-model.trim="range.maximum" inputmode="numeric"></label>
        <button :disabled="busy || !canPropose">新增 Range</button>
      </form>
      <table><caption>有效期 Salary Range</caption><thead><tr><th>法分公司</th><th>地点</th><th>Job Family</th><th>Career Level</th><th>币种</th><th>Min/Mid/Max</th><th>有效期</th><th>维护</th></tr></thead><tbody><tr v-for="item in salaryRanges" :key="item.id"><td>{{ item.legal_entity_id }}</td><td>{{ item.location }}</td><td>{{ item.job_family_id }}</td><td>{{ item.career_level_id }}</td><td>{{ item.currency }}</td><td>{{ item.amounts.minimum }}/{{ item.amounts.midpoint }}/{{ item.amounts.maximum }}</td><td>{{ item.valid_from }} – {{ item.valid_to || '∞' }}</td><td><button v-if="!item.valid_to" type="button" :disabled="busy" @click="selectSalaryRange(item)">结束/替换</button></td></tr></tbody></table>
      <form v-if="rangeChange.id" aria-label="结束或替换 Salary Range" @submit.prevent="changeSalaryRange">
        <label>动作 <select v-model="rangeChange.action"><option value="end">结束</option><option value="replace">结束并替换</option></select></label>
        <label>生效日 <input v-model="rangeChange.effective_to" type="date"></label>
        <template v-if="rangeChange.action === 'replace'"><label>Minimum <input v-model.trim="rangeChange.minimum"></label><label>Midpoint <input v-model.trim="rangeChange.midpoint"></label><label>Maximum <input v-model.trim="rangeChange.maximum"></label></template>
        <button :disabled="busy">确认维护</button>
      </form>
    </section>
    <section v-if="selected" aria-label="批次明细">
      <h2>{{ selected.business_code }}</h2><p>状态 {{ selected.state }} · R{{ selected.revision }}</p>
      <template v-if="selected.state === 'draft' || selected.state === 'activation_conflict'">
        <p v-if="selected.state === 'activation_conflict'" role="alert">冻结依据已变化；请重新解析并应用候选后再提交。</p>
        <label>XLSX <input type="file" accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" @change="chooseFile"></label>
        <button :disabled="busy || !file" @click="importWorkbook">解析 XLSX 候选</button>
        <div v-if="candidate">
          <p>候选 {{ candidate.id }} · {{ candidate.state }} · {{ candidate.line_count }} 行 · 有效期至 {{ candidate.expires_at }}</p>
          <ul v-if="candidate.errors.length"><li v-for="message in candidate.errors" :key="message">{{ message }}</li></ul>
          <table v-if="candidate.lines.length"><caption>应用前候选预览</caption><thead><tr><th>工号</th><th>币种</th><th>调整前</th><th>增加</th><th>调整后</th><th>生效日/月</th><th>原因</th></tr></thead><tbody><tr v-for="line in candidate.lines" :key="line.employee_id"><td>{{ line.staff_code }}</td><td>{{ line.currency }}</td><td>{{ line.salary_before }}</td><td>{{ line.increase_amount }}</td><td>{{ line.salary_after }}</td><td>{{ line.effective_date || line.effective_month }}</td><td>{{ [line.reason_code, line.reason_text].filter(Boolean).join(' · ') || '—' }}</td></tr></tbody></table>
          <button :disabled="busy || candidate.state !== 'valid'" @click="applyCandidate">应用候选并替换草稿</button>
        </div>
      </template>
      <table><caption>逐人冻结结果</caption><thead><tr><th>工号</th><th>币种</th><th>调整前</th><th>增加</th><th>调整后</th><th>结果</th><th>原调整事件</th><th>本年/上年次数</th></tr></thead><tbody><tr v-for="line in selected.lines" :key="line.employee_id"><td>{{ line.staff_code }}</td><td>{{ line.currency }}</td><td>{{ line.salary_before }}</td><td>{{ line.increase_amount }}</td><td>{{ line.salary_after }}</td><td>{{ line.result }}</td><td>{{ line.original_adjustment_event_id || '—' }}</td><td>{{ line.adjustment_counts.current_year }}/{{ line.adjustment_counts.previous_year }}</td></tr></tbody></table>
      <p>币种合计：<span v-for="total in selected.increase_totals_by_currency" :key="total.currency">{{ total.currency }} {{ total.amount }} </span></p>
      <template v-if="['draft', 'activation_blocked'].includes(selected.state) && selected.lines.length"><p v-if="selected.state === 'activation_blocked'" role="alert">依赖暂不可用；清单未变化，可人工重试。</p><label><input v-model="confirmed" type="checkbox"> 已核对逐人结果、币种合计和冻结摘要</label><button :disabled="busy || !confirmed" @click="activate">{{ selected.state === 'activation_blocked' ? '重试整批生效' : '整批生效' }}</button></template>
      <form v-if="selected.state === 'activated'" aria-label="更正已生效批次" @submit.prevent="correctBatch">
        <h3>更正已生效批次</h3>
        <p>更正采用 append-only 反转/替换事件，不修改原批次。</p>
        <label>更正原因 <input v-model.trim="correction.reason"></label>
        <button type="button" :disabled="busy || !selected.lines.some(line => line.original_adjustment_event_id)" @click="generateCorrectionTemplate">生成更正模板</button>
        <label>更正成员 JSON
          <textarea v-model="correction.lines" rows="8" cols="100" placeholder='[{"employee_id":"...","members":[{"member_key":"...","action":"replace","original_event_id":"...","effective_date":"2026-01-01","before_ref":null,"after":{"currency":"CNY","scale":0,"amount_minor":"11300","unit":"month","payment_frequency":"monthly","tax_basis":"gross","components":[]}}]}]'></textarea>
        </label>
        <button :disabled="busy || !correction.reason || !correction.lines">原子生效更正</button>
      </form>
    </section>
  </main>
</template>

<style scoped>
main { max-width: 80rem; margin: 1rem auto; padding: 0 1rem; font-family: system-ui, sans-serif; } form, section { margin: 1rem 0; padding: 1rem; border: 1px solid #bbb; } label { display: inline-grid; gap: .25rem; margin: .4rem; } button { margin: .4rem; } table { width: 100%; border-collapse: collapse; } th, td { border: 1px solid #bbb; padding: .4rem; text-align: left; } [role="alert"] { color: #a00000; }
</style>
