<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import ProfilePage from './ProfilePage.vue'
import GrantPage from './GrantPage.vue'
import AuditPage from './AuditPage.vue'
import IdentityGate from './IdentityGate.vue'
import OrganizationPage from './OrganizationPage.vue'
import InterviewPage from './InterviewPage.vue'
import CompensationPage from './CompensationPage.vue'
import CompensationBatchPage from './CompensationBatchPage.vue'
import BonusPage from './BonusPage.vue'
import FollowupPage from './FollowupPage.vue'

const pathname = ref(window.location.pathname)
const grantsRoute = computed(() => /^\/security\/grants\/?$/.test(pathname.value))
const auditRoute = computed(() => /^\/security\/audit\/?$/.test(pathname.value))
const organizationRoute = computed(() => /^\/orgs\/[0-9a-f-]+\/(?:tree|employees)\/?$/.test(pathname.value) ||
  /^\/employees\/[0-9a-f-]+\/organization-history\/?$/.test(pathname.value))
const interviewRoute = computed(() => /^\/interviews(?:\/[0-9a-f-]+)?\/?$/.test(pathname.value) ||
  /^\/employees\/[0-9a-f-]+\/interviews\/?$/.test(pathname.value))
const followupRoute = computed(() => /^\/employees\/[0-9a-f-]+\/followup\/?$/.test(pathname.value))
const compensationRoute = computed(() => /^\/employees\/[0-9a-f-]+\/compensation\/?$/.test(pathname.value))
const compensationBatchRoute = computed(() => /^\/orgs\/[0-9a-f-]+\/compensation-adjustments\/?$/.test(pathname.value))
const bonusRoute = computed(() => /^\/employees\/[0-9a-f-]+\/bonuses\/?$/.test(pathname.value))

function readRoute() {
  pathname.value = window.location.pathname
}
function navigate(event: MouseEvent, path: string) {
  if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return
  event.preventDefault()
  window.history.pushState({}, '', path)
  // Both the composition root and the existing profile page consume popstate.
  window.dispatchEvent(new PopStateEvent('popstate'))
}
function changeViewDate(event: Event, setAsOf: (value: string) => boolean, current: string) {
  const input = event.target as HTMLInputElement
  if (!setAsOf(input.value)) input.value = current
}

function navActive(section: 'profile' | 'grants' | 'audit' | 'organization' | 'directory' | 'interviews' | 'batches') {
  const path = pathname.value
  if (section === 'profile') return path === '/' || /^\/employees\/[0-9a-f-]+\/?$/.test(path)
  if (section === 'grants') return grantsRoute.value
  if (section === 'audit') return auditRoute.value
  if (section === 'organization') return /\/(?:tree|organization-history)\/?$/.test(path)
  if (section === 'directory') return /\/employees\/?$/.test(path) && path.startsWith('/orgs/')
  if (section === 'interviews') return interviewRoute.value
  return compensationBatchRoute.value
}
onMounted(() => window.addEventListener('popstate', readRoute))
onBeforeUnmount(() => window.removeEventListener('popstate', readRoute))
</script>

<template>
  <IdentityGate v-slot="{ expireSession, orgID, asOf, setAsOf }">
    <header class="app-shell-header">
      <div class="app-shell-bar">
        <a class="brand-lockup" href="/" aria-label="TeamLedger 首页" @click="navigate($event, '/')">
          <span class="brand-mark" aria-hidden="true">TL</span>
          <span class="brand-copy"><strong>TeamLedger</strong><small>People operations</small></span>
        </a>
        <div class="app-shell-context">
          <label class="global-view-date" for="global-view-date">
            <span>查看日期</span>
            <input id="global-view-date" type="date" :value="asOf" @change="changeViewDate($event, setAsOf, asOf)" />
          </label>
          <div class="workspace-state"><span>受保护工作区</span></div>
        </div>
      </div>
      <nav class="app-nav" aria-label="主导航">
        <a href="/" :aria-current="navActive('profile') ? 'page' : undefined" @click="navigate($event, '/')">人员资料</a>
        <a href="/security/grants" :aria-current="navActive('grants') ? 'page' : undefined" @click="navigate($event, '/security/grants')">授权</a>
        <a href="/security/audit" :aria-current="navActive('audit') ? 'page' : undefined" @click="navigate($event, '/security/audit')">审计</a>
        <a :href="`/orgs/${orgID}/tree`" :aria-current="navActive('organization') ? 'page' : undefined" @click="navigate($event, `/orgs/${orgID}/tree`)">组织树</a>
        <a :href="`/orgs/${orgID}/employees`" :aria-current="navActive('directory') ? 'page' : undefined" @click="navigate($event, `/orgs/${orgID}/employees`)">员工目录</a>
        <a href="/interviews" :aria-current="navActive('interviews') ? 'page' : undefined" @click="navigate($event, '/interviews')">面谈</a>
        <a :href="`/orgs/${orgID}/compensation-adjustments`" :aria-current="navActive('batches') ? 'page' : undefined" @click="navigate($event, `/orgs/${orgID}/compensation-adjustments`)">调薪批次</a>
      </nav>
    </header>
    <GrantPage v-if="grantsRoute" @session-expired="expireSession" />
    <AuditPage v-else-if="auditRoute" @session-expired="expireSession" />
    <InterviewPage v-else-if="interviewRoute" @session-expired="expireSession" />
    <FollowupPage v-else-if="followupRoute" @session-expired="expireSession" />
    <CompensationPage v-else-if="compensationRoute" :query-date="asOf" @session-expired="expireSession" />
    <CompensationBatchPage v-else-if="compensationBatchRoute" @session-expired="expireSession" />
    <BonusPage v-else-if="bonusRoute" @session-expired="expireSession" />
    <OrganizationPage v-else-if="organizationRoute" :query-date="asOf" @session-expired="expireSession" />
    <ProfilePage v-else :query-date="asOf" @session-expired="expireSession" />
  </IdentityGate>
</template>
